"""Classes to assist in authenticating to the GitHub API."""

import logging
import time
from datetime import datetime, timedelta
from os import environ
from random import choice, shuffle
from typing import Any, Dict, List, Optional

import jwt
import requests
from singer_sdk.authenticators import APIAuthenticatorBase
from singer_sdk.streams import RESTStream


class TokenManager:
    """A class to store a token's attributes and state.
    This parent class should not be used directly, use a subclass instead.
    """

    DEFAULT_RATE_LIMIT = 5000
    # The DEFAULT_RATE_LIMIT_BUFFER buffer serves two purposes:
    # - keep some leeway and rotate tokens before erroring out on rate limit.
    # - not consume all available calls when we rare using an org or user token.
    DEFAULT_RATE_LIMIT_BUFFER = 1000

    def __init__(self, rate_limit_buffer=None, logger=None):
        self.logger = logger
        self.rate_limit = self.DEFAULT_RATE_LIMIT
        self.rate_limit_remaining = self.DEFAULT_RATE_LIMIT
        self.rate_limit_reset: Optional[datetime] = None
        self.rate_limit_used = 0
        self.rate_limit_buffer = rate_limit_buffer or self.DEFAULT_RATE_LIMIT_BUFFER

    def update_rate_limit(self, response_headers: Any) -> None:
        self.rate_limit = int(response_headers["X-RateLimit-Limit"])
        self.rate_limit_remaining = int(response_headers["X-RateLimit-Remaining"])
        self.rate_limit_reset = datetime.fromtimestamp(int(response_headers["X-RateLimit-Reset"]))
        self.rate_limit_used = int(response_headers["X-RateLimit-Used"])

    def is_valid_token(self) -> bool:
        """Try making a request with the current token. If the request succeeds return True, else False."""
        try:
            response = requests.get(
                url="https://api.github.com/rate_limit",
                headers={
                    "Authorization": f"token {self.token}",
                },
            )
            response.raise_for_status()
            return True
        except requests.exceptions.HTTPError:
            msg = (
                f"A token was dismissed. "
                f"{response.status_code} Client Error: "
                f"{str(response.content)} (Reason: {response.reason})"
            )
            self.logger.warning(msg)
            return False

    def has_calls_remaining(self) -> bool:
        """Check if a token has capacity to make more calls.

        Returns:
            True if the token is valid and has enough api calls remaining.
        """
        too_close_to_limit = self.rate_limit_used > (self.rate_limit - self.rate_limit_buffer)
        reset_time_not_reached = self.rate_limit_reset > datetime.now()

        if self.rate_limit_reset is None:
            return True
        if too_close_to_limit and reset_time_not_reached:
            return False
        return True


class PersonalTokenManager(TokenManager):
    """A class to store token rate limiting information."""

    def __init__(self, token: str, rate_limit_buffer: Optional[int] = None, **kwargs):
        """Init PersonalTokenRateLimit info."""
        self.token = token
        super().__init__(rate_limit_buffer=rate_limit_buffer, **kwargs)


def generate_jwt_token(
    github_app_id: str,
    github_private_key: str,
    expiration_time: int = 600,
    algorithm: str = "RS256",
) -> str:
    actual_time = int(time.time())

    payload = {
        "iat": actual_time,
        "exp": actual_time + expiration_time,
        "iss": github_app_id,
    }
    token = jwt.encode(payload, github_private_key, algorithm=algorithm)

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return token


def generate_app_access_token(
    github_app_id: str,
    github_private_key: str,
    github_installation_id: Optional[str] = None,
) -> str:
    produced_at = datetime.now()
    jwt_token = generate_jwt_token(github_app_id, github_private_key)

    headers = {"Authorization": f"Bearer {jwt_token}"}

    if github_installation_id is None:
        list_installations_resp = requests.get(
            url="https://api.github.com/app/installations", headers=headers
        )
        list_installations_resp.raise_for_status()
        list_installations = list_installations_resp.json()

        if len(list_installations) == 0:
            raise Exception(f"No installations found for app {github_app_id}.")

        github_installation_id = choice(list_installations)["id"]

    url = "https://api.github.com/app/installations/{}/access_tokens".format(
        github_installation_id
    )
    resp = requests.post(url, headers=headers)

    if resp.status_code != 201:
        resp.raise_for_status()

    return resp.json()["token"], produced_at


class AppTokenManager(TokenManager):
    """A class to store an app token's attributes and state, and handle token refreshing"""

    DEFAULT_RATE_LIMIT = 15000
    DEFAULT_EXPIRY_BUFFER = 10

    def refresh_token(self):
        if self.github_private_key:
            token, token_produced_at = generate_app_access_token(
                self.github_app_id, self.github_private_key, self.github_installation_id or None
            )
            is_valid = self.is_valid_token()
            if is_valid:
                self.token = token
                self.token_expires_at = token_produced_at + datetime.timedelta(hours=1)
            else:
                self.logger.warning("Generated token could not be validated.")
                self.token = None
                self.token_expires_at = None
        else:
            self.logger.warning(
                "GITHUB_APP_PRIVATE_KEY could not be parsed. The expected format is "
                '":app_id:;;-----BEGIN RSA PRIVATE KEY-----\\n_YOUR_P_KEY_\\n-----END RSA PRIVATE KEY-----"'
            )
            self.token = None
            self.token_expires_at = None

    def __init__(self, env_key: str, rate_limit_buffer: Optional[int] = None, **kwargs):
        """Init PersonalTokenRateLimit info."""
        parts = env_key.split(";;")
        self.github_app_id = parts[0]
        self.github_private_key = (parts[1:2] or [""])[0].replace("\\n", "\n")
        self.github_installation_id = (parts[2:3] or [""])[0]
        self.refresh_token()

        super().__init__(rate_limit_buffer=rate_limit_buffer, **kwargs)
        self.expiry_time_buffer_mins = self.DEFAULT_EXPIRY_BUFFER

    def has_calls_remaining(self) -> bool:
        """ Confirm whether the app still has capacity remaining, and update the token if getting too old.

        """
        has_time_remaining = datetime.now() + datetime.timedelta(minutes=self.expiry_time_buffer_mins) < self.token_expires_at

        if has_calls_remaining and has_time_remaining:
            return True
        elif has_calls_remaining and not has_time_remaining:
            self.refresh_token()
            if self.token is None:
                return False
            else:
                return True
        else:
            return False


class GitHubTokenAuthenticator(APIAuthenticatorBase):
    """Base class for offloading API auth."""

    def prepare_tokens(self) -> Dict[str, TokenManager]:
        # Save GitHub tokens
        rate_limit_buffer = self._config.get("rate_limit_buffer", None)

        personal_tokens: Set[str] = set()
        if "auth_token" in self._config:
            personal_tokens = personal_tokens.add(self._config["auth_token"])
        if "additional_auth_tokens" in self._config:
            personal_tokens = personal_tokens.union(self._config["additional_auth_tokens"])
        else:
            # Accept multiple tokens using environment variables GITHUB_TOKEN*
            env_tokens = [
                value
                for key, value in environ.items()
                if key.startswith("GITHUB_TOKEN")
            ]
            if len(env_tokens) > 0:
                self.logger.info(
                    f"Found {len(env_tokens)} 'GITHUB_TOKEN' environment variables for authentication."
                )
                personal_tokens = env_tokens

        token_list: List[TokenManager]
        for token in personal_tokens:
            token_manager = PersonalTokenManager(token, rate_limit_buffer, logger=self.logger)
            if token_manager.is_valid_token():
                token_list.append(token_manager)

        # Parse App level private key and generate a token
        if "GITHUB_APP_PRIVATE_KEY" in environ.keys():
            # To simplify settings, we use a single env-key formatted as follows:
            # "{app_id};;{-----BEGIN RSA PRIVATE KEY-----\n_YOUR_PRIVATE_KEY_\n-----END RSA PRIVATE KEY-----}"
            env_key = environ["GITHUB_APP_PRIVATE_KEY"]
            app_token_manager = AppTokenManager(env_key, rate_limit_buffer, logger=self.logger)
            if app_token_manager.is_valid_token():
                token_list.append(app_token_manager)

        self.logger.info(f"Tap will run with {len(filtered_tokens)} auth tokens")
        return token_list

    def __init__(self, stream: RESTStream) -> None:
        """Init authenticator.

        Args:
            stream: A stream for a RESTful endpoint.
        """
        super().__init__(stream=stream)
        self.logger: logging.Logger = stream.logger
        self.tap_name: str = stream.tap_name
        self._config: Dict[str, Any] = dict(stream.config)
        self.token_list = self.prepare_tokens()
        self.active_token: Optional[TokenManager] = (
            choice(token_list) if token_list else None
        )

    def get_next_auth_token(self) -> None:
        tokens_list = self.token_list
        current_token = self.active_token.token if self.active_token else ""
        shuffle(tokens_list)
        for token_manager in tokens_list:
            if token_manager.has_calls_remaining() and current_token != token_manager.token:
                self.active_token = token_manager
                self.logger.info(f"Switching to fresh auth token")
                return

        raise RuntimeError(
            "All GitHub tokens have hit their rate limit. Stopping here."
        )

    def update_rate_limit(
        self, response_headers: requests.models.CaseInsensitiveDict
    ) -> None:
        # If no token or only one token is available, return early.
        if len(self.token_list) <= 1 or self.active_token is None:
            return

        self.active_token.update_rate_limit(response_headers)

    @property
    def auth_headers(self) -> Dict[str, str]:
        """Return a dictionary of auth headers to be applied.

        These will be merged with any `http_headers` specified in the stream.

        Returns:
            HTTP headers for authentication.
        """
        result = super().auth_headers
        if self.active_token:
            # Make sure that our token is still valid or update it.
            if not self.active_token.has_calls_remaining():
                self.get_next_auth_token()
            result["Authorization"] = f"token {self.active_token.token}"
        else:
            self.logger.info(
                "No auth token detected. "
                "For higher rate limits, please specify `auth_token` in config."
            )
        return result
