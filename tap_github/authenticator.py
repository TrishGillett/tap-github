"""Classes to assist in authenticating to the GitHub API."""

import logging
import time
from datetime import datetime
from os import environ
from random import choice, shuffle
from typing import Any, Dict, List, Optional

import jwt
import requests
from singer_sdk.authenticators import APIAuthenticatorBase
from singer_sdk.streams import RESTStream


class TokenManager:
    """A class to store a token's attributes and state."""

    def update_rate_limit(self, response_headers: Any) -> None:
        self.rate_limit = int(response_headers["X-RateLimit-Limit"])
        self.rate_limit_remaining = int(response_headers["X-RateLimit-Remaining"])
        self.rate_limit_reset = int(response_headers["X-RateLimit-Reset"])
        self.rate_limit_used = int(response_headers["X-RateLimit-Used"])

    def is_valid(self) -> bool:
        """Check if token is valid.

        Returns:
            True if the token is valid and has enough api calls remaining.
        """
        if self.rate_limit_reset is None:
            return True
        if (
            self.rate_limit_used > (self.rate_limit - self.rate_limit_buffer)
            and self.rate_limit_reset > datetime.now().timestamp()
        ):
            return False
        return True


class PersonalTokenManager(TokenManager):
    """A class to store token rate limiting information."""

    DEFAULT_RATE_LIMIT = 5000
    # The DEFAULT_RATE_LIMIT_BUFFER buffer serves two purposes:
    # - keep some leeway and rotate tokens before erroring out on rate limit.
    # - not consume all available calls when we rare using an org or user token.
    DEFAULT_RATE_LIMIT_BUFFER = 1000

    def __init__(self, token: str, rate_limit_buffer: Optional[int] = None):
        """Init PersonalTokenRateLimit info."""
        self.token = token
        self.rate_limit = self.DEFAULT_RATE_LIMIT
        self.rate_limit_remaining = self.DEFAULT_RATE_LIMIT
        self.rate_limit_reset: Optional[int] = None
        self.rate_limit_used = 0
        self.rate_limit_buffer = rate_limit_buffer or self.DEFAULT_RATE_LIMIT_BUFFER


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

    return resp.json()["token"]


class AppTokenManager(TokenManager):
    """A class to store an app token's attributes and state, and handle token refreshing"""

    # TODO - add logic to refresh the token

    DEFAULT_RATE_LIMIT = 15000
    # The DEFAULT_RATE_LIMIT_BUFFER buffer serves two purposes:
    # - keep some leeway and rotate tokens before erroring out on rate limit.
    # - not consume all available calls when we rare using an org or user token.
    DEFAULT_RATE_LIMIT_BUFFER = 1000

    def gen_key(self):
        if not (github_private_key):
            self.logger.warning(
                "GITHUB_APP_PRIVATE_KEY could not be parsed. The expected format is "
                '":app_id:;;-----BEGIN RSA PRIVATE KEY-----\n_YOUR_P_KEY_\n-----END RSA PRIVATE KEY-----"'
            )
            return None

        else:
            token = generate_app_access_token(
                self.github_app_id, self.github_private_key, self.github_installation_id or None
            )
            return token

    def __init__(self, env_key: str, rate_limit_buffer: Optional[int] = None):
        """Init PersonalTokenRateLimit info."""
        parts = env_key.split(";;")
        self.github_app_id = parts[0]
        self.github_private_key = (parts[1:2] or [""])[0].replace("\\n", "\n")
        self.github_installation_id = (parts[2:3] or [""])[0]
        self.current_token = self.gen_key()

        self.rate_limit = self.DEFAULT_RATE_LIMIT
        self.rate_limit_remaining = self.DEFAULT_RATE_LIMIT
        self.rate_limit_reset: Optional[int] = None
        self.rate_limit_used = 0
        self.rate_limit_buffer = rate_limit_buffer or self.DEFAULT_RATE_LIMIT_BUFFER


class GitHubTokenAuthenticator(APIAuthenticatorBase):
    """Base class for offloading API auth."""

    def prepare_tokens(self) -> Dict[str, TokenManager]:
        # Save GitHub tokens
        rate_limit_buffer = self._config.get("rate_limit_buffer", None)


        found_tokens: Set[str] = set()
        if "auth_token" in self._config:
            found_tokens = found_tokens.add(self._config["auth_token"])
        if "additional_auth_tokens" in self._config:
            found_tokens = found_tokens.union(self._config["additional_auth_tokens"])
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
                found_tokens = env_tokens

        tokens_map = {
            token: PersonalTokenManager(token, rate_limit_buffer) for token in found_tokens
        }

        # Parse App level private key and generate a token
        if "GITHUB_APP_PRIVATE_KEY" in environ.keys():
            # To simplify settings, we use a single env-key formatted as follows:
            # "{app_id};;{-----BEGIN RSA PRIVATE KEY-----\n_YOUR_PRIVATE_KEY_\n-----END RSA PRIVATE KEY-----}"
            env_key = environ["GITHUB_APP_PRIVATE_KEY"]
            rate_limit_buffer = self._config.get("rate_limit_buffer", None)
            app_token_manager = AppTokenManager(env_key, rate_limit_buffer=rate_limit_buffer)
            if app_token_manager.current_token is not None:
                tokens_map[app_token_manager.current_token] = app_token_manager

        for token in tokens_map:
            try:
                response = requests.get(
                    url="https://api.github.com/rate_limit",
                    headers={
                        "Authorization": f"token {token}",
                    },
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                del tokens_map[token]
                msg = (
                    f"A token was dismissed. "
                    f"{response.status_code} Client Error: "
                    f"{str(response.content)} (Reason: {response.reason})"
                )
                self.logger.warning(msg)

        self.logger.info(f"Tap will run with {len(filtered_tokens)} auth tokens")

    def __init__(self, stream: RESTStream) -> None:
        """Init authenticator.

        Args:
            stream: A stream for a RESTful endpoint.
        """
        super().__init__(stream=stream)
        self.logger: logging.Logger = stream.logger
        self.tap_name: str = stream.tap_name
        self._config: Dict[str, Any] = dict(stream.config)
        self.tokens_map = self.prepare_tokens()
        self.active_token: Optional[PersonalTokenManager] = (
            choice(list(self.tokens_map.values())) if len(self.tokens_map) else None
        )

    def get_next_auth_token(self) -> None:
        tokens_list = list(self.tokens_map.items())
        current_token = self.active_token.token if self.active_token else ""
        shuffle(tokens_list)
        for _, token_rate_limit in tokens_list:
            if token_rate_limit.is_valid() and current_token != token_rate_limit.token:
                self.active_token = token_rate_limit
                self.logger.info(f"Switching to fresh auth token")
                return

        raise RuntimeError(
            "All GitHub tokens have hit their rate limit. Stopping here."
        )

    def update_rate_limit(
        self, response_headers: requests.models.CaseInsensitiveDict
    ) -> None:
        # If no token or only one token is available, return early.
        if len(self.tokens_map) <= 1 or self.active_token is None:
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
            if not self.active_token.is_valid():
                self.get_next_auth_token()
            result["Authorization"] = f"token {self.active_token.token}"
        else:
            self.logger.info(
                "No auth token detected. "
                "For higher rate limits, please specify `auth_token` in config."
            )
        return result
