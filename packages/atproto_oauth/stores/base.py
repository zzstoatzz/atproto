"""Abstract base classes for OAuth stores."""

import typing as t
from abc import ABC, abstractmethod

if t.TYPE_CHECKING:
    from atproto_oauth.models import OAuthState


class StateStore(ABC):
    """Abstract store for OAuth state during authorization flow.

    State is short-lived (typically 10 minutes) and holds PKCE verifier,
    DPoP key, and other data needed to complete the OAuth callback.

    Note:
        Session persistence is the caller's responsibility. The OAuthClient
        returns OAuthSession objects that should be stored by the application
        and passed to Client.oauth_login() for authenticated requests.
    """

    @abstractmethod
    async def save_state(self, state: 'OAuthState') -> None:
        """Save OAuth state.

        Args:
            state: OAuth state object to save.
        """

    @abstractmethod
    async def get_state(self, state_key: str) -> t.Optional['OAuthState']:
        """Retrieve OAuth state by key.

        Args:
            state_key: State identifier.

        Returns:
            OAuth state object if found, None otherwise.
        """

    @abstractmethod
    async def delete_state(self, state_key: str) -> None:
        """Delete OAuth state by key.

        Args:
            state_key: State identifier.
        """
