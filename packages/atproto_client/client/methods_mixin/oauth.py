"""OAuth 2.1 session mixin for ATProto clients.

This mixin adds OAuth authentication support to the Client and AsyncClient classes,
enabling transparent OAuth session handling through the existing _invoke method.
"""

import typing as t

if t.TYPE_CHECKING:
    from atproto_client.client.base import InvokeType
    from atproto_client.request import Response


class OAuthSessionMixin:
    """Mixin that adds OAuth session support to sync Client.

    When an OAuth session is active, all requests are automatically authenticated
    with DPoP proofs. The mixin overrides _invoke to handle this transparently.

    OAuth configuration is optional - clients work normally without it.
    """

    def __init__(
        self,
        *args: t.Any,
        oauth_client_id: t.Optional[str] = None,
        oauth_redirect_uri: t.Optional[str] = None,
        oauth_scope: t.Optional[str] = None,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        # OAuth configuration (optional)
        self._oauth_client_id = oauth_client_id
        self._oauth_redirect_uri = oauth_redirect_uri
        self._oauth_scope = oauth_scope

        # OAuth session state
        self._oauth_session: t.Optional['OAuthSessionData'] = None

        # Lazy-initialized components
        self._oauth_initialized = False
        self._dpop_manager: t.Optional[t.Any] = None
        self._pkce_manager: t.Optional[t.Any] = None
        self._id_resolver: t.Optional[t.Any] = None

    def _ensure_oauth_initialized(self) -> None:
        """Initialize OAuth components on first use."""
        if self._oauth_initialized:
            return

        if not all([self._oauth_client_id, self._oauth_redirect_uri, self._oauth_scope]):
            raise ValueError('OAuth not configured. Provide oauth_client_id, oauth_redirect_uri, and oauth_scope.')

        from atproto_identity.resolver import IdResolver
        from atproto_oauth.dpop import DPoPManager
        from atproto_oauth.pkce import PKCEManager

        self._dpop_manager = DPoPManager()
        self._pkce_manager = PKCEManager()
        self._id_resolver = IdResolver()
        self._oauth_initialized = True

    def _is_oauth_session(self) -> bool:
        """Check if currently using an OAuth session."""
        return self._oauth_session is not None

    def _invoke(self, invoke_type: 'InvokeType', **kwargs: t.Any) -> 'Response':
        """Override _invoke to handle OAuth sessions with DPoP.

        For OAuth sessions, adds DPoP proof and handles nonce rotation automatically.
        For regular sessions, delegates to parent implementation.
        """
        # Non-OAuth requests use normal flow
        if not self._is_oauth_session():
            return super()._invoke(invoke_type, **kwargs)  # type: ignore[misc]

        self._ensure_oauth_initialized()
        return self._invoke_with_oauth(invoke_type, **kwargs)

    def _invoke_with_oauth(self, invoke_type: 'InvokeType', **kwargs: t.Any) -> 'Response':
        """Make OAuth-authenticated request with DPoP proof."""
        from atproto_oauth.dpop import DPoPManager

        from atproto_client.client.base import InvokeType, _handle_kwargs
        from atproto_client.exceptions import UnauthorizedError

        _handle_kwargs(kwargs)

        url = kwargs.get('url', '')
        headers = kwargs.pop('headers', {})
        session = self._oauth_session

        # Use PDS nonce for requests
        current_nonce = session.dpop_pds_nonce or ''

        for attempt in range(2):
            # Create DPoP proof
            dpop_proof = self._dpop_manager.create_proof(
                method='GET' if invoke_type is InvokeType.QUERY else 'POST',
                url=url,
                private_key=session.dpop_private_key,
                nonce=current_nonce if current_nonce else None,
                access_token=session.access_token,
            )

            headers['Authorization'] = f'DPoP {session.access_token}'
            headers['DPoP'] = dpop_proof

            try:
                if invoke_type is InvokeType.QUERY:
                    response = self.request.get(headers=headers, **kwargs)
                else:
                    response = self.request.post(headers=headers, **kwargs)
            except UnauthorizedError as e:
                # Check if it's a DPoP nonce error
                if DPoPManager.is_dpop_nonce_error(e.response) and attempt == 0:
                    new_nonce = DPoPManager.extract_nonce_from_response(e.response)
                    if new_nonce:
                        current_nonce = new_nonce
                        continue
                raise

            # Check for nonce error in successful response (rare but possible)
            if DPoPManager.is_dpop_nonce_error(response) and attempt == 0:
                new_nonce = DPoPManager.extract_nonce_from_response(response)
                if new_nonce:
                    current_nonce = new_nonce
                    continue

            # Update stored PDS nonce
            new_nonce = DPoPManager.extract_nonce_from_response(response)
            if new_nonce:
                session.dpop_pds_nonce = new_nonce

            return response

        return response

    def oauth_login(
        self,
        oauth_session: 'OAuthSessionData',
    ) -> None:
        """Set up client with an OAuth session.

        After calling this, all requests will be authenticated with OAuth/DPoP.
        The client's base URL is automatically updated to the user's PDS.

        Args:
            oauth_session: OAuth session data from handle_oauth_callback or restored from storage.

        Example:
            >>> # After OAuth callback
            >>> session = await oauth_client.handle_callback(code, state, iss)
            >>> client.oauth_login(session)
            >>> # Now use client normally
            >>> timeline = client.get_timeline()
        """
        self._oauth_session = oauth_session
        self.update_base_url(oauth_session.pds_url)

        # Set me attribute for convenience methods
        self.me = type('ProfileStub', (), {'did': oauth_session.did, 'handle': oauth_session.handle})()

    def oauth_logout(self) -> None:
        """Clear OAuth session."""
        self._oauth_session = None

    def export_oauth_session(self) -> t.Optional['OAuthSessionData']:
        """Export OAuth session for persistence.

        Returns the current OAuth session data which can be serialized
        and stored, then later restored with oauth_login().

        Returns:
            OAuth session data, or None if not in OAuth session.
        """
        return self._oauth_session


class AsyncOAuthSessionMixin:
    """Async version of OAuthSessionMixin for AsyncClient."""

    def __init__(
        self,
        *args: t.Any,
        oauth_client_id: t.Optional[str] = None,
        oauth_redirect_uri: t.Optional[str] = None,
        oauth_scope: t.Optional[str] = None,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        # OAuth configuration (optional)
        self._oauth_client_id = oauth_client_id
        self._oauth_redirect_uri = oauth_redirect_uri
        self._oauth_scope = oauth_scope

        # OAuth session state
        self._oauth_session: t.Optional['OAuthSessionData'] = None

        # Lazy-initialized components
        self._oauth_initialized = False
        self._dpop_manager: t.Optional[t.Any] = None
        self._pkce_manager: t.Optional[t.Any] = None
        self._id_resolver: t.Optional[t.Any] = None

    def _ensure_oauth_initialized(self) -> None:
        """Initialize OAuth components on first use."""
        if self._oauth_initialized:
            return

        if not all([self._oauth_client_id, self._oauth_redirect_uri, self._oauth_scope]):
            raise ValueError('OAuth not configured. Provide oauth_client_id, oauth_redirect_uri, and oauth_scope.')

        from atproto_identity.resolver import AsyncIdResolver
        from atproto_oauth.dpop import DPoPManager
        from atproto_oauth.pkce import PKCEManager

        self._dpop_manager = DPoPManager()
        self._pkce_manager = PKCEManager()
        self._id_resolver = AsyncIdResolver()
        self._oauth_initialized = True

    def _is_oauth_session(self) -> bool:
        """Check if currently using an OAuth session."""
        return self._oauth_session is not None

    async def _invoke(self, invoke_type: 'InvokeType', **kwargs: t.Any) -> 'Response':
        """Override _invoke to handle OAuth sessions with DPoP.

        For OAuth sessions, adds DPoP proof and handles nonce rotation automatically.
        For regular sessions, delegates to parent implementation.
        """
        # Non-OAuth requests use normal flow
        if not self._is_oauth_session():
            return await super()._invoke(invoke_type, **kwargs)  # type: ignore[misc]

        self._ensure_oauth_initialized()
        return await self._invoke_with_oauth(invoke_type, **kwargs)

    async def _invoke_with_oauth(self, invoke_type: 'InvokeType', **kwargs: t.Any) -> 'Response':
        """Make OAuth-authenticated request with DPoP proof."""
        from atproto_oauth.dpop import DPoPManager

        from atproto_client.client.base import InvokeType, _handle_kwargs
        from atproto_client.exceptions import UnauthorizedError

        _handle_kwargs(kwargs)

        url = kwargs.get('url', '')
        headers = kwargs.pop('headers', {})
        session = self._oauth_session

        # Use PDS nonce for requests
        current_nonce = session.dpop_pds_nonce or ''

        for attempt in range(2):
            # Create DPoP proof
            dpop_proof = self._dpop_manager.create_proof(
                method='GET' if invoke_type is InvokeType.QUERY else 'POST',
                url=url,
                private_key=session.dpop_private_key,
                nonce=current_nonce if current_nonce else None,
                access_token=session.access_token,
            )

            headers['Authorization'] = f'DPoP {session.access_token}'
            headers['DPoP'] = dpop_proof

            try:
                if invoke_type is InvokeType.QUERY:
                    response = await self.request.get(headers=headers, **kwargs)
                else:
                    response = await self.request.post(headers=headers, **kwargs)
            except UnauthorizedError as e:
                # Check if it's a DPoP nonce error
                if DPoPManager.is_dpop_nonce_error(e.response) and attempt == 0:
                    new_nonce = DPoPManager.extract_nonce_from_response(e.response)
                    if new_nonce:
                        current_nonce = new_nonce
                        continue
                raise

            # Check for nonce error in successful response
            if DPoPManager.is_dpop_nonce_error(response) and attempt == 0:
                new_nonce = DPoPManager.extract_nonce_from_response(response)
                if new_nonce:
                    current_nonce = new_nonce
                    continue

            # Update stored PDS nonce
            new_nonce = DPoPManager.extract_nonce_from_response(response)
            if new_nonce:
                session.dpop_pds_nonce = new_nonce

            return response

        return response

    def oauth_login(
        self,
        oauth_session: 'OAuthSessionData',
    ) -> None:
        """Set up client with an OAuth session.

        After calling this, all requests will be authenticated with OAuth/DPoP.
        The client's base URL is automatically updated to the user's PDS.

        Args:
            oauth_session: OAuth session data from handle_oauth_callback or restored from storage.

        Example:
            >>> # After OAuth callback
            >>> session = await oauth_client.handle_callback(code, state, iss)
            >>> client.oauth_login(session)
            >>> # Now use client normally
            >>> timeline = await client.get_timeline()
        """
        self._oauth_session = oauth_session
        self.update_base_url(oauth_session.pds_url)

        # Set me attribute for convenience methods
        self.me = type('ProfileStub', (), {'did': oauth_session.did, 'handle': oauth_session.handle})()

    def oauth_logout(self) -> None:
        """Clear OAuth session."""
        self._oauth_session = None

    def export_oauth_session(self) -> t.Optional['OAuthSessionData']:
        """Export OAuth session for persistence.

        Returns the current OAuth session data which can be serialized
        and stored, then later restored with oauth_login().

        Returns:
            OAuth session data, or None if not in OAuth session.
        """
        return self._oauth_session


# Re-export OAuthSession as OAuthSessionData for clarity in mixin context
from atproto_oauth.models import OAuthSession as OAuthSessionData  # noqa: E402

__all__ = ['AsyncOAuthSessionMixin', 'OAuthSessionData', 'OAuthSessionMixin']
