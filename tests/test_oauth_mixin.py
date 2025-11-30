"""Tests for OAuth mixin integration with Client and AsyncClient."""

import pytest
from atproto_client import Client
from atproto_oauth.models import OAuthSession
from cryptography.hazmat.primitives.asymmetric import ec


def _make_test_session() -> OAuthSession:
    """Create a test OAuth session with dummy values."""
    dpop_key = ec.generate_private_key(ec.SECP256R1())
    return OAuthSession(
        did='did:plc:test123',
        handle='test.bsky.social',
        pds_url='https://pds.example.com',
        authserver_iss='https://auth.example.com',
        access_token='eyJhbGciOiJFUzI1NiJ9.test.sig',  # JWT-like format
        refresh_token='eyJhbGciOiJFUzI1NiJ9.refresh.sig',
        dpop_private_key=dpop_key,
        dpop_authserver_nonce='test-nonce',
        scope='atproto',
    )


class TestOAuthMixinIntegration:
    """Tests for OAuthSessionMixin integration with Client."""

    def test_client_instantiates_without_oauth_config(self) -> None:
        """Client should work normally without OAuth configuration."""
        client = Client()
        assert client._oauth_client_id is None
        assert client._oauth_redirect_uri is None
        assert client._oauth_scope is None
        assert not client._is_oauth_session()

    def test_client_accepts_oauth_config(self) -> None:
        """Client should accept OAuth configuration via kwargs."""
        client = Client(
            oauth_client_id='https://example.com/client-metadata.json',
            oauth_redirect_uri='https://example.com/callback',
            oauth_scope='atproto',
        )
        assert client._oauth_client_id == 'https://example.com/client-metadata.json'
        assert client._oauth_redirect_uri == 'https://example.com/callback'
        assert client._oauth_scope == 'atproto'

    def test_ensure_oauth_initialized_raises_without_config(self) -> None:
        """_ensure_oauth_initialized should raise when OAuth not configured."""
        client = Client()
        with pytest.raises(ValueError, match='OAuth not configured'):
            client._ensure_oauth_initialized()

    def test_oauth_login_sets_session(self) -> None:
        """oauth_login should set the OAuth session and update base URL."""
        client = Client(
            oauth_client_id='https://example.com/client-metadata.json',
            oauth_redirect_uri='https://example.com/callback',
            oauth_scope='atproto',
        )

        session = _make_test_session()
        client.oauth_login(session)

        assert client._is_oauth_session()
        assert client._oauth_session == session
        assert 'pds.example.com' in client._base_url
        assert client.me.did == 'did:plc:test123'
        assert client.me.handle == 'test.bsky.social'

    def test_oauth_logout_clears_session(self) -> None:
        """oauth_logout should clear the OAuth session."""
        client = Client(
            oauth_client_id='https://example.com/client-metadata.json',
            oauth_redirect_uri='https://example.com/callback',
            oauth_scope='atproto',
        )

        session = _make_test_session()
        client.oauth_login(session)
        assert client._is_oauth_session()

        client.oauth_logout()
        assert not client._is_oauth_session()
        assert client._oauth_session is None

    def test_export_oauth_session_returns_session(self) -> None:
        """export_oauth_session should return the current session."""
        client = Client(
            oauth_client_id='https://example.com/client-metadata.json',
            oauth_redirect_uri='https://example.com/callback',
            oauth_scope='atproto',
        )

        session = _make_test_session()
        client.oauth_login(session)
        exported = client.export_oauth_session()

        assert exported == session

    def test_export_oauth_session_returns_none_when_not_logged_in(self) -> None:
        """export_oauth_session should return None when not in OAuth session."""
        client = Client()
        assert client.export_oauth_session() is None


class TestAsyncOAuthMixinIntegration:
    """Tests for AsyncOAuthSessionMixin integration with AsyncClient."""

    def test_async_client_instantiates_without_oauth_config(self) -> None:
        """AsyncClient should work normally without OAuth configuration."""
        from atproto_client import AsyncClient

        client = AsyncClient()
        assert client._oauth_client_id is None
        assert not client._is_oauth_session()

    def test_async_client_accepts_oauth_config(self) -> None:
        """AsyncClient should accept OAuth configuration via kwargs."""
        from atproto_client import AsyncClient

        client = AsyncClient(
            oauth_client_id='https://example.com/client-metadata.json',
            oauth_redirect_uri='https://example.com/callback',
            oauth_scope='atproto',
        )
        assert client._oauth_client_id == 'https://example.com/client-metadata.json'

    def test_async_oauth_login_sets_session(self) -> None:
        """oauth_login should work on AsyncClient."""
        from atproto_client import AsyncClient

        client = AsyncClient(
            oauth_client_id='https://example.com/client-metadata.json',
            oauth_redirect_uri='https://example.com/callback',
            oauth_scope='atproto',
        )

        session = _make_test_session()
        client.oauth_login(session)

        assert client._is_oauth_session()
        assert 'pds.example.com' in client._base_url
