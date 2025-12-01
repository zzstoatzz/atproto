"""DPoP (Demonstrating Proof-of-Possession) implementation."""

import hashlib
import json
import secrets
import time
import typing as t
from base64 import urlsafe_b64encode
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

if t.TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from atproto_client.request import Response as SDKResponse

# Union type for both httpx.Response and SDK Response
ResponseType = t.Union[httpx.Response, 'SDKResponse']


class DPoPManager:
    """Manages DPoP proof generation for OAuth."""

    @staticmethod
    def generate_keypair() -> 'EllipticCurvePrivateKey':
        """Generate ES256 keypair for DPoP.

        Returns:
            EC private key (P-256 curve).
        """
        return ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def _key_to_jwk(private_key: 'EllipticCurvePrivateKey', include_private: bool = False) -> t.Dict[str, t.Any]:
        """Convert EC private key to JWK format.

        Args:
            private_key: The EC private key.
            include_private: Whether to include private key components.

        Returns:
            JWK dictionary.
        """
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Convert to bytes and base64url encode
        def int_to_base64url(n: int, length: int) -> str:
            byte_len = (length + 7) // 8
            return urlsafe_b64encode(n.to_bytes(byte_len, 'big')).decode('utf-8').rstrip('=')

        jwk = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': int_to_base64url(public_numbers.x, 256),
            'y': int_to_base64url(public_numbers.y, 256),
        }

        if include_private:
            private_numbers = private_key.private_numbers()
            jwk['d'] = int_to_base64url(private_numbers.private_value, 256)

        return jwk

    @staticmethod
    def _sign_jwt(
        header: t.Dict[str, t.Any], payload: t.Dict[str, t.Any], private_key: 'EllipticCurvePrivateKey'
    ) -> str:
        """Sign a JWT using ES256.

        Args:
            header: JWT header.
            payload: JWT payload.
            private_key: EC private key for signing.

        Returns:
            Complete JWT string.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        # Encode header and payload
        header_b64 = urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
        payload_b64 = urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')

        # Create signing input
        signing_input = f'{header_b64}.{payload_b64}'.encode()

        # Sign (returns DER-encoded signature)
        der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

        # Convert DER signature to IEEE P1363 format (raw r|s concatenated)
        # ES256 uses P-256 curve, so r and s are each 32 bytes
        r, s = decode_dss_signature(der_signature)

        # Convert r and s to 32-byte big-endian sequences
        r_bytes = r.to_bytes(32, 'big')
        s_bytes = s.to_bytes(32, 'big')

        # Concatenate and encode
        raw_signature = r_bytes + s_bytes
        signature_b64 = urlsafe_b64encode(raw_signature).decode().rstrip('=')

        return f'{header_b64}.{payload_b64}.{signature_b64}'

    @classmethod
    def create_proof(
        cls,
        method: str,
        url: str,
        private_key: 'EllipticCurvePrivateKey',
        nonce: t.Optional[str] = None,
        access_token: t.Optional[str] = None,
    ) -> str:
        """Generate DPoP proof JWT.

        Args:
            method: HTTP method (e.g., 'GET', 'POST').
            url: Full URL of the request.
            private_key: EC private key for signing.
            nonce: Optional server-provided nonce.
            access_token: Optional access token (for 'ath' claim).

        Returns:
            DPoP proof JWT string.
        """
        # Get public key JWK
        public_jwk = cls._key_to_jwk(private_key, include_private=False)

        # Create header
        header = {
            'typ': 'dpop+jwt',
            'alg': 'ES256',
            'jwk': public_jwk,
        }

        # Strip query and fragment from URL per RFC 9449
        parsed_url = urlparse(url)
        htu = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}'

        # Create payload
        now = int(time.time())
        payload = {
            'jti': secrets.token_urlsafe(16),
            'htm': method.upper(),
            'htu': htu,
            'iat': now,
            'exp': now + 60,  # Valid for 60 seconds
        }

        # Add optional claims
        if nonce:
            payload['nonce'] = nonce

        if access_token:
            # Hash access token for 'ath' claim (same as PKCE S256)
            ath_hash = hashlib.sha256(access_token.encode('utf-8')).digest()
            payload['ath'] = urlsafe_b64encode(ath_hash).decode('utf-8').rstrip('=')

        return cls._sign_jwt(header, payload, private_key)

    @staticmethod
    def _get_header(response: ResponseType, header_name: str) -> t.Optional[str]:
        """Get header value from response, handling both httpx and SDK response types.

        SDK Response has lowercase keys, httpx.Headers is case-insensitive.

        Args:
            response: HTTP response object (httpx.Response or SDK Response).
            header_name: Header name to look up.

        Returns:
            Header value if present, None otherwise.
        """
        headers = response.headers
        # Try original case first (works for httpx.Headers which is case-insensitive)
        if value := headers.get(header_name):
            return value
        # Try lowercase (SDK Response normalizes to lowercase)
        if value := headers.get(header_name.lower()):
            return value
        return None

    @staticmethod
    def _get_error_body(response: ResponseType) -> t.Optional[t.Dict[str, t.Any]]:
        """Get JSON error body from response, handling both httpx and SDK response types.

        httpx.Response has .json() method, SDK Response has .content dict.

        Args:
            response: HTTP response object.

        Returns:
            Parsed JSON body as dict if available, None otherwise.
        """
        # Check if this is SDK Response (has .content that may already be parsed)
        if hasattr(response, 'content') and isinstance(response.content, dict):
            return response.content

        # Check for XrpcError (SDK's parsed error type)
        if hasattr(response, 'content') and hasattr(response.content, 'error'):
            return {'error': response.content.error, 'message': getattr(response.content, 'message', None)}

        # httpx.Response - call .json()
        if hasattr(response, 'json'):
            try:
                return response.json()
            except Exception:
                pass

        return None

    @classmethod
    def extract_nonce_from_response(cls, response: ResponseType) -> t.Optional[str]:
        """Extract DPoP nonce from HTTP response.

        Checks both the 'DPoP-Nonce' header and error responses.
        Handles both httpx.Response and SDK Response types.

        Args:
            response: HTTP response object.

        Returns:
            DPoP nonce string if present, None otherwise.
        """
        # Check DPoP-Nonce header (handles both cases)
        if nonce := cls._get_header(response, 'DPoP-Nonce'):
            return nonce

        # Check for error response with use_dpop_nonce
        if response.status_code in (400, 401):
            error_body = cls._get_error_body(response)
            if isinstance(error_body, dict) and error_body.get('error') == 'use_dpop_nonce':
                return cls._get_header(response, 'DPoP-Nonce')

        return None

    @classmethod
    def is_dpop_nonce_error(cls, response: ResponseType) -> bool:
        """Check if response indicates DPoP nonce error.

        Handles both httpx.Response and SDK Response types.

        Args:
            response: HTTP response object.

        Returns:
            True if response indicates need for new DPoP nonce.
        """
        if response.status_code not in (400, 401):
            return False

        # Check WWW-Authenticate header
        if www_auth := cls._get_header(response, 'WWW-Authenticate'):
            if 'use_dpop_nonce' in www_auth.lower():
                return True

        # Check JSON error response
        error_body = cls._get_error_body(response)
        if isinstance(error_body, dict) and error_body.get('error') == 'use_dpop_nonce':
            return True

        return False
