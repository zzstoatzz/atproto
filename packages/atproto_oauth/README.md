# atproto_oauth

complete OAuth 2.1 implementation for the ATProto Python SDK, following the [ATProto OAuth specification](https://atproto.com/specs/oauth).

## features

✅ **full OAuth 2.1 compliance**
- authorization code grant with PKCE (S256)
- DPoP (Demonstrating Proof-of-Possession) with ES256
- PAR (Pushed Authorization Requests)
- automatic DPoP nonce rotation
- client assertions for confidential clients

✅ **ATProto-specific**
- DID-based authentication
- handle/DID resolution and verification
- PDS endpoint discovery
- authorization server discovery
- works with Bluesky and custom PDS instances

✅ **production-ready**
- comprehensive error handling
- SSRF protection and URL validation
- async-first design
- pluggable state store for authorization flow
- caller-managed session persistence
- fully typed with type hints

## quick start

### basic usage

```python
from atproto_oauth import OAuthClient
from atproto_oauth.stores import MemoryStateStore

# create OAuth client
oauth = OAuthClient(
    client_id='http://localhost',  # or your HTTPS URL for production
    redirect_uri='http://127.0.0.1:5000/callback',
    scope='atproto',
    state_store=MemoryStateStore(),
)

# start authorization flow
auth_url, state = await oauth.start_authorization('user.bsky.social')

# user authorizes in browser, then...

# handle callback - returns OAuthSession
session = await oauth.handle_callback(
    code=authorization_code,
    state=state,
    iss=issuer_from_callback,
)

# persist session however you want (database, encrypted cookie, etc.)
# await save_to_database(session)

# use with atproto_client for authenticated requests
from atproto_client import AsyncClient

atproto = AsyncClient(
    oauth_client_id='http://localhost',
    oauth_redirect_uri='http://127.0.0.1:5000/callback',
    oauth_scope='atproto',
)
atproto.oauth_login(session)

# all client methods now work with OAuth
profile = await atproto.get_profile(session.did)
```

### flask example

see [examples/oauth_flask_demo](../../examples/oauth_flask_demo/) for complete working example.

## installation

```bash
uv add atproto  # includes atproto_oauth
```

## core components

### OAuthClient

handles the OAuth authorization flow:

```python
oauth = OAuthClient(
    client_id='https://yourapp.com/client-metadata.json',
    redirect_uri='https://yourapp.com/callback',
    scope='atproto',
    state_store=your_state_store,
    client_secret_key=your_secret_key,  # optional, for confidential clients
)
```

**methods:**
- `start_authorization(handle_or_did)` - begin OAuth flow, returns (auth_url, state)
- `handle_callback(code, state, iss)` - complete OAuth flow, returns OAuthSession
- `refresh_session(session)` - refresh tokens, returns updated OAuthSession
- `revoke_session(session)` - revoke tokens with auth server

**session persistence is your responsibility.** store the OAuthSession returned from
`handle_callback()` however you want (database, encrypted cookie, etc.), then pass
it to `Client.oauth_login()` for authenticated requests.

### state store

state stores hold temporary data during the OAuth authorization flow (PKCE verifier,
DPoP key, etc.). state is short-lived (10 minutes) and single-use.

```python
from atproto_oauth.stores import MemoryStateStore

# memory store (development only)
state_store = MemoryStateStore(state_ttl_seconds=600)
```

**custom state store:**

```python
from atproto_oauth.stores.base import StateStore

class RedisStateStore(StateStore):
    async def save_state(self, state: OAuthState) -> None:
        # save to redis with TTL
        pass

    async def get_state(self, state_key: str) -> Optional[OAuthState]:
        # retrieve from redis
        pass

    async def delete_state(self, state_key: str) -> None:
        # delete from redis
        pass
```

### models

```python
from atproto_oauth.models import OAuthSession, OAuthState, AuthServerMetadata

# OAuth session with tokens
session: OAuthSession

# access user info
print(session.did, session.handle, session.pds_url)
print(session.access_token, session.refresh_token)
```

### utilities

```python
from atproto_oauth.pkce import PKCEManager
from atproto_oauth.dpop import DPoPManager
from atproto_oauth.metadata import fetch_authserver_metadata_async

# generate PKCE pair
verifier, challenge = PKCEManager.generate_pair()

# generate DPoP keypair
dpop_key = DPoPManager.generate_keypair()

# discover authorization server
metadata = await fetch_authserver_metadata_async('https://bsky.social')
```

## architecture

### authorization flow

```
1. user enters handle (e.g., user.bsky.social)
2. resolve handle → DID → PDS endpoint → auth server
3. generate PKCE verifier/challenge
4. generate DPoP keypair
5. send PAR (Pushed Authorization Request)
6. redirect user to authorization server
7. user authorizes
8. callback with authorization code
9. exchange code for tokens (with PKCE + DPoP)
10. store OAuth session
```

### security features

**PKCE (Proof Key for Code Exchange)**
- prevents authorization code interception
- S256 challenge method required

**DPoP (Demonstrating Proof-of-Possession)**
- binds tokens to client key
- prevents token theft/replay
- automatic nonce rotation

**state parameter**
- CSRF protection
- cryptographically secure tokens
- single-use, time-limited

**URL validation**
- SSRF protection
- private IP blocking
- HTTPS enforcement (except localhost)

## comparison with nick's PR #589

### what nick implemented ✅
- DPoP support in Session class
- static token handling
- basic DPoP JWT generation

### what this package adds 🆕
- complete OAuth authorization flow
- PKCE implementation
- PAR (Pushed Authorization Requests)
- state management with stores
- token refresh with OAuth
- client metadata support
- authorization server discovery
- comprehensive error handling
- production-ready security

## production deployment

### 1. use persistent state store

```python
from your_app.stores import RedisStateStore

oauth = OAuthClient(
    state_store=RedisStateStore(),  # for multi-instance deployments
    ...
)
```

### 2. persist sessions yourself

```python
# after OAuth callback
session = await oauth.handle_callback(code, state, iss)

# serialize and encrypt for storage
session_data = serialize_oauth_session(session)
encrypted = encrypt(session_data)
await db.save_user_session(user_id, encrypted)

# later, restore and use
encrypted = await db.get_user_session(user_id)
session_data = decrypt(encrypted)
session = deserialize_oauth_session(session_data)
client.oauth_login(session)
```

### 3. deploy with HTTPS

```python
oauth = OAuthClient(
    client_id='https://yourapp.com/oauth-client-metadata.json',
    redirect_uri='https://yourapp.com/callback',
    ...
)
```

### 4. create client metadata

serve at `https://yourapp.com/oauth-client-metadata.json`:

```json
{
  "client_id": "https://yourapp.com/oauth-client-metadata.json",
  "dpop_bound_access_tokens": true,
  "application_type": "web",
  "redirect_uris": ["https://yourapp.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "atproto",
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks_uri": "https://yourapp.com/oauth/jwks.json",
  "client_name": "Your App Name",
  "client_uri": "https://yourapp.com"
}
```

### 4. generate client secret (confidential clients)

```python
from atproto_oauth.dpop import DPoPManager

# generate once, store securely (e.g., in secrets manager)
client_secret_key = DPoPManager.generate_keypair()

# use in OAuth client
client = OAuthClient(
    client_secret_key=client_secret_key,
    ...
)
```

### 5. implement token refresh

```python
# check if token is expired
if session.expires_at and datetime.now(timezone.utc) > session.expires_at:
    session = await client.refresh_session(session)
```

### 6. handle errors gracefully

```python
from atproto_oauth.exceptions import OAuthError, OAuthStateError, OAuthTokenError

try:
    session = await client.handle_callback(code, state, iss)
except OAuthStateError as e:
    # invalid/expired state - restart flow
    pass
except OAuthTokenError as e:
    # token exchange failed - show error
    pass
except OAuthError as e:
    # general OAuth error
    pass
```

## testing

run unit tests:

```bash
uv run pytest tests/test_oauth_pkce.py tests/test_oauth_dpop.py -v
```

all 12 tests pass:
- ✅ PKCE verifier/challenge generation
- ✅ DPoP keypair generation
- ✅ DPoP proof JWT creation
- ✅ DPoP nonce error detection
- ✅ access token hash (ath) claim

## troubleshooting

### "Invalid or expired state parameter"
**cause:** state expired (default 10 min) or already used
**solution:** restart authorization flow

### "DID mismatch in token"
**cause:** user identity changed during authorization
**solution:** retry with fresh authorization

### "Unsupported authorization server"
**cause:** auth server doesn't meet ATProto requirements
**solution:** check server metadata compliance

### "DPoP nonce error"
**cause:** server requires fresh nonce (handled automatically)
**solution:** library retries automatically

### import errors
**cause:** missing dependencies
**solution:** `uv sync` to install all dependencies

## development

### run tests

```bash
uv run pytest tests/test_oauth*.py -v
```

### run flask demo

```bash
uv run python examples/oauth_flask_demo/app.py
```

### type checking

```bash
uv run mypy packages/atproto_oauth
```

## references

- [ATProto OAuth Specification](https://atproto.com/specs/oauth)
- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [RFC 9449 - DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9126 - PAR](https://datatracker.ietf.org/doc/html/rfc9126)
- [Bluesky OAuth Cookbook](https://github.com/bluesky-social/cookbook/tree/main/python-oauth-web-app)

## license

MIT

## contributing

contributions welcome! areas for improvement:

- [ ] SQLite/PostgreSQL session stores
- [ ] Redis state store
- [ ] token automatic refresh
- [ ] scope management helpers
- [ ] more comprehensive tests
- [ ] integration tests with real PDS
- [ ] async/sync sync wrappers
- [ ] documentation improvements

see main [atproto repository](https://github.com/MarshalX/atproto) for contribution guidelines.
