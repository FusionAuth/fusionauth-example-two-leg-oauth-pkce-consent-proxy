# Two-Leg OAuth PKCE Consent Proxy — POC

This directory contains a proof-of-concept demonstrating a two-leg OAuth 2.0
authorization code + PKCE flow where a consent proxy (App B) intercepts the
login flow, authenticates the user, runs consent logic, and then re-initiates
the flow so the real application (App A) receives its own access token.

Both apps share a single FusionAuth application but use two different
registered redirect URIs.

---

## Directory structure

```
consent-poc/
  app-a/   — real app / CMS  (port 9998)
  app-b/   — consent proxy   (port 9999)
```

---

## Prerequisites

- FusionAuth running on `http://localhost:9011` (via `docker-compose` in the
  repo root — run `docker-compose up` from the project root)
- Node 18+ with npm

The kickstart file (`kickstart/kickstart.json`) has been updated to register
both redirect URIs on the shared FusionAuth application:

```
http://localhost:9998/stuff   ← App A (Leg 2 callback)
http://localhost:9999/stuff   ← App B (Leg 1 callback)
```

If FusionAuth was already running before this change, re-run kickstart or
add both URIs manually in the FusionAuth admin UI under
**Applications → ExampleNodeApp → OAuth → Authorized redirect URLs**.

---

## How to run

Install dependencies for each app first:

```bash
cd consent-poc/app-a && npm install
cd consent-poc/app-b && npm install
```

Then start both apps in separate terminals. Start App B first because App A
redirects to it:

```bash
# Terminal 1
cd consent-poc/app-b && npm run dev

# Terminal 2
cd consent-poc/app-a && npm run dev
```

Visit `http://localhost:9998` and click **Login via consent proxy**.

---

## Flow walkthrough

### Actors

| Actor | Port | Role |
|---|---|---|
| Browser | — | End user |
| App A | 9998 | Real application — generates PKCE pair, holds verifier, receives final token |
| App B | 9999 | Consent proxy — authenticates user for consent purposes, re-initiates flow |
| FusionAuth | 9011 | Authorization server |

### Leg 1 — consent auth

1. User visits `http://localhost:9998`.
2. App A's `GET /login` generates a PKCE pair (`code_verifier` + `code_challenge`)
   and a state nonce. The verifier is stored in an httpOnly session cookie and
   **never leaves App A**.
3. App A redirects the browser to `http://localhost:9999/authorize` with the
   full OAuth parameter set:
   `client_id`, `response_type`, `scope`, `state`, `code_challenge`,
   `code_challenge_method`, `redirect_uri=http://localhost:9998/stuff`.
4. App B's `GET /authorize` handler:
   - Captures all incoming params as `originalParams`.
   - Generates its own fresh PKCE pair for Leg 1.
   - Generates a UUID state key.
   - Stores `{ originalParams, leg1Verifier }` in an in-memory state store
     keyed by the UUID.
   - Redirects to FusionAuth `/oauth2/authorize` with App B's own
     `code_challenge`, `redirect_uri=http://localhost:9999/stuff`, and the
     UUID as `state`.
5. User logs in at FusionAuth.
6. FusionAuth redirects to `http://localhost:9999/stuff?code=…&state=<uuid>`.
7. App B's `GET /stuff` handler:
   - Looks up the stored entry by the UUID state key.
   - Exchanges the Leg 1 code with **App B's own verifier** for a consent
     access token.
   - Runs consent logic against the consent token (stub — see source).
   - Deletes the state store entry.

### Leg 2 — real app auth

8. App B redirects the browser back to FusionAuth `/oauth2/authorize` using
   `originalParams`, which includes:
   - `code_challenge` — **App A's original challenge, preserved verbatim**
   - `redirect_uri=http://localhost:9998/stuff`
   - `state` — App A's original nonce
9. FusionAuth already has a session from Leg 1, so the login screen is
   skipped. It issues a new authorization code bound to App A's
   `code_challenge` and redirects to `http://localhost:9998/stuff?code=…`.
10. App A's `GET /stuff` handler:
    - Validates the returned state nonce against its session cookie.
    - Exchanges the code with **App A's original verifier** (retrieved from
      the session cookie). This succeeds because FusionAuth bound the code to
      App A's challenge in step 8.
    - Stores the access token in an httpOnly cookie.
    - Redirects to `/`.

### Why two different `code_challenge` values are correct

The two legs intentionally use different challenges:

- Leg 1: App B's challenge, verified when App B exchanges the Leg 1 code.
- Leg 2: App A's challenge (carried through by App B), verified when App A
  exchanges the Leg 2 code.

Each challenge is paired with the verifier held by the party that exchanges
the corresponding code. App B never sees App A's verifier; App A never sees
App B's verifier.

---

## Key constraint

> **The PKCE verifier lives in App A. App B must carry the original
> `code_challenge` through Leg 2 so FusionAuth can verify it when App A
> exchanges the code.**

This is implemented in `app-b/src/index.ts` in the `GET /stuff` handler:

```typescript
const leg2Params = new URLSearchParams({
  ...
  code_challenge:        originalParams.code_challenge,   // App A's challenge — must be preserved
  code_challenge_method: originalParams.code_challenge_method || 'S256',
  redirect_uri:          originalParams.redirect_uri,     // :9998/stuff
  state:                 originalParams.state,            // App A's nonce — must be preserved
  ...
});
```

---

## Consent logic hook

The consent logic stub is in `app-b/src/index.ts` inside `GET /stuff`,
immediately after the Leg 1 token exchange:

```typescript
// TODO: replace this stub with real consent UI / storage logic.
console.log(`[/stuff] Leg 1 consent token obtained. Running consent logic...`);
```

At this point `consentToken` is a valid FusionAuth access token identifying
the user. Replace the stub with:
- Decoding the JWT to identify the user (`sub`, `email`, etc.)
- Looking up existing consent records
- Rendering a consent UI page and waiting for a form `POST` before
  continuing to the Leg 2 redirect
- Recording the consent decision

---

## FusionAuth application configuration changes

`kickstart/kickstart.json` was updated to add the two new redirect URIs:

```json
"authorizedRedirectURLs": [
  "http://localhost:8080/oauth-redirect",
  "http://localhost:9998/stuff",
  "http://localhost:9999/stuff"
]
```

The original `http://localhost:8080/oauth-redirect` entry is preserved so
the existing `complete-application` quickstart continues to work unchanged.
