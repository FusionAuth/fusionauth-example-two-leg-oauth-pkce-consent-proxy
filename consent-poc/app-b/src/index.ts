import FusionAuthClient from '@fusionauth/typescript-client';
import express from 'express';
import pkceChallenge from 'pkce-challenge';

import * as dotenv from 'dotenv';
dotenv.config();

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

for (const key of ['clientId', 'clientSecret', 'fusionAuthURL']) {
  if (!process.env[key]) {
    console.error(`Missing ${key} from .env`);
    process.exit(1);
  }
}

const clientId      = process.env.clientId!;
const clientSecret  = process.env.clientSecret!;
const fusionAuthURL = process.env.fusionAuthURL!;

// The redirect_uri registered for Leg 1 — FusionAuth returns the browser here
// after the user authenticates during the consent leg.
const APP_B_REDIRECT_URI = 'http://localhost:9999/stuff';

// ---------------------------------------------------------------------------
// Server-side state store
//
// Maps App B's generated state key → {
//   originalParams: all query params received from App A's /login redirect,
//   leg1Verifier:   the PKCE verifier App B generated for Leg 1.
// }
//
// In production this should be a persistent store (Redis, DB, etc.).
// ---------------------------------------------------------------------------

interface StoredState {
  originalParams: Record<string, string>;
  leg1Verifier: string;
}

const stateStore = new Map<string, StoredState>();

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------

const app = express();

const faClient = new FusionAuthClient('noapikeyneeded', fusionAuthURL);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Leg 1 — Step 1: App A sends the browser here with its full OAuth params.
// App B stashes them, generates its own PKCE pair, and redirects to FusionAuth.
app.get('/authorize', async (req, res) => {
  // Capture everything App A sent — we need to replay most of it in Leg 2.
  // Critically this includes: client_id, response_type, scope, state (App A's nonce),
  // code_challenge, code_challenge_method, and redirect_uri (App A's :9998/stuff).
  const originalParams: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.query)) {
    if (typeof v === 'string') originalParams[k] = v;
  }

  // Validate the minimum required params are present.
  if (!originalParams.code_challenge || !originalParams.redirect_uri) {
    console.error('/authorize: missing required params from App A', originalParams);
    return res.status(400).send('Bad request: missing code_challenge or redirect_uri');
  }

  // Generate a fresh PKCE pair for Leg 1.
  // App B uses this to exchange the Leg 1 code; App A's verifier is never sent here.
  const leg1Pkce = await pkceChallenge();

  // Generate a state key for this request and store everything.
  const leg1State = crypto.randomUUID();
  stateStore.set(leg1State, {
    originalParams,
    leg1Verifier: leg1Pkce.code_verifier,
  });

  console.log(`[authorize] stored state ${leg1State} for App A state=${originalParams.state}`);

  // Redirect to FusionAuth for Leg 1 using App B's own PKCE and redirect_uri.
  const params = new URLSearchParams({
    client_id:             clientId,
    response_type:         originalParams.response_type || 'code',
    scope:                 originalParams.scope || 'email profile openid',
    state:                 leg1State,
    code_challenge:        leg1Pkce.code_challenge,
    code_challenge_method: 'S256',
    redirect_uri:          APP_B_REDIRECT_URI,
  });

  res.redirect(302, `${fusionAuthURL}/oauth2/authorize?${params}`);
});

// Leg 1 — Step 2: FusionAuth returns here after the user authenticates.
// App B exchanges the Leg 1 code, runs consent logic, then re-initiates the
// authorize flow with App A's original params (including App A's code_challenge)
// so FusionAuth ultimately sends a code to App A's redirect_uri (:9998/stuff).
app.get('/stuff', async (req, res) => {
  const leg1State = `${req.query.state}`;
  const leg1Code  = `${req.query.code}`;

  const stored = stateStore.get(leg1State);
  if (!stored) {
    console.error(`/stuff: unknown state key ${leg1State}`);
    return res.status(400).send('Bad request: unknown or expired state');
  }

  // Remove immediately to prevent replay.
  stateStore.delete(leg1State);

  const { originalParams, leg1Verifier } = stored;

  // -------------------------------------------------------------------------
  // Leg 1 token exchange: get App B's consent access token.
  // This token is for App B's own use — running consent checks, recording
  // consent decisions, etc. It is NOT forwarded to App A.
  // -------------------------------------------------------------------------
  let consentToken: string;
  try {
    const tokenResponse = (
      await faClient.exchangeOAuthCodeForAccessTokenUsingPKCE(
        leg1Code,
        clientId,
        clientSecret,
        APP_B_REDIRECT_URI,
        leg1Verifier,
      )
    ).response;

    if (!tokenResponse?.access_token) {
      throw new Error('No access_token in Leg 1 token response');
    }
    consentToken = tokenResponse.access_token;
  } catch (err: any) {
    console.error('Leg 1 token exchange failed:', err);
    return res.status(500).json({ error: 'Leg 1 token exchange failed', detail: String(err) });
  }

  // -------------------------------------------------------------------------
  // Consent logic goes here.
  //
  // With consentToken you can:
  //   - Decode the JWT to identify the user
  //   - Look up existing consent records
  //   - Show a consent UI page (and wait for a POST before proceeding)
  //   - Record the consent decision
  //
  // For this POC we log the token and proceed immediately.
  // -------------------------------------------------------------------------
  console.log(`[/stuff] Leg 1 consent token obtained. Running consent logic...`);
  console.log(`[/stuff] User identified from consent token (decode JWT to get sub/email).`);
  // TODO: replace this stub with real consent UI / storage logic.

  // -------------------------------------------------------------------------
  // Leg 2: re-initiate the authorize flow with App A's original params.
  //
  // Key points:
  //   - redirect_uri is App A's :9998/stuff (from originalParams)
  //   - code_challenge is App A's original challenge (from originalParams)
  //   - state is App A's original nonce (from originalParams)
  //   - FusionAuth already has a session so the user won't see the login screen
  //
  // FusionAuth will issue a new code bound to App A's code_challenge,
  // and send it to :9998/stuff. App A then exchanges it with its verifier.
  // -------------------------------------------------------------------------
  const leg2Params = new URLSearchParams({
    client_id:             originalParams.client_id   || clientId,
    response_type:         originalParams.response_type || 'code',
    scope:                 originalParams.scope        || 'email profile openid',
    state:                 originalParams.state,            // App A's nonce — must be preserved
    code_challenge:        originalParams.code_challenge,   // App A's challenge — must be preserved
    code_challenge_method: originalParams.code_challenge_method || 'S256',
    redirect_uri:          originalParams.redirect_uri,     // :9998/stuff
  });

  console.log(`[/stuff] Initiating Leg 2 → FusionAuth with redirect_uri=${originalParams.redirect_uri}`);
  res.redirect(302, `${fusionAuthURL}/oauth2/authorize?${leg2Params}`);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(9999, () => {
  console.log('App B (consent proxy) listening on http://localhost:9999');
});
