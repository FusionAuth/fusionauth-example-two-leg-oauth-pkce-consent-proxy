import FusionAuthClient from '@fusionauth/typescript-client';
import express from 'express';
import cookieParser from 'cookie-parser';
import pkceChallenge from 'pkce-challenge';
import { GetPublicKeyOrSecret, verify } from 'jsonwebtoken';
import jwksClient, { RsaSigningKey } from 'jwks-rsa';

import * as dotenv from 'dotenv';
dotenv.config();

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

for (const key of ['clientId', 'clientSecret', 'fusionAuthURL', 'consentProxyURL']) {
  if (!process.env[key]) {
    console.error(`Missing ${key} from .env`);
    process.exit(1);
  }
}

const clientId      = process.env.clientId!;
const clientSecret  = process.env.clientSecret!;
const fusionAuthURL = process.env.fusionAuthURL!;
const consentProxyURL = process.env.consentProxyURL!;

// The redirect_uri that FusionAuth will send the browser to in Leg 2.
// Must be registered in the FusionAuth application's authorizedRedirectURLs.
const APP_A_REDIRECT_URI = 'http://localhost:9998/stuff';

// ---------------------------------------------------------------------------
// JWT validation
// ---------------------------------------------------------------------------

const getKey: GetPublicKeyOrSecret = async (header, callback) => {
  const client = jwksClient({ jwksUri: `${fusionAuthURL}/.well-known/jwks.json` });
  const key = await client.getSigningKey(header.kid) as RsaSigningKey;
  callback(null, key?.getPublicKey() || key?.rsaPublicKey);
};

const validateUser = async (userTokenCookie: { access_token: string } | undefined) => {
  if (!userTokenCookie?.access_token) return false;
  try {
    let decoded: unknown;
    await verify(userTokenCookie.access_token, getKey, undefined, (_err, d) => { decoded = d; });
    return decoded;
  } catch {
    return false;
  }
};

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

const SESSION_COOKIE = 'appASession'; // httpOnly — holds state nonce + PKCE verifier
const TOKEN_COOKIE   = 'appAToken';   // httpOnly — holds access token response

const faClient = new FusionAuthClient('noapikeyneeded', fusionAuthURL);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Home: if authenticated show a simple dashboard, otherwise show login link.
app.get('/', async (req, res) => {
  const tokenCookie = req.cookies[TOKEN_COOKIE];
  if (await validateUser(tokenCookie)) {
    res.send(`
      <h1>App A — ChangeBank (:9998)</h1>
      <p>You are logged in. <a href="/logout">Logout</a></p>
      <pre>${JSON.stringify(tokenCookie, null, 2)}</pre>
    `);
  } else {
    res.send(`
      <h1>App A — ChangeBank (:9998)</h1>
      <p><a href="/login">Login via consent proxy</a></p>
    `);
  }
});

// Login: generate PKCE pair + state nonce, stash in session cookie,
// then redirect the browser to App B's /authorize endpoint.
// App A's code_challenge travels with the request; the verifier stays here.
app.get('/login', async (req, res) => {
  const stateValue = crypto.randomUUID();
  const pkcePair   = await pkceChallenge();

  // Persist verifier and state nonce in an httpOnly cookie so /stuff can use them.
  res.cookie(SESSION_COOKIE, {
    stateValue,
    verifier:  pkcePair.code_verifier,
    challenge: pkcePair.code_challenge,
  }, { httpOnly: true });

  // Build the query string that App B's /authorize will receive.
  // This is the full set of OAuth params App A would normally send to FusionAuth,
  // except redirect_uri points to App A (for Leg 2) and we send App A's challenge.
  const params = new URLSearchParams({
    client_id:             clientId,
    response_type:         'code',
    scope:                 'email profile openid',
    state:                 stateValue,
    code_challenge:        pkcePair.code_challenge,
    code_challenge_method: 'S256',
    redirect_uri:          APP_A_REDIRECT_URI,
  });

  res.redirect(302, `${consentProxyURL}/authorize?${params}`);
});

// Leg 2 callback: FusionAuth redirects here after App B re-initiates the authorize
// flow with App A's original PKCE challenge and redirect_uri=:9998/stuff.
// App A exchanges the code using its own verifier (which never left this server).
app.get('/stuff', async (req, res) => {
  const sessionCookie = req.cookies[SESSION_COOKIE];
  const returnedState = `${req.query.state}`;
  const authCode      = `${req.query.code}`;

  // Validate that the state nonce echoed by FusionAuth matches what we stored.
  if (!sessionCookie || returnedState !== sessionCookie.stateValue) {
    console.error('State mismatch in /stuff', { returned: returnedState, stored: sessionCookie?.stateValue });
    return res.redirect(302, '/');
  }

  try {
    // Exchange the auth code for tokens using App A's original verifier.
    // FusionAuth can verify because the code was bound to App A's code_challenge in Leg 2.
    const tokenResponse = (
      await faClient.exchangeOAuthCodeForAccessTokenUsingPKCE(
        authCode,
        clientId,
        clientSecret,
        APP_A_REDIRECT_URI,
        sessionCookie.verifier,
      )
    ).response;

    if (!tokenResponse?.access_token) {
      console.error('No access_token in token response');
      return res.redirect(302, '/');
    }

    res.cookie(TOKEN_COOKIE, tokenResponse, { httpOnly: true });
    res.clearCookie(SESSION_COOKIE);
    res.redirect(302, '/');
  } catch (err: any) {
    console.error('Token exchange failed:', err);
    res.status(err?.statusCode || 500).json({ error: String(err) });
  }
});

// Logout: clear local cookies and bounce through FusionAuth's logout endpoint.
app.get('/logout', (_req, res) => {
  res.clearCookie(SESSION_COOKIE);
  res.clearCookie(TOKEN_COOKIE);
  res.redirect(302, `${fusionAuthURL}/oauth2/logout?client_id=${clientId}`);
});

// FusionAuth post-logout redirect.
app.get('/oauth2/logout', (_req, res) => {
  res.clearCookie(SESSION_COOKIE);
  res.clearCookie(TOKEN_COOKIE);
  res.redirect(302, '/');
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(9998, () => {
  console.log('App A (real app) listening on http://localhost:9998');
});
