import { serve } from "https://deno.land/std@0.161.0/http/server.ts";
import {
  Cookie,
  deleteCookie,
  getCookies,
  setCookie,
} from "https://deno.land/std@0.161.0/http/cookie.ts";
import * as jose from "https://deno.land/x/jose@v4.14.4/index.ts";
import { OIDCClient } from "../../src/oidc/oidc_client.ts";

const jwks = jose.createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);

const oidcClient = new OIDCClient({
  clientId: Deno.env.get("CLIENT_ID")!,
  clientSecret: Deno.env.get("CLIENT_SECRET")!,
  authorizationEndpointUri: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUri: "https://oauth2.googleapis.com/token",
  redirectUri: "http://localhost:8000/oauth2/callback",
  userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
  defaults: {
    scope: ["openid", "email", "profile"],
  },
  verifyJwt: (jwt) => jose.jwtVerify(jwt, jwks),
});

/** This is where we'll store our state and PKCE codeVerifiers */
const loginStates = new Map<string, { state: string; codeVerifier: string }>();
/** The name we'll use for the session cookie */
const cookieName = "session";

/** Handles incoming HTTP requests */
function handler(req: Request): Promise<Response> | Response {
  const url = new URL(req.url);
  const path = url.pathname;

  switch (path) {
    case "/login":
      return redirectToAuthEndpoint();
    case "/oauth2/callback":
      return handleCallback(req);
    default:
      return new Response("Not Found", { status: 404 });
  }
}

async function redirectToAuthEndpoint(): Promise<Response> {
  // Generate a random state
  const state = crypto.randomUUID();

  const { uri, codeVerifier } = await oidcClient.code.getAuthorizationUri({
    state,
  });

  // Associate the state and PKCE codeVerifier with a session cookie
  const sessionId = crypto.randomUUID();
  loginStates.set(sessionId, { state, codeVerifier });
  const sessionCookie: Cookie = {
    name: cookieName,
    value: sessionId,
    httpOnly: true,
    sameSite: "Lax",
  };
  const headers = new Headers({ Location: uri.toString() });
  setCookie(headers, sessionCookie);

  // Redirect to the authorization endpoint
  return new Response(null, { status: 302, headers });
}

async function handleCallback(req: Request): Promise<Response> {
  // Load the state and PKCE codeVerifier associated with the session
  const sessionCookie = getCookies(req.headers)[cookieName];
  const loginState = sessionCookie && loginStates.get(sessionCookie);
  if (!loginState) {
    throw new Error("invalid session");
  }
  loginStates.delete(sessionCookie);

  // Exchange the authorization code for an access token
  const tokens = await oidcClient.code.getToken(req.url, loginState);

  const userInfo = await oidcClient.getUserInfo(
    tokens.accessToken,
    tokens.idToken,
  );

  // Clear the session cookie since we don't need it anymore
  const headers = new Headers();
  deleteCookie(headers, cookieName);
  return new Response(
    `<!DOCTYPE html><html><body><h1>Hello, ${userInfo.name}!</h1></body></html>`,
    {
      headers: {
        "content-type": "text/html",
      },
    },
  );
}

// Start the app
serve(handler, { port: 8000 });
