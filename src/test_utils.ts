// deno-lint-ignore-file camelcase

import { assertEquals } from "@std/assert/equals";
import { returnsNext, stub } from "@std/testing/mock";
import { OAuth2Client, OAuth2ClientConfig } from "./oauth2_client.ts";
import { Tokens } from "./types.ts";

export function getOAuth2Client(
  overrideConfig: Partial<OAuth2ClientConfig> = {},
) {
  return new OAuth2Client({
    clientId: "clientId",
    authorizationEndpointUri: "https://auth.server/auth",
    tokenUri: "https://auth.server/token",
    ...overrideConfig,
  });
}

export interface AccessTokenCallbackSuccess {
  code?: string;
  state?: string;
}

export interface AccessTokenCallbackError {
  error?: string;
  "error_description"?: string;
  "error_uri"?: string;
  state?: string;
}

interface AccessTokenErrorResponse {
  error: string;
  "error_description"?: string;
  "error_uri"?: string;
}

interface AccessTokenResponse {
  "access_token": string;
  "token_type": string;
  "expires_in"?: number;
  "refresh_token"?: string;
  scope?: string;
}

interface MockAccessTokenResponse {
  status?: number;
  headers?: { [key: string]: string };
  body?: Partial<AccessTokenResponse | AccessTokenErrorResponse> | string;
}

interface MockAccessTokenResponseResult {
  request: Request;
  result: Tokens;
}

export async function mockATResponse(
  request: () => Promise<Tokens>,
  response?: MockAccessTokenResponse,
): Promise<MockAccessTokenResponseResult> {
  const body = typeof response?.body === "string"
    ? response?.body
    : JSON.stringify(
      response?.body ?? { access_token: "at", token_type: "tt" },
    );

  const headers = new Headers(
    response?.headers ?? { "Content-Type": "application/json" },
  );

  const status = response?.status ?? 200;

  const fetchStub = stub(
    globalThis,
    "fetch",
    returnsNext([
      Promise.resolve(new Response(body, { headers, status })),
    ]),
  );
  try {
    const result = await request();
    const req = fetchStub.calls[0].args[0] as Request;

    return { request: req, result };
  } finally {
    fetchStub.restore();
  }
}

interface AccessTokenCallbackOptions {
  baseUrl?: string;
  params?: AccessTokenCallbackSuccess | AccessTokenCallbackError;
}

export function buildAccessTokenCallback(
  options: AccessTokenCallbackOptions = {},
) {
  const base = options.baseUrl ?? "https://example.app/callback";

  const params = new URLSearchParams(
    (options.params ?? {}) as Record<string, string>,
  );

  return new URL(`?${params}`, base);
}

export interface ImplicitAccessTokenCallbackSuccess {
  access_token?: string;
  token_type?: string;
  expires_in?: string;
  scope?: string;
  state?: string;
}

interface ImplicitAccessTokenCallbackOptions {
  baseUrl?: string;
  params?: ImplicitAccessTokenCallbackSuccess | AccessTokenCallbackError;
}

export function buildImplicitAccessTokenCallback(
  options: ImplicitAccessTokenCallbackOptions = {},
) {
  const base = options.baseUrl ?? "https://example.app/callback";

  const params = new URLSearchParams(
    (options.params ?? {}) as Record<string, string>,
  );

  const url = new URL(base);
  url.hash = params.toString();
  return url;
}

export function assertMatchesUrl(test: URL, expectedUrl: string | URL): void {
  const expected = expectedUrl instanceof URL
    ? expectedUrl
    : new URL(expectedUrl);

  assertEquals(test.origin, expected.origin);
  assertEquals(test.pathname, expected.pathname);
  assertEquals(test.hash, expected.hash);

  const testParams = [...test.searchParams.entries()].sort(([a], [b]) =>
    a > b ? 1 : a < b ? -1 : 0
  );
  const expectedParams = [...expected.searchParams.entries()].sort(([a], [b]) =>
    a > b ? 1 : a < b ? -1 : 0
  );
  assertEquals(testParams, expectedParams);
}
