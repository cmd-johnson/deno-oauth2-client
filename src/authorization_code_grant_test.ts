// deno-lint-ignore-file no-explicit-any
import {
  assertEquals,
  assertMatch,
  assertNotMatch,
  assertThrowsAsync,
} from "https://deno.land/std@0.71.0/testing/asserts.ts";
import { spy, stub } from "https://deno.land/x/mock@v0.7.0/mod.ts";

import { OAuth2Client, OAuth2ClientConfig } from "./oauth2_client.ts";
import type { GetTokenOptions, Tokens } from "./authorization_code_grant.ts";
import {
  AuthorizationResponseError,
  OAuth2ResponseError,
  TokenResponseError,
} from "./errors.ts";

//#region AuthorizationCodeGrant.getAuthorizationUri successful paths

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works without additional options", () => {
  assertMatchesUrl(
    getOAuth2Client().code.getAuthorizationUri(),
    "https://auth.server/auth?response_type=code&client_id=clientId",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works when passing a single scope", () => {
  assertMatchesUrl(
    getOAuth2Client().code.getAuthorizationUri({
      scope: "singleScope",
    }),
    "https://auth.server/auth?response_type=code&client_id=clientId&scope=singleScope",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works when passing multiple scopes", () => {
  assertMatchesUrl(
    getOAuth2Client().code.getAuthorizationUri({
      scope: ["multiple", "scopes"],
    }),
    "https://auth.server/auth?response_type=code&client_id=clientId&scope=multiple+scopes",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works when passing a state parameter", () => {
  assertMatchesUrl(
    getOAuth2Client().code.getAuthorizationUri({
      state: "someState",
    }),
    "https://auth.server/auth?response_type=code&client_id=clientId&state=someState",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works with redirectUri", () => {
  assertMatchesUrl(
    getOAuth2Client({
      redirectUri: "https://example.app/redirect",
    }).code.getAuthorizationUri(),
    "https://auth.server/auth?response_type=code&client_id=clientId&redirect_uri=https%3A%2F%2Fexample.app%2Fredirect",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works with redirectUri and a single scope", () => {
  assertMatchesUrl(
    getOAuth2Client({
      redirectUri: "https://example.app/redirect",
    }).code.getAuthorizationUri({
      scope: "singleScope",
    }),
    "https://auth.server/auth?response_type=code&client_id=clientId&redirect_uri=https%3A%2F%2Fexample.app%2Fredirect&scope=singleScope",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri works with redirectUri and multiple scopes", () => {
  assertMatchesUrl(
    getOAuth2Client({
      redirectUri: "https://example.app/redirect",
    }).code.getAuthorizationUri({
      scope: ["multiple", "scopes"],
    }),
    "https://auth.server/auth?response_type=code&client_id=clientId&redirect_uri=https%3A%2F%2Fexample.app%2Fredirect&scope=multiple+scopes",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri uses default scopes if no scope was specified", () => {
  assertMatchesUrl(
    getOAuth2Client({
      defaults: { scope: ["default", "scopes"] },
    }).code.getAuthorizationUri(),
    "https://auth.server/auth?response_type=code&client_id=clientId&scope=default+scopes",
  );
});

Deno.test("AuthorizationCodeGrant.getAuthorizationUri uses specified scopes over default scopes", () => {
  assertMatchesUrl(
    getOAuth2Client({
      defaults: { scope: ["default", "scopes"] },
    }).code.getAuthorizationUri({
      scope: "notDefault",
    }),
    "https://auth.server/auth?response_type=code&client_id=clientId&scope=notDefault",
  );
});

//#endregion

//#region TODO: AuthorizationCodeGrant.getAuthorization error paths

//#endregion

//#region AuthorizationCodeGrant.getToken
//#region AuthorizationCodeGrant.getToken error paths

Deno.test("AuthorizationCodeGrant.getToken throws if the received redirectUri does not match the configured one", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client({
        redirectUri: "https://example.com/redirect",
      }).code.getToken(
        buildAccessTokenCallback("https://example.com/invalid-redirect", {}),
      ),
    AuthorizationResponseError,
    "Redirect path should match configured path",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the callbackUri does not contain any parameters", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback("https://example.com/redirect", {}),
      ),
    AuthorizationResponseError,
    "URI does not contain callback parameters",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the callbackUri contains an error parameter", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          { error: "invalid_request" },
        ),
      ),
    OAuth2ResponseError,
    "invalid_request",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the callbackUri contains the error, error_description and error_uri parameters and adds them to the error object", async () => {
  const error = await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          {
            error: "invalid_request",
            error_description: "Error description",
            error_uri: "error://uri",
          },
        ),
      ),
    OAuth2ResponseError,
    "Error description",
  ) as OAuth2ResponseError;
  assertEquals(error.error, "invalid_request");
  assertEquals(error.errorDescription, "Error description");
  assertEquals(error.errorUri, "error://uri");
});

Deno.test("AuthorizationCodeGrant.getToken throws if the callbackUri doesn't contain a code", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          // state parameter has to be set or we'll get "URI does not contain callback parameters" instead
          { state: "" },
        ),
      ),
    AuthorizationResponseError,
    "Missing code, unable to request token",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if it didn't receive a state and the state validator fails", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          { code: "code" },
        ),
        { stateValidator: () => false },
      ),
    AuthorizationResponseError,
    "Missing state",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if it didn't receive a state but a state was expected", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          { code: "code" },
        ),
        { state: "expected_state" },
      ),
    AuthorizationResponseError,
    "Missing state",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if it received a state that does not match the given state parameter", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          { code: "code", state: "invalid_state" },
        ),
        { state: "expected_state" },
      ),
    AuthorizationResponseError,
    "Invalid state: invalid_state",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the stateValidator returns false", async () => {
  await assertThrowsAsync(
    () =>
      getOAuth2Client().code.getToken(
        buildAccessTokenCallback(
          "https://example.com/redirect",
          { code: "code", state: "invalid_state" },
        ),
        { stateValidator: () => false },
      ),
    AuthorizationResponseError,
    "Invalid state: invalid_state",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server responded with a Content-Type other than application/json", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          status: 200,
          headers: {
            "Content-Type": "x-www-form-urlencoded",
          },
          body: "",
        },
      }),
    TokenResponseError,
    "Invalid token response: Response is not JSON encoded",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server responded with a correctly formatted error", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          status: 401,
          body: { error: "invalid_client" },
        },
      }),
    OAuth2ResponseError,
    "invalid_client",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server responded with a 4xx or 5xx and the body doesn't contain an error parameter", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          status: 401,
          body: {
            no_error_property: true,
          } as any,
        },
      }),
    TokenResponseError,
    "Invalid token response: Server returned 401 and no error description was given",
  );
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          status: 503,
          body: {} as any,
        },
      }),
    TokenResponseError,
    "Invalid token response: Server returned 503 and no error description was given",
  );
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          status: 418,
        },
      }),
    TokenResponseError,
    "Invalid token response: Server returned 418 and no error description was given",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server's response is not a JSON object", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: { body: '""' },
      }),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: { body: "1234" },
      }),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: { body: "null" },
      }),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: { body: `["array values?!!"]` },
      }),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server's response does not contain a token_type", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          body: { access_token: "at" },
        },
      }),
    TokenResponseError,
    "Invalid token response: missing token_type",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server's response does not contain an access_token", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          body: { token_type: "tt" },
        },
      }),
    TokenResponseError,
    "Invalid token response: missing access_token",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server response's access_token is not a string", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          body: {
            access_token: 1234 as any,
            token_type: "tt",
          },
        },
      }),
    TokenResponseError,
    "Invalid token response: access_token is not a string",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server response's refresh_token property is not a string", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          body: {
            access_token: "at",
            token_type: "tt",
            refresh_token: 123 as any,
          },
        },
      }),
    TokenResponseError,
    "Invalid token response: refresh_token is not a string",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server response's expires_in property is not a number", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          body: {
            access_token: "at",
            token_type: "tt",
            expires_in: { this: "is illegal" } as any,
          },
        },
      }),
    TokenResponseError,
    "Invalid token response: expires_in is not a number",
  );
});

Deno.test("AuthorizationCodeGrant.getToken throws if the server response's scope property is not a string", async () => {
  await assertThrowsAsync(
    () =>
      mockAccessTokenResponse_({
        callbackUrl: { code: "authCode" },
        tokenResponse: {
          body: {
            access_token: "at",
            token_type: "tt",
            scope: ["scope1", "scope2"] as any,
          },
        },
      }),
    TokenResponseError,
    "Invalid token response: scope is not a string",
  );
});

//#endregion

//#region AuthorizationCodeGrant.getToken successful paths

Deno.test("AuthorizationCodeGrant.getToken parses the minimal token response correctly", async () => {
  const r = await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode" },
    tokenResponse: {
      body: {
        access_token: "accessToken",
        token_type: "tokenType",
      },
    },
  });
  assertEquals(r.result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
  });
});

Deno.test("AuthorizationCodeGrant.getToken parses the full token response correctly", async () => {
  const r = await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode" },
    tokenResponse: {
      body: {
        access_token: "accessToken",
        token_type: "tokenType",
        refresh_token: "refreshToken",
        expires_in: 3600,
        scope: "multiple scopes",
      },
    },
  });
  assertEquals(r.result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
    refreshToken: "refreshToken",
    expiresIn: 3600,
    scope: ["multiple", "scopes"],
  });
});

Deno.test("AuthorizationCodeGrant.getToken doesn't throw if it didn't receive a state but the state validator returns true", async () => {
  await mockAccessTokenResponse_({
    callbackUrl: { code: "code" },
    callParameters: { stateValidator: () => true },
  });
});

Deno.test("AuthorizationCodeGrant.getToken builds a correct request to the token endpoint by default", async () => {
  const r = await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode" },
  });
  assertEquals(r.request.url, "https://auth.server/token");
  const body = await r.request.formData();
  assertEquals(body.get("grant_type"), "authorization_code");
  assertEquals(body.get("code"), "authCode");
  assertEquals(body.get("redirect_uri"), null);
  assertEquals(body.get("client_id"), "clientId");
  assertEquals(
    r.request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
});

Deno.test("AuthorizationCodeGrant.getToken correctly adds the redirectUri to the token request if specified", async () => {
  const r = await mockAccessTokenResponse_({
    clientConfig: {
      redirectUri: "http://some.redirect/uri",
    },
    callbackUrl: { code: "authCode", base: "http://some.redirect/uri" },
  });
  assertEquals(
    (await r.request.formData()).get("redirect_uri"),
    "http://some.redirect/uri",
  );
});

Deno.test("AuthorizationCodeGrant.getToken sends the clientId as form parameter if no clientSecret is set", async () => {
  const r = await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode" },
  });
  assertEquals(
    (await r.request.formData()).get("client_id"),
    "clientId",
  );
  assertEquals(r.request.headers.get("Authorization"), null);
});

Deno.test("AuthorizationCodeGrant.getToken sends the correct Authorization header if the clientSecret is set", async () => {
  const r = await mockAccessTokenResponse_({
    clientConfig: { clientSecret: "super-secret" },
    callbackUrl: { code: "authCode" },
  });
  assertEquals(
    r.request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c3VwZXItc2VjcmV0",
  );
  assertEquals((await r.request.formData()).get("client_id"), null);
});

Deno.test("AuthorizationCodeGrant.getToken uses the default request options", async () => {
  const r = await mockAccessTokenResponse_({
    clientConfig: {
      defaults: {
        requestOptions: {
          headers: {
            "User-Agent": "Custom User Agent",
            "Content-Type": "application/json",
          },
          params: { "custom-url-param": "value" },
          body: { "custom-body-param": "value" },
        },
      },
    },
    callbackUrl: { code: "authCode" },
  });
  const url = new URL(r.request.url);
  assertEquals(url.searchParams.getAll("custom-url-param"), ["value"]);
  assertEquals(r.request.headers.get("Content-Type"), "application/json");
  assertEquals(r.request.headers.get("User-Agent"), "Custom User Agent");
  assertMatch(await r.request.text(), /.*custom-body-param=value.*/);
});

Deno.test("AuthorizationCodeGrant.getToken uses the passed request options over the default options", async () => {
  const r = await mockAccessTokenResponse_({
    clientConfig: {
      defaults: {
        requestOptions: {
          headers: {
            "User-Agent": "Custom User Agent",
            "Content-Type": "application/json",
          },
          params: { "custom-url-param": "value" },
          body: { "custom-body-param": "value" },
        },
      },
    },
    callParameters: {
      requestOptions: {
        headers: { "Content-Type": "text/plain" },
        params: { "custom-url-param": "other_value" },
        body: { "custom-body-param": "other_value" },
      },
    },
    callbackUrl: { code: "authCode" },
  });
  const url = new URL(r.request.url);
  assertEquals(url.searchParams.getAll("custom-url-param"), ["other_value"]);
  assertEquals(r.request.headers.get("Content-Type"), "text/plain");
  assertEquals(r.request.headers.get("User-Agent"), "Custom User Agent");
  assertMatch(await r.request.text(), /.*custom-body-param=other_value.*/);
  assertNotMatch(await r.request.text(), /.*custom-body-param=value.*/);
});

Deno.test("AuthorizationCodeGrant.getToken uses the default state validator if no state or validator was given", async () => {
  const defaultValidator = spy(() => true);

  await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode", state: "some_state" },
    clientConfig: {
      defaults: { stateValidator: defaultValidator },
    },
  });

  assertEquals(
    defaultValidator.calls,
    [{ args: ["some_state"], returned: true }],
  );
});

Deno.test("AuthorizationCodeGrant.getToken uses the passed state validator over the default validator", async () => {
  const defaultValidator = spy(() => true);
  const validator = spy(() => true);

  await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode", state: "some_state" },
    clientConfig: {
      defaults: { stateValidator: defaultValidator },
    },
    callParameters: { stateValidator: validator },
  });

  assertEquals(defaultValidator.calls, []);
  assertEquals(validator.calls, [{ args: ["some_state"], returned: true }]);
});

Deno.test("AuthorizationCodeGrant.getToken uses the passed state validator over the passed state", async () => {
  const defaultValidator = spy(() => true);
  const validator = spy(() => true);

  await mockAccessTokenResponse_({
    callbackUrl: { code: "authCode", state: "some_state" },
    clientConfig: {
      defaults: { stateValidator: defaultValidator },
    },
    callParameters: { stateValidator: validator, state: "other_state" },
  });

  assertEquals(defaultValidator.calls, []);
  assertEquals(validator.calls, [{ args: ["some_state"], returned: true }]);
});

//#endregion
//#endregion

//#region Utility test functions

function getOAuth2Client(overrideConfig: Partial<OAuth2ClientConfig> = {}) {
  return new OAuth2Client({
    clientId: "clientId",
    authorizationEndpointUri: "https://auth.server/auth",
    tokenUri: "https://auth.server/token",
    ...overrideConfig,
  });
}

function assertMatchesUrl(test: URL, expectedUrl: string | URL): void {
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

interface AccessTokenErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

interface AccessTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
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

async function mockAccessTokenResponse(
  request: () => Promise<Tokens>,
  tokenResponse: MockAccessTokenResponse = {},
): Promise<MockAccessTokenResponseResult> {
  const fetchStub = stub(window, "fetch");
  try {
    const body = typeof tokenResponse.body === "string"
      ? tokenResponse.body
      : JSON.stringify(tokenResponse.body);

    const headers = new Headers(
      tokenResponse.headers || {
        "Content-Type": "application/json",
      },
    );

    const status = tokenResponse.status || 200;

    fetchStub.returns = [
      Promise.resolve(new Response(body, { headers, status })),
    ];

    const result = await request();

    const performedRequest = fetchStub.calls[0].args[0] as Request;

    return { request: performedRequest, result };
  } finally {
    fetchStub.restore();
  }
}

async function mockAccessTokenResponse_(
  options: {
    clientConfig?: Partial<OAuth2ClientConfig>;
    callParameters?: Partial<GetTokenOptions>;
    callbackUrl: (AccessTokenCallbackSuccess | AccessTokenCallbackError) & {
      base?: string;
    };
    tokenResponse?: MockAccessTokenResponse;
  },
): Promise<MockAccessTokenResponseResult> {
  const callbackUrl = buildAccessTokenCallback(
    options.callbackUrl.base ?? "https://example.com",
    options.callbackUrl,
  );

  const fetchStub = stub(window, "fetch");
  try {
    const tokenResponse = options.tokenResponse ??
      { body: { access_token: "at", token_type: "tt" } };

    const body = typeof tokenResponse.body === "string"
      ? tokenResponse.body
      : JSON.stringify(tokenResponse.body);

    const headers = new Headers(
      tokenResponse.headers ?? { "Content-Type": "application/json" },
    );

    const status = tokenResponse.status ?? 200;

    fetchStub.returns = [
      Promise.resolve(new Response(body, { headers, status })),
    ];

    const result = await getOAuth2Client(options.clientConfig).code.getToken(
      callbackUrl,
      options.callParameters,
    );

    const request = fetchStub.calls[0].args[0] as Request;

    return { request, result };
  } finally {
    fetchStub.restore();
  }
}

interface AccessTokenCallbackSuccess {
  code?: string;
  state?: string;
}
interface AccessTokenCallbackError {
  error?: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

function buildAccessTokenCallback(
  base: string,
  options: AccessTokenCallbackSuccess | AccessTokenCallbackError,
): URL {
  return new URL(
    `?${new URLSearchParams(options as Record<string, string>)}`,
    base,
  );
}

//#endregion
