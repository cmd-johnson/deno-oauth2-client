// deno-lint-ignore-file no-explicit-any
import {
  assertEquals,
  assertMatch,
  assertNotMatch,
  assertRejects,
} from "https://deno.land/std@0.161.0/testing/asserts.ts";

import { OAuth2ResponseError, TokenResponseError } from "./errors.ts";
import { getOAuth2Client, mockATResponse } from "./test_utils.ts";

//#region ResourceOwnerPasswordCredentialsGrant.getToken error paths

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server responded with a Content-Type other than application/json", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { body: "not json" },
      ),
    TokenResponseError,
    "Invalid token response: Response is not JSON encoded",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server responded with a correctly formatted error", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { status: 401, body: { error: "invalid_client" } },
      ),
    OAuth2ResponseError,
    "invalid_client",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server responded with a 4xx or 5xx and the body doesn't contain an error parameter", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { status: 401, body: {} },
      ),
    TokenResponseError,
    "Invalid token response: Server returned 401 and no error description was given",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server's response is not a JSON object", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { body: '""' },
      ),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { body: '["array values?!!"]' },
      ),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server's response does not contain a token_type", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { body: { access_token: "at" } },
      ),
    TokenResponseError,
    "Invalid token response: missing token_type",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server response's token_type is not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        {
          body: {
            access_token: "at",
            token_type: 1337 as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: token_type is not a string",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server's response does not contain an access_token", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        { body: { token_type: "tt" } },
      ),
    TokenResponseError,
    "Invalid token response: missing access_token",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server response's access_token is not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        {
          body: {
            access_token: 1234 as any,
            token_type: "tt",
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: access_token is not a string",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server response's refresh_token property is present but not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            refresh_token: 123 as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: refresh_token is not a string",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server response's id_token property is present but not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            id_token: 123 as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: id_token is not a string",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server response's expires_in property is present but not a number", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            expires_in: { this: "is illegal" } as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: expires_in is not a number",
  );
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken throws if the server response's scope property is present but not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            scope: ["scope1", "scope2"] as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: scope is not a string",
  );
});

//#endregion

//#region ResourceOwnerPasswordCredentialsGrant.getToken successful paths

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken builds a correct request to the token endpoint when not setting scopes", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client().ropc.getToken({
        username: "un",
        password: "pw",
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "password");
  assertEquals(body.get("username"), "un");
  assertEquals(body.get("password"), "pw");
  assertEquals(body.get("client_id"), "clientId");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals([...body.keys()].length, 4);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken builds a correct request to the token endpoint when setting a single scope", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client().ropc.getToken({
        username: "un",
        password: "pw",
        scope: "singleScope",
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "password");
  assertEquals(body.get("username"), "un");
  assertEquals(body.get("password"), "pw");
  assertEquals(body.get("client_id"), "clientId");
  assertEquals(body.get("scope"), "singleScope");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals([...body.keys()].length, 5);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken builds a correct request to the token endpoint when setting multiple scopes", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client().ropc.getToken({
        username: "un",
        password: "pw",
        scope: ["multiple", "scopes"],
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "password");
  assertEquals(body.get("username"), "un");
  assertEquals(body.get("password"), "pw");
  assertEquals(body.get("client_id"), "clientId");
  assertEquals(body.get("scope"), "multiple scopes");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals([...body.keys()].length, 5);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken uses default scopes if no scope was specified", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        defaults: { scope: ["default", "scopes"] },
      }).ropc.getToken({
        username: "un",
        password: "pw",
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "password");
  assertEquals(body.get("username"), "un");
  assertEquals(body.get("password"), "pw");
  assertEquals(body.get("client_id"), "clientId");
  assertEquals(body.get("scope"), "default scopes");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals([...body.keys()].length, 5);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken uses specified scopes over default scopes", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        defaults: { scope: ["default", "scopes"] },
      }).ropc.getToken({
        username: "un",
        password: "pw",
        scope: "notDefault",
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "password");
  assertEquals(body.get("username"), "un");
  assertEquals(body.get("password"), "pw");
  assertEquals(body.get("client_id"), "clientId");
  assertEquals(body.get("scope"), "notDefault");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals([...body.keys()].length, 5);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken parses the minimal token response correctly", async () => {
  const { result } = await mockATResponse(
    () => getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
    {
      body: {
        access_token: "accessToken",
        token_type: "tokenType",
      },
    },
  );
  assertEquals(result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
  });
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken parses the full token response correctly", async () => {
  const { result } = await mockATResponse(
    () => getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
    {
      body: {
        access_token: "accessToken",
        token_type: "tokenType",
        refresh_token: "refreshToken",
        expires_in: 3600,
        scope: "multiple scopes",
      },
    },
  );
  assertEquals(result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
    refreshToken: "refreshToken",
    expiresIn: 3600,
    scope: ["multiple", "scopes"],
  });
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken sends the clientId as form parameter if no clientSecret is set", async () => {
  const { request } = await mockATResponse(
    () => getOAuth2Client().ropc.getToken({ username: "un", password: "pw" }),
  );
  assertEquals(
    (await request.formData()).get("client_id"),
    "clientId",
  );
  assertEquals(request.headers.get("Authorization"), null);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken sends the correct Authorization header if the clientSecret is set", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({ clientSecret: "super-secret" }).ropc.getToken({
        username: "un",
        password: "pw",
      }),
  );
  assertEquals(
    request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c3VwZXItc2VjcmV0",
  );
  assertEquals((await request.formData()).get("client_id"), null);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken uses the default request options", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        defaults: {
          requestOptions: {
            headers: {
              "User-Agent": "Custom User Agent",
              "Content-Type": "application/json",
            },
            urlParams: { "custom-url-param": "value" },
            body: { "custom-body-param": "value" },
          },
        },
      }).ropc.getToken({ username: "un", password: "pw" }),
  );
  const url = new URL(request.url);
  assertEquals(url.searchParams.getAll("custom-url-param"), ["value"]);
  assertEquals(request.headers.get("Content-Type"), "application/json");
  assertEquals(request.headers.get("User-Agent"), "Custom User Agent");
  assertMatch(await request.text(), /.*custom-body-param=value.*/);
});

Deno.test("ResourceOwnerPasswordCredentialsGrant.getToken uses the passed request options over the default options", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        defaults: {
          requestOptions: {
            headers: {
              "User-Agent": "Custom User Agent",
              "Content-Type": "application/json",
            },
            urlParams: { "custom-url-param": "value" },
            body: { "custom-body-param": "value" },
          },
        },
      }).ropc.getToken(
        {
          username: "un",
          password: "pw",
          requestOptions: {
            headers: { "Content-Type": "text/plain" },
            urlParams: { "custom-url-param": "other_value" },
            body: { "custom-body-param": "other_value" },
          },
        },
      ),
  );
  const url = new URL(request.url);
  assertEquals(url.searchParams.getAll("custom-url-param"), ["other_value"]);
  assertEquals(request.headers.get("Content-Type"), "text/plain");
  assertEquals(request.headers.get("User-Agent"), "Custom User Agent");

  const requestText = await request.text();
  assertMatch(requestText, /.*custom-body-param=other_value.*/);
  assertNotMatch(requestText, /.*custom-body-param=value.*/);
});

//#endregion
