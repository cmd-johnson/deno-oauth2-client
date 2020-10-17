import type { OAuth2Client, RequestOptions } from "./oauth2_client.ts";
import { AuthError, AuthServerResponseError } from "./errors.ts";

interface GetUriOptions {
  state?: string;
  scope?: string | string[];
}

export interface GetTokenOptions {
  state?: string;
  stateValidator?: (state: string | null) => boolean;
  requestOptions?: RequestOptions;
}

export interface AccessTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface Tokens {
  accessToken: string;
  tokenType: string;
  expiresIn?: number;
  refreshToken?: string;
  scope?: string[];
}

export class AuthorizationCodeGrant {
  constructor(
    private readonly client: OAuth2Client,
  ) {}

  public getAuthorizationUri(options: GetUriOptions = {}): URL {
    const params = new URLSearchParams();
    params.set("response_type", "code");
    params.set("client_id", this.client.config.clientId);
    if (typeof this.client.config.redirectUri === "string") {
      params.set("redirect_uri", this.client.config.redirectUri);
    }
    const scope = options.scope ?? this.client.config.defaults?.scope;
    if (scope) {
      params.set("scope", Array.isArray(scope) ? scope.join(" ") : scope);
    }
    if (options.state) {
      params.set("state", options.state);
    }
    return new URL(`?${params}`, this.client.config.authorizationEndpointUri);
  }

  public async getToken(
    authResponseUri: string | URL,
    options: GetTokenOptions = {},
  ): Promise<Tokens> {
    const validated = this.validateAuthorizationResponse(
      this.toUrl(authResponseUri),
      options,
    );

    const request = this.buildAccessTokenRequest(
      validated.code,
      options.requestOptions,
    );

    const accessTokenResponse = await fetch(request);

    return this.validateTokenResponse(accessTokenResponse);
  }

  private validateAuthorizationResponse(
    url: URL,
    options: GetTokenOptions,
  ): { code: string; state?: string } {
    if (typeof this.client.config.redirectUri === "string") {
      const expectedUrl = new URL(this.client.config.redirectUri);

      if (
        typeof url.pathname === "string" &&
        url.pathname !== expectedUrl.pathname
      ) {
        throw new TypeError(
          `Redirect path should match configured path, but got: ${url.pathname}`,
        );
      }
    }

    if (!url.search || !url.search.substr(1)) {
      throw new TypeError(`URI does not contain callback parameters: ${url}`);
    }

    const params = new URLSearchParams(url.search || "");

    if (params.has("error")) {
      throw AuthError.fromURLSearchParams(params);
    }

    const code = params.get("code") || "";
    if (!code) {
      throw new TypeError("Missing code, unable to request token");
    }

    const state = params.get("state");
    const stateValidator = options.stateValidator ??
      (options.state && ((s) => s === options.state)) ??
      this.client.config.defaults?.stateValidator;

    if (stateValidator && !stateValidator(state)) {
      if (state === null) {
        throw new TypeError("Missing state");
      } else {
        throw new TypeError(`Invalid state: ${params.get("state")}`);
      }
    }

    if (state) {
      return { code, state };
    }
    return { code };
  }

  private buildAccessTokenRequest(
    code: string,
    requestOptions: RequestOptions = {},
  ): Request {
    const requestParams: { [key: string]: string } = {
      grant_type: "authorization_code",
      code,
    };
    const headers: { [k: string]: string } = {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    };

    if (typeof this.client.config.redirectUri === "string") {
      requestParams.redirect_uri = this.client.config.redirectUri;
    }

    if (typeof this.client.config.clientSecret === "string") {
      // We have a client secret, authenticate using HTTP Basic Auth as described in RFC6749 Section 2.3.1.
      const { clientId, clientSecret } = this.client.config;
      headers.Authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    } else {
      // This appears to be a public client, include the client ID along in the body
      requestParams.client_id = this.client.config.clientId;
    }

    return new Request(this.client.config.accessTokenUri, {
      method: "POST",
      headers: new Headers({
        ...headers,
        ...(this.client.config.defaults?.requestOptions?.headers || {}),
        ...(requestOptions.headers ?? {}),
      }),
      body: new URLSearchParams({
        ...requestParams,
        ...(this.client.config.defaults?.requestOptions?.params || {}),
        ...(requestOptions.params ?? {}),
      }).toString(),
    });
  }

  private toUrl(url: string | URL): URL {
    return url instanceof URL ? url : new URL(url, "http://ignored");
  }

  private async validateTokenResponse(response: Response): Promise<Tokens> {
    if (!response.ok) {
      throw await this.getError(response);
    }

    let body: AccessTokenResponse;
    try {
      body = await response.json();
    } catch (error) {
      throw new AuthServerResponseError(
        "Response is not JSON encoded",
        response,
      );
    }

    if (typeof body !== "object" || Array.isArray(body) || body === null) {
      throw new AuthServerResponseError(
        "body is not a JSON object",
        response,
      );
    }
    if (typeof body.access_token !== "string") {
      throw new AuthServerResponseError(
        body.access_token
          ? "access_token is not a string"
          : "missing access_token",
        response,
      );
    }
    if (typeof body.token_type !== "string") {
      throw new AuthServerResponseError(
        body.token_type ? "token_type is not a string" : "missing token_type",
        response,
      );
    }
    if (
      body.refresh_token !== undefined &&
      typeof body.refresh_token !== "string"
    ) {
      throw new AuthServerResponseError(
        "refresh_token is not a string",
        response,
      );
    }
    if (
      body.expires_in !== undefined && typeof body.expires_in !== "number"
    ) {
      throw new AuthServerResponseError(
        "expires_in is not a number",
        response,
      );
    }
    if (body.scope !== undefined && typeof body.scope !== "string") {
      throw new AuthServerResponseError(
        "scope is not a string",
        response,
      );
    }

    const tokens: Tokens = {
      accessToken: body.access_token,
      tokenType: body.token_type,
    };

    if (body.refresh_token) {
      tokens.refreshToken = body.refresh_token;
    }
    if (body.expires_in) {
      tokens.expiresIn = body.expires_in;
    }
    if (body.scope) {
      tokens.scope = body.scope.split(" ");
    }

    return tokens;
  }

  /** Tries to build an AuthError from the response and defaults to AuthServerResponseError if that fails. */
  private async getError(
    response: Response,
  ): Promise<AuthError | AuthServerResponseError> {
    try {
      const body = await response.json();
      if (typeof body.error !== "string") {
        throw new TypeError("body should contain an error");
      }
      return new AuthError(body);
    } catch {
      return new AuthServerResponseError(
        `Server returned ${response.status} and no error description was given`,
        response,
      );
    }
  }
}
