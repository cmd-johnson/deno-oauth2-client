import type { OAuth2Client, RequestOptions } from "./oauth2_client.ts";
import { AuthError, AuthServerResponseError } from "./errors.ts";

interface GetUriOptions {
  state?: string;
  scope?: string | string[];
}

interface GetTokenOptions {
  state?: string;
  stateValidator?: (state: string) => boolean;
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

export class CodeFlow {
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
    const scope = this.client.config.defaults?.scope || options.scope;
    if (scope) {
      params.set("scope", Array.isArray(scope) ? scope.join(" ") : scope);
    }
    if (options.state) {
      params.set("state", options.state);
    }
    return new URL(`?${params}`, this.client.config.authorizationEndpointUri);
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

    const state = params.get("state") || undefined;
    const stateValidator = this.client.config.defaults?.stateValidator ||
      options.stateValidator || (options.state && ((s) => s === options.state));
    if (stateValidator && (!state || !stateValidator(state))) {
      throw new TypeError(`Invalid state: ${params.get("state")}`);
    }

    return { code, state };
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

  // TODO: Test getToken options and how/that they override the default options provided by the OAuth2Client
  public async getToken(
    authResponseUri: string | URL,
    options: GetTokenOptions = {},
  ): Promise<Tokens> {
    const url = authResponseUri instanceof URL
      ? authResponseUri
      : new URL(authResponseUri, "http://ignored");

    const validated = this.validateAuthorizationResponse(url, options);

    const request = this.buildAccessTokenRequest(
      validated.code,
      options.requestOptions,
    );

    const accessTokenResponse = await fetch(request);

    if (accessTokenResponse.ok) {
      try {
        const body: AccessTokenResponse = await accessTokenResponse.json();

        if (
          typeof body !== "object" || Array.isArray(body) ||
          typeof body.access_token !== "string" ||
          typeof body.token_type !== "string" ||
          ("refresh_token" in body && typeof body.refresh_token !== "string") ||
          ("expires_in" in body && typeof body.expires_in !== "number") ||
          ("scope" in body && typeof body.scope !== "string")
        ) {
          throw new TypeError("Invalid access token response body");
        }

        return {
          accessToken: body.access_token,
          tokenType: body.token_type,
          refreshToken: body.refresh_token,
          expiresIn: body.expires_in,
          scope: body.scope?.split(" "),
        };
      } catch {
        throw new AuthServerResponseError(accessTokenResponse);
      }
    } else {
      throw await this.getError(accessTokenResponse);
    }
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
      return new AuthServerResponseError(response);
    }
  }
}
