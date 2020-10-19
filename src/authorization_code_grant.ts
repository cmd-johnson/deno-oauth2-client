import type { OAuth2Client, RequestOptions } from "./oauth2_client.ts";
import {
  AuthorizationResponseError,
  OAuth2ResponseError,
  TokenResponseError,
} from "./errors.ts";

export interface GetUriOptions {
  /**
   * State parameter to send along with the authorization request.
   *
   * see https://tools.ietf.org/html/rfc6749#section-4.1.1
   */
  state?: string;
  /**
   * Scopes to request with the authorization request.
   *
   * If an array is passed, it is concatinated using spaces as per
   * https://tools.ietf.org/html/rfc6749#section-3.3
   */
  scope?: string | string[];
}

export interface GetTokenOptions {
  /**
   * The state parameter expected to be returned by the authorization response.
   *
   * Usually you'd store the state you sent with the authorization request in the
   * user's session so you can pass it here.
   * If it could be one of many states or you want to run some custom verification
   * logic, use the `stateValidator` parameter instead.
   */
  state?: string;
  /**
   * The state validator used to verify that the received state is valid.
   *
   * The option object's state value is ignored when a stateValidator is passed.
   */
  stateValidator?: (state: string | null) => boolean;
  /** Request options used when making the access token request. */
  requestOptions?: RequestOptions;
}

interface AccessTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

/** Tokens and associated information received from a successful access token request. */
export interface Tokens {
  accessToken: string;
  /**
   * The type of access token received.
   *
   * See https://tools.ietf.org/html/rfc6749#section-7.1
   * Should usually be "Bearer" for most OAuth 2.0 servers, but don't count on it.
   */
  tokenType: string;
  /** The lifetime in seconds of the access token. */
  expiresIn?: number;
  /**
   * The optional refresh token returned by the authorization server.
   *
   * Consult your OAuth 2.0 Provider's documentation to see under
   * which circumstances you'll receive one.
   */
  refreshToken?: string;
  /**
   * The scopes that were granted by the user.
   *
   * May be undefined if the granted scopes match the requested scopes.
   * See https://tools.ietf.org/html/rfc6749#section-5.1
   */
  scope?: string[];
}

/**
 * Implements the OAuth 2.0 authorization code grant.
 *
 * See https://tools.ietf.org/html/rfc6749#section-4.1
 */
export class AuthorizationCodeGrant {
  constructor(
    private readonly client: OAuth2Client,
  ) {}

  /** Builds a URI you can redirect a user to to make the authorization request. */
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

  /**
   * Parses the authorization response request tokens from the authorization server.
   *
   * Usually you'd want to call this method in the function that handles the user's request to your configured redirectUri.
   * @param authResponseUri The complete URI the user got redirected to by the authorization server after making the authorization request.
   *     Must include all received URL parameters.
   */
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

    return this.parseTokenResponse(accessTokenResponse);
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
        throw new AuthorizationResponseError(
          `Redirect path should match configured path, but got: ${url.pathname}`,
        );
      }
    }

    if (!url.search || !url.search.substr(1)) {
      throw new AuthorizationResponseError(
        `URI does not contain callback parameters: ${url}`,
      );
    }

    const params = new URLSearchParams(url.search || "");

    if (params.has("error")) {
      throw OAuth2ResponseError.fromURLSearchParams(params);
    }

    const code = params.get("code") || "";
    if (!code) {
      throw new AuthorizationResponseError(
        "Missing code, unable to request token",
      );
    }

    const state = params.get("state");
    const stateValidator = options.stateValidator ??
      (options.state && ((s) => s === options.state)) ??
      this.client.config.defaults?.stateValidator;

    if (stateValidator && !stateValidator(state)) {
      if (state === null) {
        throw new AuthorizationResponseError("Missing state");
      } else {
        throw new AuthorizationResponseError(
          `Invalid state: ${params.get("state")}`,
        );
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

    const uri = new URL(this.client.config.tokenUri);
    const params = {
      ...(this.client.config.defaults?.requestOptions?.params ?? {}),
      ...(requestOptions.params ?? {}),
    };
    Object.keys(params).forEach((key) => {
      uri.searchParams.append(key, params[key]);
    });

    return new Request(uri.toString(), {
      method: "POST",
      headers: new Headers({
        ...headers,
        ...(this.client.config.defaults?.requestOptions?.headers ?? {}),
        ...(requestOptions.headers ?? {}),
      }),
      body: new URLSearchParams({
        ...requestParams,
        ...(this.client.config.defaults?.requestOptions?.body ?? {}),
        ...(requestOptions.body ?? {}),
      }).toString(),
    });
  }

  private toUrl(url: string | URL): URL {
    return url instanceof URL ? url : new URL(url, "http://ignored");
  }

  private async parseTokenResponse(response: Response): Promise<Tokens> {
    if (!response.ok) {
      throw await this.getTokenResponseError(response);
    }

    let body: AccessTokenResponse;
    try {
      body = await response.json();
    } catch (error) {
      throw new TokenResponseError(
        "Response is not JSON encoded",
        response,
      );
    }

    if (typeof body !== "object" || Array.isArray(body) || body === null) {
      throw new TokenResponseError(
        "body is not a JSON object",
        response,
      );
    }
    if (typeof body.access_token !== "string") {
      throw new TokenResponseError(
        body.access_token
          ? "access_token is not a string"
          : "missing access_token",
        response,
      );
    }
    if (typeof body.token_type !== "string") {
      throw new TokenResponseError(
        body.token_type ? "token_type is not a string" : "missing token_type",
        response,
      );
    }
    if (
      body.refresh_token !== undefined &&
      typeof body.refresh_token !== "string"
    ) {
      throw new TokenResponseError(
        "refresh_token is not a string",
        response,
      );
    }
    if (
      body.expires_in !== undefined && typeof body.expires_in !== "number"
    ) {
      throw new TokenResponseError(
        "expires_in is not a number",
        response,
      );
    }
    if (body.scope !== undefined && typeof body.scope !== "string") {
      throw new TokenResponseError(
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
  private async getTokenResponseError(
    response: Response,
  ): Promise<OAuth2ResponseError | TokenResponseError> {
    try {
      const body = await response.json();
      if (typeof body.error !== "string") {
        throw new TypeError("body should contain an error");
      }
      return new OAuth2ResponseError(body);
    } catch {
      return new TokenResponseError(
        `Server returned ${response.status} and no error description was given`,
        response,
      );
    }
  }
}
