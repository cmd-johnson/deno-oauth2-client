import type { OAuth2Client } from "./oauth2_client.ts";
import { AuthorizationResponseError, OAuth2ResponseError } from "./errors.ts";
import { RequestOptions, TokenResponse, Tokens } from "./types.ts";
import { OAuth2GrantBase } from "./grant_base.ts";

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

export interface StateLookupSuccess<T> {
  valid: true;
  data: T;
}
export interface StateLookupFailure {
  valid: false;
}
export type StateLookupResult<T> = StateLookupSuccess<T> | StateLookupFailure;

export interface GetTokenOptions<T> {
  /**
   * The state parameter expected to be returned by the authorization response.
   *
   * Usually you'd store the state you sent with the authorization request in the
   * user's session so you can pass it here.
   * If it could be one of many states or you want to run some custom verification
   * logic, use the `stateValidator` parameter instead.
   */
  expectedState?: string;
  /**
   * The state validator used to verify that the received state is valid.
   *
   * The option object's state value is ignored when a stateValidator is passed.
   */
  // stateValidator?: (state: string | null) => boolean;
  stateLookup?: (state: string | null) => Promise<StateLookupResult<T>> | StateLookupResult<T>;
  /** Request options used when making the access token request. */
  requestOptions?: RequestOptions;
}

/**
 * Implements the OAuth 2.0 authorization code grant.
 *
 * See https://tools.ietf.org/html/rfc6749#section-4.1
 */
export class AuthorizationCodeGrant extends OAuth2GrantBase {
  constructor(client: OAuth2Client) {
    super(client);
  }

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
  public async getToken<T = never>(
    authResponseUri: string | URL,
    options: GetTokenOptions<T> = {},
  ): Promise<TokenResponse<T>> {
    const validated = await this.validateAuthorizationResponse(
      this.toUrl(authResponseUri),
      options,
    );

    const request = this.buildAccessTokenRequest(
      validated.code,
      options.requestOptions,
    );

    const accessTokenResponse = await fetch(request);

    return {
      tokens: await this.parseTokenResponse(accessTokenResponse),
      stateLookupData: validated.stateLookupData,
    };
  }

  private async validateAuthorizationResponse<T>(
    url: URL,
    options: GetTokenOptions<T>,
  ): Promise<{ code: string; state?: string, stateLookupData?: T }> {
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

    if (params.get("error") !== null) {
      throw OAuth2ResponseError.fromURLSearchParams(params);
    }

    const code = params.get("code") || "";
    if (!code) {
      throw new AuthorizationResponseError(
        "Missing code, unable to request token",
      );
    }
    
    const state = params.get("state");
    if (options.stateLookup) {
      const result = await options.stateLookup(state);
      if (!result.valid) {
        throw new AuthorizationResponseError(
          `Invalid state: ${params.get("state")}`,
        );
      }
      return {
        code,
        state: state ?? undefined,
        stateLookupData: result.data,
      };
    } else if (options.expectedState) {
      if (state !== options.expectedState) {
        if (state === null) {
          throw new AuthorizationResponseError("Missing state");
        } else {
          throw new AuthorizationResponseError(
            `Invalid state: ${params.get("state")}`,
          );
        }
      }
    }
    return {
      code,
      state: state ?? undefined,
    };
  }

  private buildAccessTokenRequest(
    code: string,
    requestOptions: RequestOptions = {},
  ): Request {
    const body: Record<string, string> = {
      grant_type: "authorization_code",
      code,
    };
    const headers: Record<string, string> = {
      "Accept": "application/json",
    };

    if (typeof this.client.config.redirectUri === "string") {
      body.redirect_uri = this.client.config.redirectUri;
    }

    if (typeof this.client.config.clientSecret === "string") {
      // We have a client secret, authenticate using HTTP Basic Auth as described in RFC6749 Section 2.3.1.
      const { clientId, clientSecret } = this.client.config;
      headers.Authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    } else {
      // This appears to be a public client, include the client ID along in the body
      body.client_id = this.client.config.clientId;
    }

    return this.buildRequest(this.client.config.tokenEndpointUri, {
      method: "POST",
      headers,
      body,
    }, requestOptions);
  }
}
