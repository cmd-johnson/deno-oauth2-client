import { OAuth2GrantBase } from "./grant_base.ts";
import type { OAuth2ClientConfig } from "./oauth2_client.ts";
import type { RequestOptions, Tokens } from "./types.ts";

export interface ResourceOwnerPasswordCredentialsTokenOptions {
  /** The resource owner username */
  username: string;
  /** The resource owner password */
  password: string;
  /**
   * Scopes to request with the authorization request.
   *
   * If an array is passed, it is concatenated using spaces as per
   * https://tools.ietf.org/html/rfc6749#section-3.3
   */
  scope?: string | string[];

  requestOptions?: RequestOptions;
}

/**
 * Implements the OAuth 2.0 resource owner password credentials grant.
 *
 * See https://tools.ietf.org/html/rfc6749#section-4.3
 */
export class ResourceOwnerPasswordCredentialsGrant extends OAuth2GrantBase {
  constructor(config: OAuth2ClientConfig) {
    super(config);
  }

  /**
   * Uses the username and password to request an access and optional refresh token
   */
  public async getToken(
    options: ResourceOwnerPasswordCredentialsTokenOptions,
  ): Promise<Tokens> {
    const request = this.buildTokenRequest(options);

    const accessTokenResponse = await fetch(request);

    const { tokens } = await this.parseTokenResponse(accessTokenResponse);
    return tokens;
  }

  protected buildTokenRequest(
    options: ResourceOwnerPasswordCredentialsTokenOptions,
  ): Request {
    const body: Record<string, string> = {
      "grant_type": "password",
      username: options.username,
      password: options.password,
    };
    const headers: Record<string, string> = {
      "Accept": "application/json",
    };

    const scope = options.scope ?? this.config.defaults?.scope;
    if (scope) {
      if (Array.isArray(scope)) {
        body.scope = scope.join(" ");
      } else {
        body.scope = scope;
      }
    }

    if (typeof this.config.clientSecret === "string") {
      // We have a client secret, authenticate using HTTP Basic Auth as described in RFC6749 Section 2.3.1.
      const { clientId, clientSecret } = this.config;
      headers.Authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    } else {
      // This appears to be a public client, include the client ID in the body instead
      body.client_id = this.config.clientId;
    }

    return this.buildRequest(this.config.tokenUri, {
      method: "POST",
      headers,
      body,
    }, options.requestOptions);
  }
}
