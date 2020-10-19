import { AuthorizationCodeGrant } from "./authorization_code_grant.ts";

export interface RequestOptions {
  /** Headers to set when performing outgoing HTTP requests. */
  headers?: Record<string, string>;
  /** URL parameters to set when performing outgoing HTTP requests. */
  params?: Record<string, string>;
  /** Body parameters to set when performing outgoing HTTP requests. */
  body?: Record<string, string>;
}

export interface OAuth2ClientConfig {
  /** The client ID provided by the authorization server. */
  clientId: string;
  /** The client secret provided by the authorization server, if using a confidential client. */
  clientSecret?: string;
  /** The URI of the client's redirection endpoint (sometimes also called callback URI). */
  redirectUri?: string;

  /** The URI of the authorization server's authorization endpoint. */
  authorizationEndpointUri: string;
  /** The URI of the authorization server's token endpoint. */
  tokenUri: string;

  defaults?: {
    /** Default request options to use when performing outgoing HTTP requests.
     * For example used when exchanging authorization codes for access tokens.
     */
    requestOptions?: RequestOptions;
    /** Default scopes to request unless otherwise specified. */
    scope?: string | string[];
    /** Default state validator to use for validating the authorization response's state value. */
    stateValidator?: (state: string | null) => boolean;
  };
}

export class OAuth2Client {
  /**
   * Implements the Authorization Code Grant.
   *
   * See RFC6749, section 4.1.
   */
  public code = new AuthorizationCodeGrant(this);

  constructor(
    public readonly config: Readonly<OAuth2ClientConfig>,
  ) {}
}
