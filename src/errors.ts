interface ErrorResponseParams {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export class AuthError extends Error {
  public readonly error: string;
  public readonly errorDescription?: string;
  public readonly errorUri?: string;
  public readonly state?: string;

  constructor(response: ErrorResponseParams) {
    super(response.error_description || response.error);

    this.error = response.error;
    this.errorDescription = response.error_description;
    this.errorUri = response.error_uri;
    this.state = response.state;
  }

  public static fromURLSearchParams(params: URLSearchParams) {
    const error = params.get("error");
    if (error === null) {
      throw new TypeError("error URL parameter must be set");
    }
    const response: ErrorResponseParams = {
      error: params.get("error") as string,
    };

    const description = params.get("error_description");
    if (description !== null) {
      response.error_description = description;
    }

    const uri = params.get("error_uri");
    if (uri !== null) {
      response.error_uri = uri;
    }

    const state = params.get("state");
    if (state !== null) {
      response.state = state;
    }

    return new AuthError(response);
  }
}

export class AuthServerResponseError extends Error {
  public readonly response: Response;

  constructor(description: string, response: Response) {
    super(`Invalid server response: ${description}`);
    this.response = response;
  }
}
