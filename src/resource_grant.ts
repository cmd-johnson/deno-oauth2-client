import type { OAuth2Client } from "./oauth2_client.ts";
import { OAuth2GrantBase } from "./grant_base.ts";
import { HttpVerb, RequestOptions } from "./types.ts";
  

export class ResourceGrant extends OAuth2GrantBase {
    constructor(client: OAuth2Client) {
        super(client);
      };

    public async serverResponse(
    method: HttpVerb,
    resourcePath: string,
    token: string,
    requestOptions?: RequestOptions): Promise<Response> {
        const headers: Record<string, string> = {
            "Authorization": `Bearer ${token}`,
            "content-type": "application/json",
        };
        const resourceUrl: string = this.client.config.resourceEndpointHost + resourcePath
        const request = this.buildRequest(resourceUrl, {
            method,
            headers
        }, requestOptions);
        console.log(request)
        const response = await fetch(request);
        console.log(response)

    return response
    }
}