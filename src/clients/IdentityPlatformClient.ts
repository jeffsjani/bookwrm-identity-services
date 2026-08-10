import { env } from "../config/env.js";

export class Base44IdentityAdapter {
		async health() {
				const response = await fetch(
						`${env.BASE44_BASE_URL}${env.IDENTITY_API_PATH}`,
						{
								method: "POST",
								headers: {
										"Content-Type": "application/json",
										Authorization:
												`Bearer ${env.BOOKWRM_IDENTITY_API_KEY}`
								},
								body: JSON.stringify({
										version: "v1",
										action: "health"
								})
						}
				);

				return response.json();
		}
}