import { describe, expect, it } from "vitest";

import { ConfigurationService } from "../src/config/ConfigurationService.js";

describe("ConfigurationService PrivateID validation", () => {
		it("fails in production when both redirect and callback URLs are missing", () => {
				const service = new ConfigurationService({
						NODE_ENV: "production"
				});

				expect(() => service.validatePrivateIdConfiguration()).toThrow(
						"Missing required configuration:\n\nPRIVATEID_REDIRECT_URL\n\nPRIVATEID_CALLBACK_URL"
				);
		});

		it("fails in production when PRIVATEID_REDIRECT_URL is missing", () => {
				const service = new ConfigurationService({
						NODE_ENV: "production",
						PRIVATEID_CALLBACK_URL: "https://identity.bookwrm.com/privateid/webhook"
				});

				expect(() => service.validatePrivateIdConfiguration()).toThrow(
						"Missing required configuration:\n\nPRIVATEID_REDIRECT_URL"
				);
		});

		it("fails in production when PRIVATEID_CALLBACK_URL is missing", () => {
				const service = new ConfigurationService({
						NODE_ENV: "production",
						PRIVATEID_REDIRECT_URL: "https://identity.bookwrm.com/privateid/callback"
				});

				expect(() => service.validatePrivateIdConfiguration()).toThrow(
						"Missing required configuration:\n\nPRIVATEID_CALLBACK_URL"
				);
		});

		it("passes in production when both redirect and callback URLs are configured", () => {
				const service = new ConfigurationService({
						NODE_ENV: "production",
						PRIVATEID_REDIRECT_URL: "https://identity.bookwrm.com/privateid/callback",
						PRIVATEID_CALLBACK_URL: "https://identity.bookwrm.com/privateid/webhook"
				});

				expect(() => service.validatePrivateIdConfiguration()).not.toThrow();
		});
});
