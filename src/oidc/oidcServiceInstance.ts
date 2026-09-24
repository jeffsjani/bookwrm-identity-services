import { PrivateIDAuthenticationProvider } from "../privateid/PrivateIDAuthenticationProvider.js";
import { OIDCService } from "./OIDCService.js";

// Composition root for the Bookwrm deployment. HAPI ID Core receives this provider through DI;
// the Bookwrm adapter remains responsible for selecting PrivateID.
export const oidcService = new OIDCService({
		authenticationProvider: new PrivateIDAuthenticationProvider()
});