// Backward-compat shim: the Base44-specific implementation moved to src/adapters/base44 (HAPI ID H1).
// Kept here only so existing imports (tests, OIDCService's legacy fallback) don't need to change.
export {
		registerBase44OIDCClient as registerOIDCClients,
		type RegisteredOIDCClient
} from "../adapters/base44/Base44OIDCClientAdapter.js";
