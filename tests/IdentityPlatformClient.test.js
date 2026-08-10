import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
function okResponse(data) {
    return {
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue(data)
    };
}
function errorResponse(status) {
    return {
        ok: false,
        status,
        json: vi.fn().mockResolvedValue({})
    };
}
async function loadClientClass() {
    vi.resetModules();
    process.env.BASE44_BASE_URL = "https://identity.example.com";
    process.env.IDENTITY_API_PATH = "/api/identity";
    process.env.BOOKWRM_IDENTITY_API_KEY = "test-key";
    const module = await import("../src/clients/IdentityPlatformClient.js");
    return module.IdentityPlatformClient;
}
describe("IdentityPlatformClient", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });
    afterEach(() => {
        vi.unstubAllGlobals();
    });
    it("returns JSON on successful health request and logs request metadata", async () => {
        const responsePayload = {
            success: true,
            requestId: "upstream-1",
            version: "v1",
            data: {
                status: "ok"
            }
        };
        const fetchMock = vi.fn().mockResolvedValue(okResponse(responsePayload));
        vi.stubGlobal("fetch", fetchMock);
        vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue("req-123");
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => undefined);
        const IdentityPlatformClient = await loadClientClass();
        const client = new IdentityPlatformClient();
        const result = await client.health();
        expect(result).toEqual(responsePayload);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe("https://identity.example.com/api/identity");
        expect(init.method).toBe("POST");
        const body = JSON.parse(String(init.body));
        expect(body.action).toBe("health");
        expect(infoSpy).toHaveBeenCalledTimes(1);
        const logged = JSON.parse(String(infoSpy.mock.calls[0][0]));
        expect(logged.RequestId).toBe("req-123");
        expect(logged.Action).toBe("health");
        expect(logged.Success).toBe(true);
        expect(logged.RetryCount).toBe(0);
        expect(typeof logged.Latency).toBe("number");
    });
    it("retries on HTTP 500 and succeeds on a later attempt", async () => {
        const responsePayload = {
            success: true,
            requestId: "upstream-2",
            version: "v1",
            data: []
        };
        const fetchMock = vi
            .fn()
            .mockResolvedValueOnce(errorResponse(500))
            .mockResolvedValueOnce(okResponse(responsePayload));
        vi.stubGlobal("fetch", fetchMock);
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => undefined);
        const IdentityPlatformClient = await loadClientClass();
        const client = new IdentityPlatformClient();
        const result = await client.getPolicies();
        expect(result).toEqual(responsePayload);
        expect(fetchMock).toHaveBeenCalledTimes(2);
        const logged = JSON.parse(String(infoSpy.mock.calls[0][0]));
        expect(logged.Success).toBe(true);
        expect(logged.RetryCount).toBe(1);
        expect(logged.Action).toBe("getPolicies");
    });
    it("does not retry on HTTP 401 and throws a standardized ApiError", async () => {
        const fetchMock = vi.fn().mockResolvedValue(errorResponse(401));
        vi.stubGlobal("fetch", fetchMock);
        const infoSpy = vi.spyOn(console, "info").mockImplementation(() => undefined);
        const IdentityPlatformClient = await loadClientClass();
        const client = new IdentityPlatformClient();
        await expect(client.getNotifications()).rejects.toMatchObject({
            name: "ApiError",
            statusCode: 401
        });
        expect(fetchMock).toHaveBeenCalledTimes(1);
        const logged = JSON.parse(String(infoSpy.mock.calls[0][0]));
        expect(logged.Success).toBe(false);
        expect(logged.RetryCount).toBe(0);
        expect(logged.Action).toBe("getNotifications");
    });
    it("maps abort failures to timeout ApiError instead of raw fetch errors", async () => {
        const fetchMock = vi.fn().mockRejectedValue(new DOMException("Aborted", "AbortError"));
        vi.stubGlobal("fetch", fetchMock);
        const IdentityPlatformClient = await loadClientClass();
        const client = new IdentityPlatformClient();
        try {
            await client.getTimeline();
            expect.unreachable("Expected getTimeline to throw");
        }
        catch (error) {
            expect(error).toMatchObject({
                name: "ApiError",
                statusCode: 408
            });
        }
    });
});
