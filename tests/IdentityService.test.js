import { describe, expect, it, vi } from "vitest";
async function loadIdentityServiceClass() {
    vi.resetModules();
    process.env.BASE44_BASE_URL = "https://identity.example.com";
    process.env.IDENTITY_API_PATH = "/api/identity";
    process.env.BOOKWRM_IDENTITY_API_KEY = "test-key";
    const module = await import("../src/identity/IdentityService.js");
    return module.IdentityService;
}
describe("IdentityService", () => {
    it("delegates all methods to the platform client", async () => {
        const fakeResponse = {
            success: true,
            requestId: "req-1",
            version: "v1",
            data: {}
        };
        const fakeClient = {
            health: vi.fn().mockResolvedValue(fakeResponse),
            getIdentityContext: vi.fn().mockResolvedValue(fakeResponse),
            resolveIdentity: vi.fn().mockResolvedValue(fakeResponse),
            reverify: vi.fn().mockResolvedValue(fakeResponse),
            getSecurityContext: vi.fn().mockResolvedValue(fakeResponse),
            getPolicies: vi.fn().mockResolvedValue(fakeResponse),
            getTimeline: vi.fn().mockResolvedValue(fakeResponse),
            getNotifications: vi.fn().mockResolvedValue(fakeResponse),
            getTrustedDevices: vi.fn().mockResolvedValue(fakeResponse)
        };
        const IdentityService = await loadIdentityServiceClass();
        const service = new IdentityService(fakeClient);
        const healthResult = await service.health();
        expect(healthResult).toEqual(fakeResponse);
        expect(fakeClient.health).toHaveBeenCalledTimes(1);
        const contextResult = await service.getIdentityContext("user-123");
        expect(contextResult).toEqual(fakeResponse);
        expect(fakeClient.getIdentityContext).toHaveBeenCalledTimes(1);
        expect(fakeClient.getIdentityContext).toHaveBeenCalledWith("user-123");
        const resolveResult = await service.resolveIdentity();
        expect(resolveResult).toEqual(fakeResponse);
        expect(fakeClient.resolveIdentity).toHaveBeenCalledTimes(1);
        const reverifyResult = await service.reverify();
        expect(reverifyResult).toEqual(fakeResponse);
        expect(fakeClient.reverify).toHaveBeenCalledTimes(1);
        const securityResult = await service.getSecurityContext();
        expect(securityResult).toEqual(fakeResponse);
        expect(fakeClient.getSecurityContext).toHaveBeenCalledTimes(1);
        const policiesResult = await service.getPolicies();
        expect(policiesResult).toEqual(fakeResponse);
        expect(fakeClient.getPolicies).toHaveBeenCalledTimes(1);
        const timelineResult = await service.getTimeline();
        expect(timelineResult).toEqual(fakeResponse);
        expect(fakeClient.getTimeline).toHaveBeenCalledTimes(1);
        const notificationsResult = await service.getNotifications();
        expect(notificationsResult).toEqual(fakeResponse);
        expect(fakeClient.getNotifications).toHaveBeenCalledTimes(1);
        const trustedDevicesResult = await service.getTrustedDevices();
        expect(trustedDevicesResult).toEqual(fakeResponse);
        expect(fakeClient.getTrustedDevices).toHaveBeenCalledTimes(1);
    });
});
