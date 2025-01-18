import { AclClassification, HttpAclBuilder } from "./acl";

export {
    AclClassification, HttpAcl, HttpAclBuilder,
    HttpRequestMethod, AclClassificationResult
} from "./acl"


describe('host only acl', () => {
    it('acl show allow example.com', () => {
        const acl = new HttpAclBuilder().allowedHosts(["example.com"]).allowHostsAclDefault(false).build()
        const result = acl.isHostAllowed("example.com")

        expect(result.status).toBe(AclClassification.AllowedUserAcl);
        expect(result.allowed).toBe(true);
    });
    it('acl show deny google.com', () => {
        const acl = new HttpAclBuilder().allowedHosts(["example.com"]).allowHostsAclDefault(false).build()
        const result = acl.isHostAllowed("google.com")

        expect(result.status).toBe(AclClassification.DeniedDefault);
        expect(result.allowed).toBe(false);
    });
});

describe('schema', () => {
    it('should deny http', () => {
        const acl = new HttpAclBuilder().http(false).build()
        const result = acl.isSchemeAllowed("http")

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);
    });
    it('should allow http', () => {
        const acl = new HttpAclBuilder().http(true).build()
        const result = acl.isSchemeAllowed("http")

        expect(result.status).toBe(AclClassification.AllowedUserAcl);
        expect(result.allowed).toBe(true);
    });
    it('should allow https', () => {
        const acl = new HttpAclBuilder().https(true).build()
        const result = acl.isSchemeAllowed("https")

        expect(result.status).toBe(AclClassification.AllowedUserAcl);
        expect(result.allowed).toBe(true);
    });
    it('should deny https', () => {
        const acl = new HttpAclBuilder().https(false).build()
        const result = acl.isSchemeAllowed("https")

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);
    });
    it('should deny', () => {
        const acl = new HttpAclBuilder().build()
        const result = acl.isSchemeAllowed("ftp")

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);
    });
    it('should deny http by default', () => {
        const acl = new HttpAclBuilder().build()
        const result = acl.isSchemeAllowed("http")

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);
    });
    it('should allow https by default', () => {
        const acl = new HttpAclBuilder().build()
        const result = acl.isSchemeAllowed("https")

        expect(result.status).toBe(AclClassification.AllowedUserAcl);
        expect(result.allowed).toBe(true);
    });
});

describe("private ip range", () => {
    it("acl show deny private ipv4", () => {
        const acl = new HttpAclBuilder().allowPrivateIpRanges(false).build();
        const result = acl.isIpAllowed("192.168.1.1")

        expect(result.status).toBe(AclClassification.DeniedPrivateRange);
        expect(result.allowed).toBe(false);
    })
    it("acl show deny private ipv4", () => {
        const acl = new HttpAclBuilder().allowPrivateIpRanges(false).build();
        const result = acl.isIpAllowed("10.255.255.254")

        expect(result.status).toBe(AclClassification.DeniedPrivateRange);
        expect(result.allowed).toBe(false);
    })
    it("acl show allow private ipv4", () => {
        const acl = new HttpAclBuilder().allowPrivateIpRanges(true).build();
        const result = acl.isIpAllowed("172.31.255.255")

        expect(result.status).toBe(AclClassification.AllowedDefault);
        expect(result.allowed).toBe(true);
    })
    it("acl show deny private ipv6", () => {
        const acl = new HttpAclBuilder().allowPrivateIpRanges(false).build();
        const result = acl.isIpAllowed("fc00:789a:bcde:f012::3")

        expect(result.status).toBe(AclClassification.DeniedPrivateRange);
        expect(result.allowed).toBe(false);
    })
})
