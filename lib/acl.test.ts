import { AclClassification, HttpAclBuilder, HttpRequestMethod } from "./acl";

export {
    AclClassification, HttpAcl, HttpAclBuilder,
    HttpRequestMethod, AclClassificationResult
} from "./acl"

describe('url', () => {
    it('url validation', () => {
        const acl = new HttpAclBuilder()
            .https(true)
            .http(false)
            .allowUserNameOnUrl(false)
            .build()

        const resultHttps = acl.isUrlAllowed("https://example.com")
        const resultHttp = acl.isUrlAllowed("http://example.com")
        const resultInvalidPort = acl.isUrlAllowed("http://example.com:9012")
        const resultWithUser = acl.isUrlAllowed("http://admin:password@example.com:9012")

        expect(resultHttps.status).toBe(AclClassification.AllowedUserAcl);
        expect(resultHttps.allowed).toBe(true);

        expect(resultHttp.status).toBe(AclClassification.DeniedDefault);
        expect(resultHttp.allowed).toBe(false);

        expect(resultInvalidPort.status).toBe(AclClassification.DeniedDefault);
        expect(resultInvalidPort.allowed).toBe(false);

        expect(resultWithUser.status).toBe(AclClassification.DeniedUserAcl);
        expect(resultWithUser.details).toBe("Username on the url is not allowed");
        expect(resultWithUser.allowed).toBe(false);
    });
});

describe('ports', () => {
    it('allow 443 and 80 by default others should deny default', () => {
        const acl = new HttpAclBuilder().build()
        const result1 = acl.isPortAllowed(80)
        const result2 = acl.isPortAllowed(443)
        const result3 = acl.isPortAllowed(21)

        expect(result1.status).toBe(AclClassification.AllowedUserAcl);
        expect(result1.allowed).toBe(true);

        expect(result2.status).toBe(AclClassification.AllowedUserAcl);
        expect(result2.allowed).toBe(true);

        expect(result3.status).toBe(AclClassification.DeniedDefault);
        expect(result3.allowed).toBe(false);
    });
});

describe('ports', () => {
    it('deny patch requests', () => {
        const acl = new HttpAclBuilder()
            .deniedMethods([HttpRequestMethod.PATCH])
            .build()
        const result = acl.isMethodAllowed(HttpRequestMethod.PATCH)

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);
    });
    it('deny patch requests with high proirity', () => {
        const acl = new HttpAclBuilder()
            .allowedMethods([HttpRequestMethod.PATCH])
            .deniedMethods([HttpRequestMethod.PATCH])
            .build()
        const result = acl.isMethodAllowed(HttpRequestMethod.PATCH)

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);
    });
});


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
    it("acl allow whitelisted private ipv4 and when fail open", () => {
        const acl = new HttpAclBuilder().allowPrivateIpRanges(false).allowedIpAddress(["192.168.1.10"]).build();
        const result = acl.isIpAllowed("192.168.1.10")
        const result2 = acl.isIpAllowed("1.1.1.1")

        expect(result.status).toBe(AclClassification.AllowedUserAcl);
        expect(result.allowed).toBe(true);

        expect(result2.status).toBe(AclClassification.AllowedDefault);
        expect(result2.allowed).toBe(true);
    })
    it("acl deny blacklisted private ipv4 and whitelist public ip while default is fail close", () => {
        const acl = new HttpAclBuilder().allowPrivateIpRanges(false)
            .allowIpAclDefault(false)
            .allowedIpAddress(["1.1.1.1"])
            .deniedIpAddress(["192.168.1.10"])
            .build();

        const result = acl.isIpAllowed("192.168.1.10")
        const resultAllowPublic = acl.isIpAllowed("1.1.1.1")
        const resultDenyPublic = acl.isIpAllowed("8.8.8.8")

        expect(result.status).toBe(AclClassification.DeniedUserAcl);
        expect(result.allowed).toBe(false);

        expect(resultAllowPublic.status).toBe(AclClassification.AllowedUserAcl);
        expect(resultAllowPublic.allowed).toBe(true);

        expect(resultDenyPublic.status).toBe(AclClassification.DeniedDefault);
        expect(resultDenyPublic.allowed).toBe(false);
    })
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

