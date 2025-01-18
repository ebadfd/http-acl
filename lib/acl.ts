import { isPrivate } from "ip"

export enum AclClassification {
    // Allowed according to ACL
    AllowedUserAcl,
    // Fail open - because default is to allow when no match
    AllowedDefault,
    // Denied according to denied acl
    DeniedUserAcl,
    // Fail close - because default is to deny when no match
    DeniedDefault,
    // denied 
    Denied,
    // allow private range
    AllowPrivateRange,
    // IP is in private range
    DeniedPrivateRange,
}

export enum HttpRequestMethod {
    GET = 'GET',
    CONNECT = 'CONNECT',
    DELETE = 'DELETE',
    HEAD = 'HEAD',
    OPTIONS = 'OPTIONS',
    PATCH = 'PATCH',
    POST = 'POST',
    PUT = 'PUT',
    TRACE = 'TRACE',
}

interface AclClassificationResult {
    status: AclClassification
    details: string | null
    allowed: boolean
}

export class HttpAcl {
    allowHttp: boolean = false;
    allowHttps: boolean = true;
    allowMethodAclDefault: boolean = false;

    allowPrivateIpRanges: boolean = true;
    allowIpAclDefault: boolean = true;
    allowPortAclDefault: boolean = true;
    allowHostsAclDefault: boolean = true;

    allowUserNameOnUrl: boolean = false;

    allowedMethods: HttpRequestMethod[];
    // Denied Methods has higher priority to prevent fail open cases
    deniedMethods: HttpRequestMethod[];

    allowedPorts: number[];
    deniedPorts: number[];

    allowedHosts: string[];
    deniedHosts: string[];

    allowedIpAddress: string[];
    deniedIpAddress: string[];

    constructor() {
        this.allowedMethods = [
            HttpRequestMethod.GET,
            HttpRequestMethod.CONNECT,
            HttpRequestMethod.DELETE,
            HttpRequestMethod.HEAD,
            HttpRequestMethod.OPTIONS,
            HttpRequestMethod.PATCH,
            HttpRequestMethod.POST,
            HttpRequestMethod.PUT,
            HttpRequestMethod.TRACE,
        ];
        this.allowedPorts = [80, 443, 8080]
        this.deniedMethods = [];
    }

    isSchemeAllowed(scheme: String) {
        if (scheme == "http" && this.allowHttp || scheme === "https" && this.allowHttps) {
            return this.result(AclClassification.AllowedUserAcl)
        }
        return this.result(AclClassification.DeniedUserAcl)
    }

    isMethodAllowed(method: HttpRequestMethod) {
        if (this.deniedMethods.includes(method)) {
            return this.result(AclClassification.DeniedUserAcl, "Denied user acl has high priority")
        }

        if (this.allowedMethods.includes(method)) {
            return this.result(AclClassification.AllowedUserAcl)
        }

        if (this.allowMethodAclDefault) {
            return this.result(AclClassification.AllowedDefault)
        }

        return this.result(AclClassification.DeniedDefault)
    }

    isIpAllowed(ip: string) {
        const isprivateIp = isPrivate(ip)

        if (this.allowedIpAddress.includes(ip)) {
            return this.result(AclClassification.AllowedUserAcl)
        }

        if (this.deniedIpAddress.includes(ip)) {
            return this.result(AclClassification.DeniedUserAcl)
        }

        if (isprivateIp && !this.allowPrivateIpRanges) {
            return this.result(AclClassification.DeniedUserAcl)
        }

        if (this.allowIpAclDefault) {
            return this.result(AclClassification.AllowedDefault)
        }

        return this.result(AclClassification.DeniedDefault)
    }

    isPortAllowed(port: number) {
        if (this.deniedPorts.includes(port)) {
            return this.result(AclClassification.DeniedUserAcl)
        }

        if (this.allowedPorts.includes(port)) {
            return this.result(AclClassification.AllowedUserAcl)
        }

        if (this.allowPortAclDefault) {
            return this.result(AclClassification.AllowedDefault)
        }

        return this.result(AclClassification.DeniedDefault)
    }

    isHostAllowed(host: string) {
        if (this.deniedHosts.includes(host)) {
            return this.result(AclClassification.DeniedUserAcl)
        }

        if (this.allowedHosts.includes(host)) {
            return this.result(AclClassification.AllowedUserAcl)
        }

        if (this.allowHostsAclDefault) {
            return this.result(AclClassification.AllowedDefault)
        }

        return this.result(AclClassification.DeniedDefault)
    }

    isUrlAllowed(url: string) {
        const parsedUrl = new URL(url);
        const isHostAllowed = this.isHostAllowed(parsedUrl.host)
        const isPortAllowed = this.isPortAllowed(Number(parsedUrl.port))
        const isProtocolAllowed = this.isSchemeAllowed(parsedUrl.protocol)

        if (isHostAllowed && isPortAllowed && isProtocolAllowed) {
            return this.result(AclClassification.AllowedUserAcl)
        }

        if (parsedUrl.username != '' && !this.allowUserNameOnUrl) {
            return this.result(AclClassification.DeniedUserAcl, "Username on the url is not allowed")
        }

        return this.result(AclClassification.DeniedDefault)
    }

    private result(classification: AclClassification, details: string | null = null): AclClassificationResult {
        return {
            status: classification,
            details,
            allowed: true
        }
    }

    static default(): HttpAcl {
        return new HttpAclBuilder()
            .http(true)
            .https(true)
            .allowPrivateIpRanges(false)
            .deniedMethods([HttpRequestMethod.PUT])
            .build();
    }
}

interface IhttpAclBuilder {
    http(allow: boolean): HttpAclBuilder;
    https(allow: boolean): HttpAclBuilder;

    allowPrivateIpRanges(allow: boolean): HttpAclBuilder;
    allowMethodAclDefault(allow: boolean): HttpAclBuilder;

    allowedMethods(methods: HttpRequestMethod[]): HttpAclBuilder;
    deniedMethods(methods: HttpRequestMethod[]): HttpAclBuilder;

    build(): HttpAcl
}

export class HttpAclBuilder implements IhttpAclBuilder {
    private acl: HttpAcl;

    constructor() {
        this.acl = new HttpAcl();
    }

    http(allow: boolean): this {
        this.acl.allowHttp = allow;
        return this
    }

    https(allow: boolean): this {
        this.acl.allowHttps = allow;
        return this
    }

    allowPrivateIpRanges(allow: boolean): this {
        this.acl.allowPrivateIpRanges = allow;
        return this
    }

    allowMethodAclDefault(allow: boolean): HttpAclBuilder {
        this.acl.allowMethodAclDefault = allow;
        return this
    }

    allowedMethods(methods: HttpRequestMethod[]): HttpAclBuilder {
        this.acl.allowedMethods = methods;
        return this
    }

    deniedMethods(methods: HttpRequestMethod[]): HttpAclBuilder {
        this.acl.deniedMethods = methods;
        return this;
    }

    build(): HttpAcl {
        return this.acl
    }
}
