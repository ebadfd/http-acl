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

export interface AclClassificationResult {
    status: AclClassification
    details: string | null
    allowed: boolean
}

export class HttpAcl {
    allowHttp: boolean = false;
    allowHttps: boolean = true;
    allowMethodAclDefault: boolean = false;

    allowPrivateIpRanges: boolean = false;

    allowIpAclDefault: boolean = true;
    allowPortAclDefault: boolean = false;
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
        this.deniedPorts = [];

        this.allowedHosts = [];
        this.deniedHosts = [];

        this.allowedIpAddress = [];
        this.deniedIpAddress = [];

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
            return this.result(AclClassification.DeniedPrivateRange)
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
        const allowed =
            classification === AclClassification.AllowedUserAcl ||
            classification === AclClassification.AllowedDefault ||
            classification === AclClassification.AllowPrivateRange;

        return {
            status: classification,
            details,
            allowed
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

    allowIpAclDefault(allow: boolean): HttpAclBuilder;
    allowPortAclDefault(allow: boolean): HttpAclBuilder;
    allowHostsAclDefault(allow: boolean): HttpAclBuilder;

    allowUserNameOnUrl(allow: boolean): HttpAclBuilder;

    allowedPorts(ports: number[]): HttpAclBuilder;
    deniedPorts(ports: number[]): HttpAclBuilder;

    allowedHosts(hosts: string[]): HttpAclBuilder;
    deniedHosts(hosts: string[]): HttpAclBuilder;

    allowedIpAddress(ips: string[]): HttpAclBuilder;
    deniedIpAddress(ips: string[]): HttpAclBuilder;

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

    allowedIpAddress(ips: string[]): HttpAclBuilder {
        this.acl.allowedIpAddress = ips;
        return this
    }

    deniedIpAddress(ips: string[]): HttpAclBuilder {
        this.acl.deniedIpAddress = ips;
        return this
    }

    allowedPorts(ports: number[]): HttpAclBuilder {
        this.acl.allowedPorts = ports;
        return this
    }

    deniedPorts(ports: number[]): HttpAclBuilder {
        this.acl.deniedPorts = ports;
        return this
    }

    allowUserNameOnUrl(allow: boolean): HttpAclBuilder {
        this.acl.allowUserNameOnUrl = allow;
        return this
    }

    allowHostsAclDefault(allow: boolean): HttpAclBuilder {
        this.acl.allowHostsAclDefault = allow;
        return this
    }

    allowPortAclDefault(allow: boolean): HttpAclBuilder {
        this.acl.allowPortAclDefault = allow;
        return this
    }

    allowIpAclDefault(allow: boolean): HttpAclBuilder {
        this.acl.allowIpAclDefault = allow;
        return this
    }

    allowedHosts(hosts: string[]): HttpAclBuilder {
        this.acl.allowedHosts = hosts;
        return this
    }

    deniedHosts(hosts: string[]): HttpAclBuilder {
        this.acl.deniedHosts = hosts;
        return this
    }


    build(): HttpAcl {
        return this.acl
    }
}
