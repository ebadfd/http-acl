import { HttpAclBuilder } from "../lib"
import { Agent as httpsAgent } from "https"
import { Agent as httpAgent } from "http"
import { Resolver } from "dns"
import axios from 'axios'

const resolver = new Resolver();
resolver.setServers([
    '10.20.23.31',
    '1.1.1.1',
]);

const acl = new HttpAclBuilder()
    .http(false)
    .https(true)
    .allowPrivateIpRanges(false)
    .build()

const instance = axios.create({
    httpAgent: new httpAgent({
        lookup: (hostname, _, callback) => {
            resolver.resolve4(hostname, (err, addresses) => {
                if (!addresses[0]) {
                    throw new Error(`No address found for DNS resolution on ${hostname}`);
                }

                const aclhost = acl.isHostAllowed(hostname)

                if (!aclhost.allowed) {
                    throw new Error(`Request has been rejected from acl due to ${aclhost.status}`)
                }

                const aclprotoc = acl.isSchemeAllowed("http")

                if (!aclprotoc.allowed) {
                    throw new Error(`Request has been rejected from acl due to ${aclprotoc.status}`)
                }

                const aclip = acl.isIpAllowed(addresses[0])

                if (!aclip.allowed) {
                    throw new Error(`Request has been rejected from acl due to ${aclip.status}`)
                }

                callback(err, [{ address: addresses[0], family: 4 }]);
            });
        },
    }),
    httpsAgent: new httpsAgent({
        lookup: (hostname, _, callback) => {
            resolver.resolve4(hostname, (err, addresses) => {
                if (!addresses[0]) {
                    throw new Error(`No address found for DNS resolution on ${hostname}`);
                }

                const aclhost = acl.isHostAllowed(hostname)

                if (!aclhost.allowed) {
                    throw new Error(`Request has been rejected from acl due to ${aclhost.status}`)
                }

                const aclprotoc = acl.isSchemeAllowed("https")

                if (!aclprotoc.allowed) {
                    throw new Error(`Request has been rejected from acl due to ${aclprotoc.status}`)
                }

                const aclip = acl.isIpAllowed(addresses[0])

                if (!aclip.allowed) {
                    throw new Error(`Request has been rejected from acl due to ${aclip.status}`)
                }

                callback(err, [{ address: addresses[0], family: 4 }]);
            });
        },
    }),
});

instance.get("https://ebadfd.tech/blog.rss").then((result) => {
    console.log(result.status)
}).catch((error) => {
    console.error(error)
})

instance.get("http://ebadfd.tech/blog.rss").then((result) => {
    console.log(result.status)
}).catch((error) => {
    console.error(error)
})

instance.get("https://nas.local/").then((result) => {
    console.log(result.status)
}).catch((error) => {
    console.error(error)
})

