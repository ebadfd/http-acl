# http-acl

An ACL for HTTP requests.

## Why?

This library was created primarily to prevent SSRF (Server-Side Request Forgery) attacks and to validate HTTP requests. It is inspired by the [http-acl](https://docs.rs/http-acl/latest/http_acl/).

## Overview

This crate provides a simple Access Control List (ACL) to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can be used to ensure that a user's HTTP request meets the predefined requirements before the request is processed.

## Features

- Define which hosts are allowed
- Restrict access to specific ports
- Specify allowed IP ranges
- Protect against SSRF vulnerabilities by validating requests


## Example usage

```ts
const acl = new HttpAclBuilder()
    .http(false)
    .https(true)
    .allowPrivateIpRanges(false)
    .build()

const instance = axios.create({
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

instance.get("https://nas.local/").then((result) => {
    console.log(result.status)
}).catch((error) => {
    console.error(error)
})

```
