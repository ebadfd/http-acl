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

