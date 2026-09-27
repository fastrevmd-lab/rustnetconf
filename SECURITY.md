# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/fastrevmd-lab/rustnetconf/security/advisories/new

Include what you'd include in a bug report — affected version, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

This is a NETCONF client library used to automate network and security infrastructure. Vulnerability classes we especially want to hear about: SSH/host-key verification bypass, XML/NETCONF parsing issues that could let a malicious or malformed device response affect the client beyond the intended session (parser differentials, injection through unescaped config payloads), and anything that could cause a device-changing RPC to fire without the caller's explicit intent.

## Response

This is a community-maintained project. There's no guaranteed SLA, but reports are read and triaged by a human maintainer, not by any automated or model-based process.
