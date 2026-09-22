# Security Policy

Please report security-sensitive issues privately before public disclosure.

The preferred route is a private GitHub Security Advisory for this repository. Do not put credentials, private Authorization headers, or exploitable challenge payloads into a public issue.

Digestory processes authentication challenges and produces HTTP authorization headers. Parser bugs, header injection, credential disclosure, algorithm-confusion/downgrade issues, replay-related state errors, and crashes on attacker-controlled input should be treated as security-sensitive.

### Scope

Digestory provides HTTP Digest Authentication. It does not provide transport confidentiality, endpoint identity, or general message secrecy.

Digest Authentication does not replace TLS. Use HTTPS for HTTP traffic, especially when credentials or authenticated requests cross an untrusted network.

Digestory's core `Session` object keeps the password out of public readers, but applications should still avoid logging session objects, credentials, Authorization headers, and authentication challenges containing sensitive material.

For concurrent in-flight authentication exchanges that require `Authentication-Info` verification, use the request-specific `AuthorizationContext` API. The legacy `authorize` / `update_authentication_info` pair retains a single compatibility last-request slot and is intended for sequential exchanges.

### Supported versions

The 0.1 release line is the supported release line for this project while it is current.

### Reporting

For a vulnerability, include:

- the affected version or commit;
- a minimal reproduction or test case when safe to share privately;
- the affected API or parser surface;
- the security impact you observed.

Please allow time for investigation and coordinated disclosure before making the issue public.
