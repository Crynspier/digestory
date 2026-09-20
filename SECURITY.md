# Security Policy

Please report security-sensitive issues privately before public disclosure.

Digestory processes authentication challenges and produces HTTP authorization headers. Parser bugs, header injection, credential disclosure, algorithm-confusion/downgrade issues, replay-related state errors, and crashes on attacker-controlled input should be treated as security-sensitive.

Digest Authentication itself has protocol limitations. RFC 7616 does not provide general confidentiality and recommends transport protection such as TLS for HTTP messages. Digestory therefore does not attempt to turn Digest Authentication into a replacement for HTTPS.
