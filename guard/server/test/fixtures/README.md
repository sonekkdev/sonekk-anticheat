# Test fixtures

These keys and certificates are throwaway, generated with OpenSSL purely so the
attestation tests can prove chain validation works:

- `root.pem` / `root.key` - trusted test CA
- `leaf.pem` / `leaf.key` - leaf certificate used to sign the challenge
- `other-root.pem` / `other-root.key` - a CA that is not trusted, used to prove
  that an untrusted anchor is rejected

They protect nothing. Never treat them as secrets, and never reuse them.

- `attested-leaf.pem` / `attested-leaf.key` - leaf carrying a synthetic Android key
  attestation extension: verified boot, device locked, challenge `0123456789abcdef0123456789abcdef`
- `unlocked-leaf.pem` / `unlocked-leaf.key` - same, but boot state unverified and device unlocked
- `ext.cnf` / `ext-unlocked.cnf` - openssl extension files used to build those two certificates
