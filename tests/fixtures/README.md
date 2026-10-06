These certificates and the private key are synthetic fixtures for TLS tests.
Both certificates have `CA:TRUE`, as in the LND certificate that triggered
`CaUsedAsEndEntity`, and share a key to test exact certificate pinning.
Never use this public test key for a deployed service.
