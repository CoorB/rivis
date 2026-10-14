# NEO project profile

This profile preserves the original SNB NEO defaults:

- Project-only hosts: `neo\.sa|alahli\.com`.
- Collection recording defaults to those same hosts; throttling defaults to `neo\.sa`.
- Use `--insecure` (legacy alias: `--dev`) for dev, whose certificate does not cover the dev hosts. SIT,
  NFR, UAT, and pre-prod use the shared valid gateway certificate.
- Use Debug Android variants; their network security configuration trusts user CAs. Release variants pin TLS.
- On iOS, use a Debug build or an `-unprotected` configuration when certificate pinning is enabled.
- The known Android package is `com.snb.neo.uat`; bundle IDs vary by generated iOS variant.

The example rules are the original NEO rules, all disabled on first use.
