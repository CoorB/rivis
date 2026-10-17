"""system_trust — the certificates this Mac trusts for HTTPS, as one PEM file for mitmproxy's upstream checks.

mitmproxy checks servers against its own bundled root list (certifi), not the macOS keychain. On a network that
inspects TLS (a corporate root pushed by MDM or installed by IT), every HTTPS call through Rivis then failed with
"certificate verify failed", while Safari, curl and Proxyman worked. This builds the list the Mac itself uses:
  - the macOS root store (SystemRootCertificates.keychain) as the system trust settings allow it for SSL, minus roots an
    admin or the user set to "Never Trust", and
  - every certificate in the System and user keychains that macOS trusts for SSL (`security verify-cert -p ssl`,
    local only), i.e. exactly what IT, MDM or the user marked as trusted — nothing the Mac does not trust.
Extra PEM files given on the command line are added as they are (an explicit choice by the person starting Rivis).

Usage: system_trust.py OUT.pem [EXTRA.pem ...]   prints "<roots> <added>" and exits 0, or exits 1 (caller falls back
to mitmproxy's own list). Stdlib only; runs under /usr/bin/python3.
"""
import os
import re
import subprocess
import sys
import tempfile

SECURITY = "/usr/bin/security"
SYSTEM_ROOTS = "/System/Library/Keychains/SystemRootCertificates.keychain"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----", re.S)
HASHED = re.compile(r"SHA-1 hash: ([0-9A-F]+)\s+(-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----)", re.S)


def _security(*args, timeout=20):
    return subprocess.run([SECURITY] + list(args), capture_output=True, text=True, timeout=timeout)


def _user_keychains():
    cp = _security("list-keychains", "-d", "user")
    return [k.strip().strip('"') for k in cp.stdout.splitlines() if k.strip()]


def trusted_for_ssl(pem, workdir):
    """macOS's own verdict: does this Mac trust the certificate as an SSL anchor? (local only, no network)"""
    path = os.path.join(workdir, "c.pem")
    with open(path, "w") as fh:
        fh.write(pem + "\n")
    return _security("verify-cert", "-c", path, "-p", "ssl", "-L", "-l", "-q").returncode == 0


def added_anchors(workdir, keychains=None):
    """Certificates outside the root store that macOS trusts for SSL (corporate / MDM / admin / user trust)."""
    keychains = [k for k in (keychains if keychains is not None else [SYSTEM_KEYCHAIN] + _user_keychains())
                 if os.path.exists(k)]
    if not keychains:
        return []
    seen, kept = set(), []
    for sha1, pem in HASHED.findall(_security("find-certificate", "-a", "-Z", "-p", *keychains).stdout):
        if sha1 in seen:
            continue
        seen.add(sha1)
        if trusted_for_ssl(pem, workdir):
            kept.append(pem)
    return kept


SSL_POLICIES = {"sslServer", "basicX509", None}
TRUST_ROOT, TRUST_AS_ROOT, DENY = 1, 2, 3


def _trust_settings(domain_flag, workdir):
    """{SHA-1: [settings]} for one trust-settings domain ("-s" system, "-d" admin, "" user), or None if unreadable."""
    path = os.path.join(workdir, "ts%s.plist" % domain_flag.strip("-"))
    args = ["trust-settings-export"] + ([domain_flag] if domain_flag else []) + [path]
    if _security(*args).returncode != 0:
        return None
    try:
        import plistlib
        with open(path, "rb") as fh:
            return {k.upper(): (v.get("trustSettings") or []) for k, v in plistlib.load(fh).get("trustList", {}).items()}
    except (OSError, ValueError):
        return None


def _ssl_verdict(settings):
    """True / False for SSL from one domain's settings of a certificate (an empty list means 'trust for everything')."""
    if not settings:
        return True
    ssl = [t for t in settings if t.get("kSecTrustSettingsPolicyName") in SSL_POLICIES]
    if any(t.get("kSecTrustSettingsResult", TRUST_ROOT) == DENY for t in ssl):
        return False
    return any(t.get("kSecTrustSettingsResult", TRUST_ROOT) in (TRUST_ROOT, TRUST_AS_ROOT) for t in ssl)


def _ssl_denied(settings):
    """An admin or user 'Never Trust' for SSL (settings for other policies, e.g. code signing, do not count)."""
    return any(t.get("kSecTrustSettingsPolicyName") in SSL_POLICIES and t.get("kSecTrustSettingsResult", TRUST_ROOT) == DENY
               for t in settings or [])


def system_roots(workdir):
    """Apple's root store as macOS trusts it for SSL: roots the system trust settings list (not, e.g., Apple's
    code-signing-only root), minus any root an admin or the user set to 'Never Trust' for SSL."""
    hashed = HASHED.findall(_security("find-certificate", "-a", "-Z", "-p", SYSTEM_ROOTS).stdout)
    system = _trust_settings("-s", workdir)
    overrides = [d for d in (_trust_settings("-d", workdir), _trust_settings("", workdir)) if d]
    roots = []
    for sha1, pem in hashed:
        if system is not None and (sha1 not in system or not _ssl_verdict(system[sha1])):
            continue
        if any(sha1 in d and _ssl_denied(d[sha1]) for d in overrides):
            continue
        roots.append(pem)
    return roots


def build(out, extras=()):
    with tempfile.TemporaryDirectory() as workdir:
        roots = system_roots(workdir)
        if len(roots) < 20:                   # not macOS, or the root store could not be read: keep mitmproxy's list
            return None
        added = added_anchors(workdir)
    for extra in extras:
        with open(extra) as fh:
            added += PEM.findall(fh.read())
    tmp = out + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(roots + added) + "\n")
    os.replace(tmp, out)
    return len(roots), len(added)


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    try:
        counts = build(argv[1], argv[2:])
    except (OSError, subprocess.SubprocessError) as exc:
        print("system_trust: %s" % exc, file=sys.stderr)
        return 1
    if not counts:
        return 1
    print("%d %d" % counts)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
