"""Load mitmweb's password from a private file so the secret never appears in argv."""
import os

from mitmproxy import ctx, exceptions


class RivisWebAuth:
    def load(self, loader):
        loader.add_option("proxy_auth_token_file", str, "", "0600 file containing the mitmweb password")

    def configure(self, updated):
        if "proxy_auth_token_file" not in updated or not ctx.options.proxy_auth_token_file:
            return
        path = os.path.expanduser(ctx.options.proxy_auth_token_file)
        try:
            with open(path) as fh:
                token = fh.read().strip()
        except OSError as exc:
            raise exceptions.OptionsError(f"cannot read UI password file {path}: {exc}") from exc
        if not token:
            raise exceptions.OptionsError(f"UI password file {path} is empty")
        if len(token) < 16:   # a user-chosen RIVIS_WEB_PASSWORD; the generated one is 32 hex characters
            ctx.log.warn("the UI password is shorter than 16 characters; anyone on this Mac who guesses it controls the proxy")
        ctx.options.update(web_password=token)


addons = [RivisWebAuth()]
