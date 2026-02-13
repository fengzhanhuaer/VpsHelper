from pathlib import Path

from flask import redirect, render_template, request, url_for

APP = None


def setup(app, _base_dir: Path) -> None:
    global APP
    APP = app


def _require_setup() -> None:
    if APP is None:
        raise RuntimeError("FirewallHelper 未初始化，请先调用 setup(app, base_dir)")


def register_routes(require_login) -> None:
    _require_setup()

    @APP.route("/firewall")
    def firewall():
        token = request.args.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))
        return render_template("firewall.html", username=username, token=token)
