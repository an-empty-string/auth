import base64
import json
import os

from . import models, utils
from .methods import LdapAuthenticator
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, redirect, url_for, request, session, flash

app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY=os.getenv("SECRET", os.urandom(32))
))

@app.before_request
def do_check():
    if "timestamp" in session:
        if session["timestamp"] + timedelta(days=1) < datetime.now():
            session.clear()

    utils.set_csrf()

@app.route("/")
@utils.require_login
def index():
    sessions = models.Session.select() \
                             .where(models.Session.username == session["user"]) \
                             .order_by(models.Session.issued.desc()) \
                             .limit(20)

    grants = models.ServiceGrant.select() \
                                .where(models.ServiceGrant.username == session["user"])

    return render_template("dashboard.html", sessions=sessions, grants=grants)

@app.route("/login/", methods=["GET", "POST"])
@utils.require_csrf
def login():
    if request.method == "GET":
        return render_template("login.html")

    authenticator = LdapAuthenticator(os.getenv("LDAP_SERVER"), os.getenv("LDAP_DN"), os.getenv("LDAP_PASSWORD"))
    username, password = request.form.get("username", ""), request.form.get("password", "")

    info = authenticator.authenticate(username, password)
    if info:
        session["user"] = info.username
        session["display"] = info.displayname
        session["userid"] = info.userid
        session["groups"] = info.groups
        session["timestamp"] = datetime.now()
        flash("You are now logged in as {}.".format(info.displayname))
        return utils.redirect_to_next()

    flash("Authentication failed.")
    return render_template("login.html")

@app.route("/logout/")
def logout():
    if "user" in session:
        session.pop("username")

    flash("Logged out.")
    return redirect(url_for("login"))

@app.route("/logout/full/", methods=["POST"])
@utils.require_csrf
@utils.require_login
def signout_all_sessions():
    sessions = models.Session.select() \
                             .where(models.Session.username == session["user"],
                                    models.Session.signout == True)

    for sess in sessions:
        utils.invalidate_session(sess)

    models.Session.update(signin=True) \
                  .where(models.Session.username == session["user"],
                         models.Session.signin == False) \
                  .execute()

    session.pop("username")

    flash("Globally logged out.")
    return redirect(url_for("index"))

@app.route("/grant/remove/", methods=["POST"])
@utils.require_csrf
@utils.require_login
def remove_grant():
    domain = request.form.get("domain")
    try:
        grant = models.ServiceGrant.get(domain=domain, username=session["user"])
        grant.delete_instance()
        flash("Grant deleted. You'll now need to authorize your next login to {}.".format(domain))
    except models.ServiceGrant.DoesNotExist:
        flash("You don't have a grant for the requested service,")

    return redirect(url_for("index"))

@app.route("/request/<req>/", methods=["GET", "POST"])
@utils.require_csrf
@utils.require_login
def handle_request(req):
    try:
        req = json.loads(base64.urlsafe_b64decode(req).decode())
        callback = req["callback"]
        domain = utils.netloc(callback)
    except:
        abort(400)

    if not domain:
        abort(400)

    if request.method == "GET":
        allow = models.ServiceGrant.select() \
                                   .where(models.ServiceGrant.username == session["user"],
                                          models.ServiceGrant.domain == domain) \
                                   .count()

        if not allow:
            return render_template("check.html", domain=domain)

        add_grant = False

    if request.method == "POST":
        add_grant = request.form.get("grant", False)

    if add_grant:
        models.ServiceGrant.create(username=session["user"], domain=domain)

    existing = models.Session.select() \
                     .where(models.Session.username == session["user"],
                            models.Session.domain == domain,
                            models.Session.signout == False)
    for sess in existing:
        utils.invalidate_session(sess)

    meta = dict(groups=session["groups"], uid=session["userid"], display=session["display"])
    sess = models.Session.create(username=session["user"], domain=domain, meta_json=json.dumps(meta))
    return redirect(callback + ("&" if "?" in callback else "?") + "token=" + sess.token)

@app.route("/session/<token>/")
def token_info(token):
    try:
        session = models.Session.get(token=token)
    except models.Session.DoesNotExist:
        abort(404)

    if session.signin:
        abort(404)

    if session.issued + timedelta(15) < datetime.now():
        abort(404)

    session.signin = True
    session.save()

    user = dict(name=session.username)
    user.update(json.loads(session.meta_json))

    return jsonify(
        id=session.token,
        valid_for=dict(domain=session.domain),
        user=user
    )
