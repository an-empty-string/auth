import base64
import json
import os
import random

from . import models, utils, authlib
from .methods import LdapAuthenticator
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, redirect, url_for, request, session, flash, abort

app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY=os.getenv("SECRET", os.urandom(32))
))

@app.before_request
def do_check():
    if "timestamp" in session:
        if session["timestamp"] + timedelta(days=1) < datetime.now():
            session.clear()

    if "token" in session:
        sess = models.LocalSession.get(token=session["token"])
        if not sess.valid:
            session.clear()
            flash("You have been logged out.")

    utils.set_csrf()

@app.route("/")
@utils.require_login
def index():
    sessions = models.Session.select() \
                             .where(models.Session.username == session["user"],
                                    models.Session.signout == False) \
                             .order_by(models.Session.issued.desc())

    grants = models.ServiceGrant.select() \
                                .where(models.ServiceGrant.username == session["user"])

    return render_template("dashboard.html", sessions=sessions, grants=grants)

@app.route("/login/", methods=["GET", "POST"])
@utils.require_csrf
def login():
    if "user" in session:
        flash("You are already logged in.")
        return redirect(url_for("index"))

    if request.method == "GET":
        return render_template("login.html", _next=request.args.get("_next", "/"))

    authenticator = LdapAuthenticator(os.getenv("LDAP_SERVER"), os.getenv("LDAP_DN"), os.getenv("LDAP_PASSWORD"))
    username, password = request.form.get("username", ""), request.form.get("password", "")

    info = authenticator.authenticate(username, password)
    if info:
        session["user"] = info.username
        session["display"] = info.displayname
        session["userid"] = info.userid
        session["groups"] = info.groups
        session["timestamp"] = datetime.now()
        sess = models.LocalSession.create(username=session["user"])
        session["token"] = sess.token

        flash("You are now logged in as {}.".format(info.displayname))
        return utils.redirect_to_next()

    flash("Authentication failed.")
    return render_template("login.html", _next=request.args.get("_next", "/"))

@app.route("/login/xdomain/", methods=["GET", "POST"])
@app.route("/login/xdomain/<domain>/")
@utils.require_csrf
def login_xdomain(domain=None):
    if "user" in session:
        flash("You are already logged in.")
        return redirect(url_for("index"))

    if request.method == "POST":
        domain = request.form.get("domain", "")

    if request.method == "GET":
        if not domain:
            flash("You must specify a domain to authenticate against.")
            return render_template("xdomain.html")

    if domain == utils.netloc(request.url):
        flash("You cannot create a circular cross-domain authentication path.")
        return render_template("xdomain.html")

    if domain is not None and (domain.lower() not in os.getenv("CROSSDOMAIN", "").lower().split(",")):
        flash("That is not an allowed domain.")
        return redirect(url_for("index"))

    auth = authlib.SSOAuthenticator("https://{}".format(domain))
    return redirect(auth.request_url(url_for("verify_xdomain", _next=request.args.get("_next", "/"), _external=True)))

@app.route("/login/xdomain/verify/")
def verify_xdomain():
    if "token" not in request.args or "by" not in request.args:
        abort(400)

    auth = authlib.SSOAuthenticator("https://{}".format(request.args.get("by")))
    token = auth.token(request.args.get("token"), request.url)
    if not token:
        abort(400)

    xdomainize = lambda k: "{}@{}".format(k, request.args.get("by"))
    session["user"] = xdomainize(token["user"]["name"])
    session["display"] = token["user"]["display"]
    session["userid"] = random.randint(10**8, 10**9)
    session["groups"] = list(map(xdomainize, token["user"]["groups"]))
    sess = models.LocalSession.create(username=session["user"])
    session["token"] = sess.token
    return utils.redirect_to_next()

@app.route("/login/kerberos/")
def kerberos_login():
    if os.getenv("KERBEROS", "") == "":
        flash("Kerberos login is not enabled")
        return redirect(url_for("login"))

    authenticator = LdapAuthenticator(os.getenv("LDAP_SERVER"), os.getenv("LDAP_DN"), os.getenv("LDAP_PASSWORD"))
    info = authenticator.authenticate(request.headers.get("REMOTE_USER"), False)
    session["user"] = info.username
    session["display"] = info.displayname
    session["userid"] = info.userid
    session["groups"] = info.groups
    session["timestamp"] = datetime.now()
    sess = models.LocalSession.create(username=session["user"])
    session["token"] = sess.token
    return utils.redirect_to_next()

@app.route("/logout/")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

@app.route("/_/idplogout/")
def idplogout():
    n = models.LocalSession.update(valid=False) \
                           .where(models.LocalSession.token == request.args.get("token", "")) \
                           .execute()

    if not n:
       abort(404)

    return jsonify(ok=True)

@app.route("/logout/full/", methods=["POST"])
@utils.require_csrf
@utils.require_login
def signout_all_sessions():
    sessions = models.Session.select() \
                             .where(models.Session.username == session["user"],
                                    models.Session.signout == False)

    for sess in sessions:
        utils.invalidate_session(sess)

    models.Session.update(signin=True) \
                  .where(models.Session.username == session["user"]) \
                  .execute()

    models.LocalSession.update(valid=False) \
                      .where(models.LocalSession.username == session["user"]) \
                      .execute()

    session.clear()

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
        if "@{}".format(domain) in session["user"]:
            flash("You cannot create a circular cross-domain authentication path.")
            return redirect("/")

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
    return redirect(callback + ("&" if "?" in callback else "?") + "token={}&by={}".format(sess.token, utils.netloc(request.url)))

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
