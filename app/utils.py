from flask import abort, flash, redirect, request, session, url_for
from functools import wraps
import random
import requests
import string
import urllib.parse

def safe_redirect(to):
    our_netloc = netloc(request.url)
    their_netloc = netloc(to)
    if not their_netloc or our_netloc == their_netloc:
        return redirect(to)
    return redirect("/")

def redirect_to_next():
    if "_next" in request.args:
        return safe_redirect(request.args.get("_next"))
    return redirect("/")

def random_string(n=32, allowed=(string.ascii_letters + string.digits)):
    return "".join(random.choice(allowed) for i in range(n))

def set_csrf():
    if "csrf" not in session:
        session["csrf"] = random_string()

def require_csrf(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if request.method == "GET":
            return f(*args, **kwargs)

        if request.form.get("csrf", "") == session.get("csrf", ""):
            return f(*args, **kwargs)

        abort(403)
    return wrapped

def require_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user" in session:
            return f(*args, **kwargs)
        flash("You need to log in first.")
        return redirect(url_for("login", _next=request.url))
    return wrapped

def netloc(url):
    return urllib.parse.urlparse(url).netloc

def invalidate_session(session):
    req = requests,get("http//{}/_/idplogout/".format(session.domain), dict(token=session.token))
    if req.status_code == 200:
        session.signin = True
        session.signout = True
        session.save()
        return True

    return False
