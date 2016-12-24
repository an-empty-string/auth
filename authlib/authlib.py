import base64
import json
import requests
import urllib.parse
import warnings

class SSOAuthenticator:
    def __init__(self, server):
        self.server = server.strip("/")
        if not self.server.startswith("https://"):
            warnings.warn("SSOAuthenticator was not initialized with a secure endpoint")

    def request_url(self, callback):
        req = json.dumps(dict(callback=callback)).encode()
        return "{}/request/{}/".format(self.server, base64.urlsafe_b64encode(req).decode())

    def token(self, token, url):
        req = requests.get("{}/session/{}/".format(self.server, token))
        if req.status_code != 200:
            return False

        token = req.json()
        if token["valid_for"]["domain"] != urllib.parse.urlparse(url).netloc:
            return False

        return token
