from collections import namedtuple
from ldap3 import Tls, Server, Connection
from ldap3.utils.dn import parse_dn
import logging
import re

UserInfo = namedtuple("UserInfo", ["username", "displayname", "userid", "groups"])

class Authenticator(object):
    def authenticate(username, password):
        return True

class LdapAuthenticator(Authenticator):
    user_regex = re.compile("^[A-Za-z0-9.]+$")
    logger = logging.getLogger("app.methods.LdapAuthenticator")

    def __init__(self, server, bind_dn, bind_pw, search_base="dc=fwilson,dc=me"):
        self.server = server
        self.bind_dn = bind_dn
        self.bind_pw = bind_pw
        self.search_base = search_base

    def authenticate(self, username, password):
        if not self.user_regex.match(username):
            self.logger.info("Username {} did not match username regex, aborting".format(username))
            return False

        tls = Tls("/etc/openldap/cert.pem")
        server = Server(self.server, 636, tls)
        conn = Connection(server, self.bind_dn, self.bind_pw, auto_bind=True)

        try:
            conn.open()
        except:
            self.logger.critical("Failed to connect to LDAP server")
            return False

        if not conn.bind():
            self.logger.critical("Failed to bind to LDAP server")
            return False

        result = conn.search(self.search_base,
                             "(&(objectClass=posixAccount)(uid={}))".format(username),
                             attributes=["cn", "uidNumber", "memberOf"])

        if not result:
            self.logger.info("Could not find user {}".format(username))
            return False

        user = conn.entries[0]
        self.logger.info("Found user {}".format(user.entry_dn))

        if not conn.rebind(user.entry_dn, password):
            self.logger.info("Failed to authenticate {}".format(username))
            return False

        displayname = user.cn.value
        userid = int(user.uidNumber.value)
        groups = [parse_dn(i)[0][1] for i in user.memberOf]
        self.logger.info("Authenticated {} as {} ({}) groups={}".format(username, displayname, userid, groups))
        return UserInfo(username=username, displayname=displayname, userid=userid,
                        groups=groups)

DefaultAuthenticator = LdapAuthenticator
