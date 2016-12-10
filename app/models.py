from . import utils
from datetime import datetime, timedelta
from peewee import *
import os
import playhouse.db_url

database = playhouse.db_url.connect(os.getenv("DATABASE", "sqlite:///auth.db"))

class BaseModel(Model):
    class Meta:
        database = database

class Session(BaseModel):
    username = CharField(64)
    domain = CharField(64)
    meta_json = CharField(4096)

    signin = BooleanField(default=False)
    signout = BooleanField(default=False)
    token = CharField(32, default=utils.random_string)
    issued = DateTimeField(default=datetime.now)

class ServiceGrant(BaseModel):
    username = CharField(64)
    domain = CharField(64)

Session.create_table(True)
ServiceGrant.create_table(True)
