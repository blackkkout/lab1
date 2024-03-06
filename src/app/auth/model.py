from typing import List

from odmantic import Model, EmbeddedModel
from bson import ObjectId, Binary


class Password(EmbeddedModel):
    value: str
    type: str
    history: List[str]


class User(Model):
    username: str
    password: Password
    access_level: str


class Resource(Model):
    access_level: str
    filename: str
    content: Binary
    userId: ObjectId
