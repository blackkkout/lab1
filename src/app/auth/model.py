from typing import List

from odmantic import Model, EmbeddedModel


class Password(EmbeddedModel):
    value: str
    type: str
    history: List[str]


class User(Model):
    username: str
    password: Password
    access_level: str
