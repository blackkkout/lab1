from typing import List

from odmantic import Model, EmbeddedModel, Field


class Password(EmbeddedModel):
    value: str
    type: str
    history: List[str]


class User(Model):
    username: str
    password: Password
