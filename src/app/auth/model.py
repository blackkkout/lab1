from typing import List

from odmantic import Model, EmbeddedModel, Field


class Password(EmbeddedModel):
    value: str
    type: str
    history: List[str] = Field(default_factory=list)


class User(Model):
    username: str
    password: Password
