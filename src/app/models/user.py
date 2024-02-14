from odmantic import Model, EmbeddedModel, Field


class UserPassword(EmbeddedModel):
    value: str
    type: str
    history: list = []


class User(Model):
    username: str = Field(unique=True)
    password: UserPassword
