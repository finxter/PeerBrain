"""Below we will define the necessary pydantic models to use in our application."""
from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional
from pydantic import BaseModel #pylint: disable=no-name-in-module

class User(BaseModel): # pylint: disable=too-few-public-methods
    """Class to define the User object for our application. This will get updatet
    and more complex as development continues."""
    username: str
    key: Optional[UUID] = uuid4()
    email: str or None = None
    disabled: bool or None = None

class Thought(BaseModel): # pylint: disable=too-few-public-methods
    """Thoughts are Brainwave's equivalent of tweets. Their rating will determine popularity
    and the likelihood they are shown to non-directly connected users. Need to implement an
    algorithm to estimate peoples interests and how alike they are to do this successfully.
    They can still downvote it and not see it again."""
    username: str
    key: Optional[UUID] = uuid4()
    title: str
    content: str
    rating: Optional[float] = 0.0
    creation_date: Optional[datetime]

class Token(BaseModel): # pylint: disable=too-few-public-methods
    """Class defining our JWT token"""
    access_token: str
    token_type: str

class TokenData(BaseModel): # pylint: disable=too-few-public-methods
    """Helper class for the authentication process."""
    username: str or None = None

class UserInDB(User): # pylint: disable=too-few-public-methods
    """Helper class for the authentication process."""
    hashed_pw: str
