from pydantic import BaseModel
from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime

class User(BaseModel):
    username : str
    key : Optional[UUID] = uuid4()
    email : str or None = None
    disabled : bool or None = None

class Thought(BaseModel):
    """Thoughts are Brainwave's equivalent of tweets. Their rating will determine popularity and the likelihood
    they are shown to non-directly connected users. Need to implement an algorithm to estimate peoples interests and how alike they are to 
    do this successfully. They can still downvote it and not see it again."""
    user_id : str
    key : Optional[UUID] = uuid4()
    title : str
    content : str
    #Rating being a float will probably be more efficient as it will be based on a logaritmic function that will flatten as it gets more likes
    rating : Optional[float] = 0.0
    creation_date : Optional[datetime.datetime] 
    
class Token(BaseModel):
    access_token : str
    token_type : str
    
class TokenData(BaseModel):
    username : str or None = None

class UserInDB(User):
    hashed_pw : str