from pydantic import BaseModel
from uuid import UUID, uuid4


class User(BaseModel):
    username : str
    email : str

class Thought(BaseModel):
    """Thoughts are Brainwave's equivalent of tweets. Their rating will determine popularity and the likelihood
    they are shown to non-directly connected users. Need to implement an algorithm to estimate peoples interests and how alike they are to 
    do this successfully. They can still downvote it and not see it again."""
    user_id : str
    key : str
    title : str
    content : str
    #Rating being a float will probably be more efficient as it will be based on a logaritmic function that will flatten as it gets more likes
    rating : float
      