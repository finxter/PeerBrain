from typing import Union, Optional, List
from fastapi import FastAPI, Path, Query, HTTPException, status
from uuid import UUID, uuid4

#---LOCAL IMPORTS---#
from models import User, Thought
from db import *


app = FastAPI()


@app.get("/")
def read_root():
    raise HTTPException(status_code=405, detail = "Calling on the root page is not allowed!")


@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

@app.get("/my_item")
def my_item():
    return {"Tweet": "This seems to work"}