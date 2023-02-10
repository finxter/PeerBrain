from typing import Union, Optional, List
from fastapi import FastAPI, Path, Query, HTTPException, status
from uuid import UUID, uuid4

#---LOCAL IMPORTS---#
from models import User, Thought
from db import get_thoughts, get_users, create_user, get_user_by_email, get_user_by_username


app = FastAPI()


@app.get("/")
def read_root():
    raise HTTPException(status_code=405, detail = "Calling on the root page is not allowed!")

@app.get("/users")
async def get_all_users():
    return get_users()

@app.get("/thoughts/{username}")
async def get_thoughts_for_user(username : str):
    return get_thoughts(username)

@app.post("/users")
async def register_user(user : User):
    username  = user.username
    email = user.email
    
    if get_user_by_email(email) or get_user_by_username(username):
        raise HTTPException(status_code=400, detail="A user with that username/email already exists.")
    create_user(username, email)
    return {"Account creation" : "Successful"}