"""This file will containt all the database logic for our server module. It will leverage the Deta Base NoSQL database api."""
from datetime import datetime
import math
from typing import Union
import os
from pprint import pprint #pylint: disable=unused-import
from uuid import uuid4
from deta import Deta
from dotenv import load_dotenv
from passlib.context import CryptContext


#---LOCAL IMPORTS---#
from models import User, Thought

load_dotenv()

#---DB INIT---#
DETA_KEY = os.getenv("DETA_KEY")
deta = Deta(DETA_KEY)

USERS = deta.Base("users")
THOUGHTS = deta.Base("thoughts")

#---PW ENCRYPT INIT---#
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")

#---USER FUNCTIONS---#
def get_user_by_username(username:str)->Union[dict, None]:
    try:
        return USERS.fetch({"username" : username}).items
    except Exception as error_message:
        print(error_message)
        return None

def get_user_by_email(email:str)->Union[dict, None]:
    try:
        return USERS.fetch({"email" : email}).items
    except Exception as error_message:
        print(error_message)
        return None

def get_users()->dict:
    user_dict = {}
    for user in USERS.fetch().items:
        user_dict[user["username"]]=user
    return user_dict

def create_user(username:str, email:str, pw_to_hash:str)->None:

    new_user = {"username" : username,
                "key" : str(uuid4()),
                "hashed_pw" : gen_pw_hash(pw_to_hash), 
                "email" : email,
                "disabled" : False}
    try:
        USERS.put(new_user)
    except Exception as error_message:
        print(error_message)

def gen_pw_hash(pw:str)->str:
    return pwd_context.hash(pw)


#---THOUGHTS FUNCTIONS---#
def update_rating(rating:float)->float:
    rating += math.log(rating+1)
    return rating

def get_thought(query_str:str)->Union[dict, str, None]:
    try:
        thought_list=THOUGHTS.fetch().items
        for thought in thought_list:
            if query_str.lower() in thought["title"].lower():
                return thought
            else:
                return f"No thought found for the search term {query_str}"
    except Exception as error_message:
        print(error_message)
        return None

def get_thoughts(username:str)->Union[dict, None]:
    try:
        return THOUGHTS.fetch({"username" : username}).items
    except Exception as error_message:
        print(error_message)
        return None

def create_thought(username:str, title:str, content:str )->None:
    new_thought = {"username" : username,
                   "key" : str(uuid4()), 
                   "title" : title, 
                   "content" : content,
                   "rating" : 0.0,
                   "creation_date": str(datetime.utcnow())
                   }
    try:
        THOUGHTS.put(new_thought)
    except Exception as error_message:
        print(error_message)
