"""This file will containt all the database logic for our server module. It will leverage the Deta Base NoSQL database api."""
from datetime import datetime
import math
from typing import Union
import os
import logging
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
KEYS = deta.Base("keys_db")

#---PW ENCRYPT INIT---#
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")

#---USER FUNCTIONS---#
def gen_pw_hash(pw:str)->str:
    return pwd_context.hash(pw)


def get_users()->dict:
    user_dict = {}
    for user in USERS.fetch().items:
        user_dict[user["username"]]=user
    return user_dict

def get_user_by_username(username:str)->Union[dict, None]:
    try:
        if (USERS.fetch({"username" : username}).items) == []:
            return {"Username" : "No user with username found"}
        else:
            return USERS.fetch({"username" : username}).items[0]
    except Exception as error_message:
        logging.exception(error_message)
        return None


def get_user_by_email(email:str)->Union[dict, None]:
    try:
        if (USERS.fetch({"email" : email}).items) == []:
            return {"Email" : "No user with email found"}
        else:
            return USERS.fetch({"email" : email}).items[0]
    except Exception as error_message:
        logging.exception(error_message)
        return None
    
def get_friends_by_username(username:str)->Union[dict, None]:
    friends_list =[]
    try:
        friends_list = USERS.fetch({"username" : username}).items[0]["friends"]
        friends_dict = {}
        for friend in friends_list:
            user = get_user_by_username(friend)
            friends_dict[user['username']] = {"email":user['email']}
        return friends_dict    
    except Exception as error_message:
        logging.exception(error_message)
        return None
    
def add_friend(username, friend_username):
    update= {"friends": USERS.util.append(friend_username) }
    
    try:
        user = get_user_by_username(username)
        user_key = user["key"]
        if not friend_username in get_users():
            return {"Username" : "Not Found"}
        elif username == friend_username:
            return{"Username" : "You can't add yourself as a friend!"}
        elif friend_username in user["friends"]:
            return {"Username" : "Already a friend!"}
        else:
            
            return USERS.update(update, user_key), f"User {friend_username} added as a friend successfully!"
    except Exception as error_message:
        logging.exception(error_message)
        return None
    
    
def change_password(username, pw_to_hash):
    hashed_pw = gen_pw_hash(pw_to_hash)
    update= {"hashed_pw": hashed_pw }
    
    try:
        user = get_user_by_username(username)
        user_key = user["key"]
        if not username in get_users():
            return {"Username" : "Not Found"}
        else:
            
            return USERS.update(update, user_key), f"User {username} password changed!"
    except Exception as error_message:
        logging.exception(error_message)
        return None       
    

def create_user(username:str, email:str, pw_to_hash:str)->None:

    new_user = {"username" : username,
                "key" : str(uuid4()),
                "hashed_pw" : gen_pw_hash(pw_to_hash), 
                "email" : email,
                "friends" : [],
                "disabled" : False}
    try:
        print(gen_pw_hash(pw_to_hash))
        USERS.put(new_user)
    except Exception as error_message:
        logging.exception(error_message)


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
        logging.exception(error_message)
        return None

def get_thoughts(username:str)->Union[dict, None]:
    try:
        return THOUGHTS.fetch({"username" : username}).items
    except Exception as error_message:
        logging.exception(error_message)
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
        logging.exception(error_message)


#get the public key from the cloud
def get_public_key(username:str)->Union[bytes, None]:
    try:
        retrieved_key = KEYS.get(f"{username}")["public key"]
        new_public_key = retrieved_key.encode("utf-8")
        return new_public_key
    except Exception as error_message:
        print(error_message)
        return None


def upload_public_key(public_key:bytes, username:str)->Union[bool, None]:
    #public_key_str = public_key.decode("utf-8")
    pub_key = {"key" : username, 
               "public key" : public_key}
    try:
        KEYS.put(pub_key)
    except Exception as error_message:
        logging.exception(error_message)
        
    try:
        retrieved_key = get_public_key(username)
        print(type(retrieved_key))
        print(type(public_key))
        if public_key.encode('utf-8')==retrieved_key:
            print("Public key uploaded succesfully")
            return True
        else:
            print("Public key upload corrupted, please try again!")
            return False
    except Exception as error_message:
        logging.exception(error_message)
        return None