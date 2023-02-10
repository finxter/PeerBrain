from deta import Deta
from pprint import pprint
from uuid import UUID, uuid4
from dotenv import load_dotenv
import os
import json


#---LOCAL IMPORTS---#
from models import User, Thought

load_dotenv()

#---DB INIT---#
DETA_KEY = os.getenv("DETA_KEY")
deta = Deta(DETA_KEY)

USERS = deta.Base("users")
THOUGHTS = deta.Base("thoughts")

#---USER FUNCTIONS---#
def get_user_by_username(username:str)->dict:
    try:
        return USERS.fetch({"username" : username}).items  
    except Exception as e:
        print(e)
      
def get_user_by_email(email:str)->dict:
    try:
        return USERS.fetch({"email" : email}).items  
    except Exception as e:
        print(e)
        
def create_user(username:str, email:str)->None:
    if not get_user_by_email(email) or not get_user_by_username(username):
        new_user = User(username = username, key = str(uuid4()), email = email)
        new_user_dict = new_user.dict()
        
        try:
            USERS.put(new_user_dict)
        except Exception as e:
            print(e)
    else:
        return "A user with that username/email already exists!"

#---THOUGHTS FUNCTIONS---#
def get_thoughts(username:str)->dict:
    user_id = get_user_by_username(username)[0]["key"]
    try:
        return THOUGHTS.fetch({"user_id" : user_id}).items  
    except Exception as e:
        print(e)

def create_thought(user_id:str, title:str, content:str )->None:
    new_thought = Thought(user_id = user_id, key = str(uuid4()), title = title, content = content, rating = 0.0)
    new_thought_dict = new_thought.dict()
    
    try:
        THOUGHTS.put(new_thought_dict)
    except Exception as e:
        print(e)
        
 
#create_thought("177ccd28-1194-4889-a20e-ffd159ff9557", "testtweet2", "Second try at creating a tweet, this should prove very interesting. How fun!")              
print(get_thoughts("testuser"))
#print(get_user_by_email("tom.teck@gmail.com"))