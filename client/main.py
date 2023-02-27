"""Brainwaves cli client file"""
import getpass
import os
import json
import requests
from typing import List
from uuid import uuid4



from encrypt_data import generate_keypair, get_public_key, load_private_key, upload_public_key, detect_private_key, \
    save_private_key, encrypt_message_symmetrical, wrap_encrypt_sym_key, decrypt_message, generate_sym_key, load_sym_key, \
        detect_sym_key

#---VARIABLES---#
login_headers = {"Content-Type": "application/x-www-form-urlencoded"}

#---FUNCTIONS---#
def login(server_url:str)->None:
    """Function that will check first if a token exists. Next it will check the validity 
    if it exists. If it is not valid it will request a new one from
    the server after having request the username and password. 
    If there is no token available it will directly request a new token from the server
    based on the username and password provided."""

    #--> Check if the token.json file exists in the current directory
    if os.path.exists("token.json"):

        #--> Define the headers with the Authorization token
        headers = {"Authorization": f"Bearer {get_token()}"}

        #--> Make a GET request to the protected endpoint with the headers
        response = requests.get(f"{server_url}api/v1/token-test", headers=headers,timeout=10)

        #-->Token is present but no longer valid
        if response.status_code == 401:

            username = input("Please enter your username: ")
            password = getpass.getpass(prompt = "Please enter your password: ")

            # Define the payload with the username and password
            payload = {"username": username, "password": password}
            login_response = requests.post(server_url, data=payload, timeout=10)

            # Extract the JWT token from the response
            jwt_token = login_response.json()["access_token"]

            create_token(jwt_token)
            print()
            print("Logged in successfully!")
            print()

        print()
        print("Logged in with valid token")
        print()

    else:
        #-->No token found, request a new one
        username = input("Please enter your username: ")
        password = getpass.getpass(prompt = "Please enter your password: ")

        # Define the payload with the username and password
        payload = {"username": username, "password": password}
        # Make a POST request to the login endpoint with the payload
        login_response = requests.post(server_url, data=payload, headers=login_headers, timeout=10)

        # Extract the JWT token from the login response
        jwt_token = login_response.json()["access_token"]

        # Set the JWT token in token.json file
        create_token(jwt_token)

        print()
        print("Logged in successfully!")
        print()

def get_token()->str:
    """Function to get the json token from a local json file called token.json"""
    with open("token.json", "r", encoding='utf-8') as file:
        data = json.load(file)
        jwt_token = data["token"]
        return jwt_token

def create_token(jwt_token:str)->None:
    """Function to write the json token to a local json file called token.json"""
    with open("token.json", "w", encoding='utf-8') as file:
        data = {"token": jwt_token}
        json.dump(data, file)

def get_account_info(server_url:str)->None:
    """Function that returns account details for the endpoint specified in the 
    account_url_suffix variable"""
    account_url_suffix = "api/v1/me"
    headers = {"Authorization": f"Bearer {get_token()}"}
    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, timeout=10)
    data = response.json()

    return data['username'], data['email']

def get_all_users(server_url:str)->None:
    """Development function to get all users in the database. Will be deprecated on app release."""
    account_url_suffix = "api/v1/users"

    headers = {"Authorization": f"Bearer {get_token()}"}

    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, timeout=10)
    
        
    data = response.json()


    print("---all users---")
    for key, value in data.items():
        print(key)
        print(value)

def get_user_friends(server_url:str)->None:
    """function to return a list of all user friends."""
    account_url_suffix = "api/v1/friends"

    headers = {"Authorization": f"Bearer {get_token()}"}

    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, timeout=10)

    data = response.json()


    print("---Friends---")
   
    for key, value in data.items():
        print(key)
        print(value)

def add_user_friends(server_url:str, friend_username:str):
    """function to return a list of all user friends."""
    account_url_suffix = "api/v1/friends/"

    headers = {"Authorization": f"Bearer {get_token()}"}
    
    response = requests.post(f"{server_url}{account_url_suffix}{friend_username}", headers=headers, timeout=10)

    data = response.json()
    print("---------------------------")
    print(f"Trying to add {friend_username} as a friend. RESULT : {data}")
    print("---------------------------")

def register_user(server_url:str, username:str, user_email:str, user_password:str, friends:List[str]=[]):
    """function to return a list of all user friends."""
    account_url_suffix = "api/v1/users"

    

    payload = {
    'username': username,
    'email': user_email,
    'user_password': user_password,
    "friends" : friends,
    "disabled" : False
    
    }
    
    print(payload)
    response = requests.post(f"{server_url}{account_url_suffix}", json=payload, timeout=10)

    data = response.json()
    for key, value in data.items():
        print("---------------------------")
        print(f"{key} {value}")
        print("---------------------------")
        
def main():
    """Display the main menu and prompt the user to choose an option."""    
    
    #server_url = "http://127.0.0.1:8000/"
    server_url = "http://143.42.200.202:8080/"
    authenticated = False

    print()
    print("Welcome to version 0.1 of the Brainwaves P2P client!")
    print("-------------------------------------------------------------------")
    print(f"The currently set server url is {server_url}")
    print("-------------------------------------------------------------------")
    print()
    print("Please select what you want to do from the menu below.")

    #MENU SHOWING WHILE WE ARE NOT LOGGED IN OR AUTHENTICATED WITH TOKEN
    if not authenticated:
        while authenticated == False:
            print("1. Log in to the current server.")
            print("2. Register account on the current server")
            print("3. Change server.")
            print("Q to exit")
            choice = input(">> ")
            
            if choice == "1":
                try:
                    login(server_url)
                    authenticated = True
                except KeyError:
                    print("---")
                    print("Username/Password incorrect")
                    print("---")
            elif choice == "2":
                username = input("Enter your username: ")
                user_email = input("Enter your email address: ")
                user_password = getpass.getpass(prompt = "Please enter a password: ")
                confirm_password = getpass.getpass(prompt = "Confirm your password: ")
                if user_password == confirm_password:
                    register_user(server_url, username, user_email, user_password)
                else:
                    print("Passwords do not match!")
            elif choice == "3":
                server_url = input("Please enter a new url: ")
            elif choice == "Q" or choice=="q":
                break
            else:
                print("Invalid choice")    
                
    #MENU SHOWING WHILE WE LOGGED IN OR AUTHENTICATED WITH TOKEN       
    if authenticated:        
        while True:
            
            print("\nMAIN MENU:")
            print()
            print("\nPlease choose an option:")
            print()
            print("1. TECHNICAL ACTIONS")
            print("2. ACCOUNT ACTIONS")
            print("3. LOG OUT")
            print("Q to exit")

            choice = input(">> ")
            
            if choice == "1":
                while True:
                    print("\TECHNICAL MENU:")
                    print()
                    print("\nPlease choose an option:")
                    print()
                    print("1. Get all users.")
                    print("2. Generate SSH Keypair and symmetrical key(needed to create and read messages/tweets)")
                    print("B to return to main menu")
                    
                    sub_choice = input(">> ")
                    
                    if sub_choice == "1":
                        get_all_users(server_url)
                    elif sub_choice == "2":
                        if detect_private_key() and detect_sym_key():
                            print()
                            print("Keys already exist, overwriting them will make your account irretrievable!!")
                            print()
                            print("Key creation canceled!")
                        else:    
                            public_key, private_key = generate_keypair()
                            save_private_key(private_key)
                            upload_public_key(public_key, get_account_info(server_url)[0])
                            generate_sym_key()
                    elif sub_choice == "B" or sub_choice=="b":
                        print("Returning to main menu...")
                        break        
                    else:
                        print("Invalid choice")        
            elif choice == "2":
                while True:
                    print("\ACCOUNT MENU:")
                    print()
                    print("\nPlease choose an option:")
                    print()
                    print("1. Check your account details.")
                    print("2. Create a message")
                    print("3. Add a friend")
                    print("4. Check friends list")
                    print("B to return to main menu")
                    
                    sub_choice = input(">> ")
                    if sub_choice == "1":
                        username, email = get_account_info(server_url)
                        print("---YOUR ACCOUNT DETAILS---")
                        print()
                        print(f"Username : {username}")
                        print(f"Email : {email}")
                    elif sub_choice == "2":
                        print("Message creation function here")
                        pass
                    elif sub_choice == "3":
                        friend_username = input("Enter your friend's username:")
                        add_user_friends(server_url, friend_username)
                    elif sub_choice == "4":
                        get_user_friends(server_url)
                    elif sub_choice == "B" or sub_choice=="b":
                        print("Returning to main menu...")
                        break        
                    else:
                        print("Invalid choice")
            elif choice == "3":
                file_path = "token.json"  
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print("Logged out successfully!")
                    authenticated == False
                    break
                else:
                    print("You are not logged in!")    
            elif choice == "Q" or choice=="q":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

