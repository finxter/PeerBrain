"""Brainwaves cli client file"""
import getpass
import os
import json
import requests

from encrypt_data import generate_keypair, get_public_key, load_private_key, upload_public_key, detect_private_key, \
    save_private_key, encrypt_message_symmetrical, wrap_encrypt_sym_key, decrypt_message

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

    print("---YOUR ACCOUNT DETAILS---")
    print()
    print(f"Username : {data['username']}")
    print(f"Email : {data['email']}")

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



def main():
    """Display the main menu and prompt the user to choose an option."""    
    server_url = "http://127.0.0.1:8000/"

    print()
    print("Welcome to version 0.1 of the Brainwaves P2P client!")
    print()
    print(f"The currently set server url is {server_url}")
    print()
    # if get_token():
    #     print("There is a token available.")
    # else:
    #     print("No token found, please login first.")
    print()
    print("Please select what you want to do from the menu below.")

    while True:
        print("\nPlease choose an option:")
        print()
        print("1. Log in to the current server.")
        print("2. Check your account details.")
        print("3. Change server.")
        print("4. Get all users.")
        print("5. Exit")

        choice = input(">> ")
        if choice == "1":
            login(server_url)
        elif choice == "2":
            get_account_info(server_url)
        elif choice == "3":
            server_url = input("Please enter a new url: ")
        elif choice == "4":
            get_all_users(server_url)
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


#     def register_presence(self, messages):
#         """ Register the client's presence with the tracker and the messages it has available """
#         response = requests.post(f'{self.tracker_url}/register', json={'messages': messages})
#         response.raise_for_status()

#     def request_peers(self, message_id):
#         """ Request information about peers that have a specific message """
#         response = requests.get(f'{self.tracker_url}/peers/{message_id}')
#         response.raise_for_status()
#         self.peers = response.json()['peers']

#     def download_message(self, message_id):
#         """ Download a message from a peer """
#         for peer in self.peers:
#             try:
#                 response = requests.get(f'{peer}/messages/{message_id}')
#                 if response.status_code == 200:
#                     return response.text
#             except requests.RequestException:
#                 continue
#         raise Exception(f"Message {message_id} not found on any peers")
