import requests
import getpass


# Define the endpoint URL
url = "http://127.0.0.1:8000/token"

username = input("Please enter your username: ")
password = getpass.getpass(prompt = "Please enter your password: ")
# Define the payload with the username and password
payload = {"username": username, "password": password}

# Make a POST request to the endpoint with the payload
response = requests.post(url, data=payload)

# Extract the JWT token from the response
jwt_token = response.json()["access_token"]
print()
print("Logged in successfully!")
print()


def get_account_info():
    
    account_url = "http://127.0.0.1:8000/api/v1/me"

# Define the headers with the Authorization token
    headers = {"Authorization": f"Bearer {jwt_token}"}

    # Make a GET request to the protected endpoint with the headers
    response = requests.get(account_url, headers=headers)

    # Extract the response data
    data = response.json()
    print("---YOUR ACCOUNT DETAILS---")
    print()
    print(f"Username : {data['username']}")
    print(f"Email : {data['email']}")



get_account_info()


# class Client:
#     def __init__(self, tracker_url):
#         self.tracker_url = tracker_url
#         self.peers = []

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

# def main():
#     Client("127.0.0.1:8000")

# if __name__ == '__main__':
#     main()