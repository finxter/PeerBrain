import requests

class Client:
    def __init__(self, tracker_url):
        self.tracker_url = tracker_url
        self.peers = []

    def register_presence(self, messages):
        """ Register the client's presence with the tracker and the messages it has available """
        response = requests.post(f'{self.tracker_url}/register', json={'messages': messages})
        response.raise_for_status()

    def request_peers(self, message_id):
        """ Request information about peers that have a specific message """
        response = requests.get(f'{self.tracker_url}/peers/{message_id}')
        response.raise_for_status()
        self.peers = response.json()['peers']

    def download_message(self, message_id):
        """ Download a message from a peer """
        for peer in self.peers:
            try:
                response = requests.get(f'{peer}/messages/{message_id}')
                if response.status_code == 200:
                    return response.text
            except requests.RequestException:
                continue
        raise Exception(f"Message {message_id} not found on any peers")

def main():
    Client("127.0.0.1:8000")

if __name__ == '__main__':
    main()