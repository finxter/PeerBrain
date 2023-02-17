import os
from dotenv import load_dotenv
from deta import Deta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



load_dotenv()

DETA_KEY = os.getenv("DETA_KEY")
deta = Deta(DETA_KEY)

KEYS = deta.Base("keys_db")

# Generate a new RSA key pair for a client
def generate_keypair()->tuple:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_key, private_key

#get the public key from the cloud
def get_public_key(username:str)->Union[bytes, None]:
    try:
        retrieved_key = KEYS.get(f"{username}")["public key"]
        new_public_key = retrieved_key.encode("utf-8")
        return new_public_key
    except Exception as error_message:
        print(error_message)
        return None
    
#Upload public key to cloud
def upload_public_key(public_key:bytes, username:str)->Union[bool, None]:
    public_key_str = public_key.decode("utf-8")
    pub_key = {"key" : username, 
               "public key" : public_key_str}
    try:
        KEYS.put(pub_key)
    except Exception as error_message:
        print(error_message)
        
    try:
        retrieved_key = get_public_key(username)
        if public_key==retrieved_key:
            print("Public key uploaded succesfully")
            return True
        else:
            print("Public key upload corrupted, please try again!")
            return False
    except Exception as error_message:
        print(error_message)
        return None

#Detect if a private key is available on your system        
def detect_private_key()->bool:
    if os.path.exists("private_key.pem"):
        print("Found local private key.")
        return True
    else:
        print("No local private key found.")
        return False
    
#Load your private key after checking if one is available on your system    
def load_private_key():
    if detect_private_key:
        with open('private_key.pem', 'rb') as f:
            key_data = f.read()
            key = serialization.load_pem_private_key(
            key_data,
            password=None)
            private_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
                )
            return private_key
    
#Save private key to local storage
def save_private_key(private_key)->None:
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)
        
    reloaded_key = load_private_key()
    if private_key == reloaded_key:
        print("Private key saved successfully")
    else:
        print("Private key not saved successfully, please try again!")

def encrypt_message_symmetrical(message:str)->bytes:
    # Generate a random symmetric encryption key
    symmetric_key = Fernet.generate_key()
    # Create a Fernet object using the key
    fernet = Fernet(symmetric_key)
    # Encrypt the text string
    encrypted_text = fernet.encrypt(message.encode())
    return symmetric_key, encrypted_text


def wrap_encrypt_sym_key(sym_key:bytes, username:str):
    """Function to prepare the public key to encrypt the symmetric key, and then encrypt it"""
    public_key = serialization.load_pem_public_key(get_public_key(username))
    # Encrypt the symmetric key with the client's public key
    encrypted_sim_key = public_key.encrypt(sym_key,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return encrypted_sim_key

def decrypt_message(encrypted_message, encryption_sim_key):
    private_key = serialization.load_pem_private_key(
    load_private_key(), password=None)

    # Decrypt the encrypted key using the private key
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    # Create a Fernet object with the symmetric key
    fernet = Fernet(decrypted_key)

    # Decrypt the encrypted message
    decrypted_message = fernet.decrypt(encrypt_message)

    # Decode the decrypted message bytes to string
    decrypted_message = decrypted_message.decode()

    # Print the decrypted message
    print(decrypted_message)
    return decrypted_message

# private_key_test = load_private_key()
# public_key_test = get_public_key("tom")


#print(encrypt_message_symmetrical("this is a testmessage"))





