import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



load_dotenv()

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

#Detect if a private key is available on your system        
def detect_private_key()->bool:
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')):
        print("Found local private key.")
        return True
    else:
        print("No local private key found.")
        return False
    
#Load your private key after checking if one is available on your system    
def load_private_key():
    if detect_private_key:
        key_path = os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')
        with open(key_path, 'rb') as f:
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
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')
    with open(key_path, 'wb') as f:
        f.write(private_key)
        
    reloaded_key = load_private_key()
    if private_key == reloaded_key:
        print("Private key saved successfully")
    else:
        print("Private key not saved successfully, please try again!")

def encrypt_message_symmetrical(message:str)-> bytes:
    try:
        symmetric_key = load_symmetric_key()
        # Create a Fernet object using the key
        fernet = Fernet(symmetric_key)
        # Encrypt the text string
        encrypted_text = fernet.encrypt(message.encode())
        return symmetric_key, encrypted_text
    except Exception as error_message:
        logging.exception(error_message)

def wrap_encrypt_sym_key(sym_key:bytes, username:str)->Union[str, bytes]:
    """Function to prepare the public key to encrypt the symmetric key, and then encrypt it"""
    public_key = serialization.load_pem_public_key(get_public_key(username))#==To change to use the endpoint, drop the username
    # Encrypt the symmetric key with the client's public key
    encrypted_sim_key = public_key.encrypt(sym_key,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return username, encrypted_sim_key

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

def load_sym_key()->bytes:
     # Load the key from a file
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'message.key')
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
        return key

def generate_sym_key()->None:
    # Generate a symmetric key
    key = Fernet.generate_key()

    # Save the key to a file
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'message.key')
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

    if load_sym_key() == key:
        print("Symmetric key saved successfully")
    else:
        print("Symmetric key not saved successfully, please try again!")
    
def detect_sym_key()->bool:
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'keys', 'message.key')):
        print("Found local sym key.")
        return True
    else:
        print("No local private sym found.")
        return False




    




