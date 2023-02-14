from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256

# Step 1: User Login
def user_login(username, password):
    # Hash the password
    hashed_password = SHA256.new(password.encode()).hexdigest()
    # Check if the username and hashed password match what is stored in the database
    # Return True if the login is successful, False otherwise
    # For the purposes of this example, we will assume the login is successful
    return True

# Step 2: Key Generation
def generate_key_pair():
    # Generate a RSA key pair
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    # Return the keys
    return private_key.export_key(), public_key.export_key()

# Define the default public key
default_public_key = RSA.generate(2048).publickey().export_key()

# Step 3: Message Encryption
def encrypt_message(message, recipient_public_key=default_public_key):
    # Deserialize the recipient's public key
    recipient_public_key = RSA.import_key(recipient_public_key)
    # Encrypt the message using the recipient's public key
    cipher = PKCS1_OAEP.new(recipient_public_key)
    ciphertext = cipher.encrypt(message.encode())
    # Return the encrypted message
    return ciphertext



# Step 4: Message Signing
def sign_message(message, sender_private_key):
    # Deserialize the sender's private key
    sender_private_key = RSA.import_key(sender_private_key)
    # Sign the message using the sender's private key
    signer = pkcs1_15.new(sender_private_key)
    signature = signer.sign(SHA256.new(message.encode()))
    # Return the signature
    return signature

# Prompt for username and password
username = input("Enter your username: ")
password = input("Enter your password: ")

# Check if the login is successful
if user_login(username, password):
    print("Login successful!")
    # Generate the key pair
    private_key, public_key = generate_key_pair()
    print("Key pair generated:")
    print("Private key:", private_key.decode())
    print("Public key:", public_key.decode())
    # Prompt the user for the message and recipient's public key
    message = input("Enter the message you would like to encrypt: ")
    recipient_public_key = input("Enter the recipient's public key (press enter to use the default key): ").encode()
    if recipient_public_key == b"":
        recipient_public_key = default_public_key
    # Encrypt the message
    ciphertext = encrypt_message(message, recipient_public_key)
    print("Message encrypted:", ciphertext)
    # Sign the message
    signature = sign_message(message, private_key)
    print("Message signed:", signature)
    print("\nMessage sent successfully!")
else:
    print("Login failed.")