import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Constants for file names and directories
PUBLIC_KEYS_DB_FILE = "public_keys.json"
privateKeyDir = "private_keys"

# Ensure the private keys directory exists
if not os.path.exists(privateKeyDir):
    os.makedirs(privateKeyDir)

# Generate an ECDSA (SECP256R1) key pair for a voter: save the private key
# locally as PEM and return the public key as a PEM string for the public DB.
def generate_key_pair(voter_id_prefix):
    # Generate a new ECDSA private key using the SECP256R1 curve
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )

    # Serialize and save the private key to a PEM file (no encryption)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    privateKeyPath = os.path.join(privateKeyDir, f"{voter_id_prefix}_private.pem")
    with open(privateKeyPath, "wb") as f:
        f.write(private_pem)
    print(f"Private key for voter {voter_id_prefix} saved to {privateKeyPath}")

    # Serialize the public key to a PEM string (used by the server for signature verification)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8') # Decode to string for JSON storage

    return public_pem


# Prompt for a voter count, generate a key pair for each, and write/update
# the public-key database on disk.
def main():
    print("Welcome to the Registrar Key Generation Tool!")

    # Ask the user how many voters to register
    num_voters_str = input("How many voters do you want to register? ")
    try:
        num_voters = int(num_voters_str)
        if num_voters <= 0:
            print("Please enter a positive number of voters.")
            return
    except ValueError:
        print("Invalid input. Please enter a number.")
        return

    # Load existing public key database if it exists, or start a new one
    public_keys_db = {}
    if os.path.exists(PUBLIC_KEYS_DB_FILE):
        with open(PUBLIC_KEYS_DB_FILE, "r") as f:
            try:
                public_keys_db = json.load(f)
                print(f"Loaded existing public key database from {PUBLIC_KEYS_DB_FILE}")
            except json.JSONDecodeError:
                print(f"Warning: {PUBLIC_KEYS_DB_FILE} is corrupted or empty. Starting new database.")
                public_keys_db = {}
    else:
        print("No existing public key database found. Creating a new one.")

    # Generate key pairs for each voter and update the public key database
    for i in range(num_voters):
        voter_id_prefix = f"voter_{i+1}" # Simple voter ID scheme
        if voter_id_prefix in public_keys_db:
            print(f"Voter ID {voter_id_prefix} already exists. Overwriting its key pair.")

        public_pem = generate_key_pair(voter_id_prefix)
        public_keys_db[voter_id_prefix] = public_pem
        # The print statement is already inside generate_key_pair

    # Save the updated public key database to disk
    with open(PUBLIC_KEYS_DB_FILE, "w") as f:
        json.dump(public_keys_db, f, indent=4)
    print(f"Updated public key database saved to {PUBLIC_KEYS_DB_FILE}")
    print("Registration complete.")

if __name__ == '__main__':
    main()

# --- END OF FILE registrar.py ---