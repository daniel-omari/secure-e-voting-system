# This builds upon the skeleton code file for lab 1. Any instructions that are new have NEW at the beginning of the line.

# Step 1: Import the requests library to send HTTP requests to the server.
# Import libraries for cryptographic operations.
import requests
import json
import os
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64 # For encoding/decoding binary signatures to/from string for JSON

# Step 2: Define the base URL of the server
#   This should match the host and port used in server.py
serverURL = "http://localhost:5000"
privateKeyDir = "private_keys" # Directory where registrar saves private keys
# Client-side known allowed candidates for pre-validation (optional but good for UX)
allowedCandidates = ["Alice", "Bob", "Charlie"]

# Step 3: Write a function that takes as input a voter ID and loads the voter's private key from a PEM file.
#   This key is used to sign the vote before submission.
#   The function should return an error if the voter ID is not an eligible voter.
def loadPrivateVoterKey(voter_id: str) -> Optional[ec.EllipticCurvePrivateKey]:
    privateKeyPath = os.path.join(privateKeyDir, f"{voter_id}_private.pem")
    
    if not os.path.exists(privateKeyPath):
        # The function should return an error if the voter ID is not an eligible voter.
        print(f"Error: Private key file for voter ID '{voter_id}' not found at {privateKeyPath}. Please ensure the voter is registered.")
        return None
    
    try:
        with open(privateKeyPath, "rb") as f:
            raw = f.read()
        private_key = serialization.load_pem_private_key(
            raw,
            password=None,
            backend=default_backend()
        )
        
        return private_key
    
    except ValueError as e:
        print(f"Error: key file for '{voter_id}' appears corrupted or password-protected: {e}")
    return None

# Step 4: Write a function to sign the vote.
#   Your function should take as input a private signing key and a candidate, and should return a signature.
#   Convert signature to hex string for transmission
def createVoteSignature(private_key: ec.EllipticCurvePrivateKey, voter_id: str, candidate_name: str) -> str:
    # The message to be signed must be consistent with what the server expects to verify.
    # It includes the voter_id and candidate_name.
    message = f"{voter_id},{candidate_name}"
    message_bytes = message.encode('utf-8')

    # Sign the message using the provided private key and ECDSA with SHA256.
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    # Convert signature to hex string for transmission (or base64, as used previously for JSON compatibility)
    # Base64 is typically better for binary data in JSON. The previous server example used base64,
    # so let's stick to base64 for consistency in transmission via JSON.
    sign_b64 = base64.b64encode(signature).decode('utf-8')
    return sign_b64

# NEW Step 5: Write a function to get the status of the server.
#   NEW Your function should return the current status, or an error message if the status cannot be retrieved.
def fetchElectionStatus(timeout: float = 3.0) -> Optional[str]:
    try:
        response = requests.get(f"{serverURL}/status", timeout=timeout)
        response.raise_for_status()
        status_data = response.json()
        return status_data.get("status")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure the server is running.")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching status: {e.response.json().get('error', e)}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while fetching status: {e}")
        return None

# Step 6: Write a function to send a vote
#   NEW Your function must first retrieve the status of the election. If the election is not open, or the election status cannot be retrieved, 
#   NEW return an error message
#   Generate a signature using the signing function in step 4.
#   Prepare the headers and JSON payload
#   Include voter ID, candidate name, and signature in the payload.
#   Print the payload for testing purposes.
#   Send a POST request to the /vote endpoint and raise an error if the server responds with a failure code (e.g. 400 or 500)
#   Print the server's response (should be a confirmation message)
def submitVote(voter_id: str, candidate_name: str) -> None:
    elect_status = fetchElectionStatus()
    if elect_status is None:
        print("Error: Could not determine election status. Vote not submitted.")
        return
    if elect_status != "OPEN":
        print(f"Error: Election is {elect_status}. Cannot submit vote when election is not OPEN.")
        return
    
    # Load the private key for the given voter ID.
    private_key = loadPrivateVoterKey(voter_id)
    if private_key is None:
        return

    # Validate candidate on client-side for better UX (optional, server will also validate)
    allowed = {c.lower(): c for c in allowedCandidates}
    chosen_normalized = allowed.get(candidate_name.lower())
    if chosen_normalized is None:
        print(f"Error: Invalid candidate '{candidate_name}'. Allowed candidates are: {', '.join(allowedCandidates)}")
        return

    # Generate a signature using the signing function in step 4.
    signature = createVoteSignature(private_key, voter_id, chosen_normalized)

    headers = {"Content-Type": "application/json"}
    # Include voter ID, candidate name, and signature in the payload.
    payload = {
        "voter_id": voter_id,
        "candidate": chosen_normalized,
        "signature": signature
    }

    # Print the payload for testing purposes.
    print(f"\n--- Sending Vote Payload ---")
    print(json.dumps(payload, indent=2))
    print(f"----------------------------")

    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(f"{serverURL}/vote", headers=headers, json=payload, timeout=5.0)
        response.raise_for_status()  # raise an exception for HTTP errors
        print(f"Server response: {response.json()}")
    except requests.exceptions.HTTPError as e:
        print(f"Error sending vote: {e.response.json().get('error', e)}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure the server is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Step 7: Write a function to fetch current vote results
#   First check the election status. Return the result only if the election status is "closed".
#   Return an error message if status cannot be retrieved or status is "open".
#   Send a GET request to the /results endpoint
#   Print the vote tally in a readable format
def fetchResults() -> None:
    elect_status = fetchElectionStatus()
    if elect_status is None:
        print("Error: Could not retrieve election status.")
        return

    if elect_status != "CLOSED":
        print(f"Error: Election is {elect_status}. Results can only be retrieved when election is CLOSED.")
        return
    
    try:
        response = requests.get(f"{serverURL}/results", timeout=5.0)
        response.raise_for_status()
        results = response.json()

        # Ensure the response is a dictionary
        if not isinstance(results, dict):
            print("\nError: Server response is not a dictionary.")
            print(json.dumps(results, indent=2))
            return

        # Case 1: Tally has been published and is available
        if "tally" in results and results["tally"] is not None:
            print("\n--- Final Election Tally (Published) ---")
            if "message" in results: # Optionally print the message from the server
                print(f"Server Message: {results['message']}")
            for candidate, count in results["tally"].items():
                print(f"- {candidate}: {count} votes")
            print("----------------------------------------")
        
        # Case 2: Election is closed, but tally is NOT yet published (server provides instructions)
        # This condition requires both 'message' AND 'instructions' keys to be present.
        elif "message" in results and "instructions" in results:
            print("\nElection Results Status:")
            print(f"- {results['message']}")
            print(f"- {results['instructions']}")
            print("\nNote: The administrator has not yet published the final tally after reconstruction.")
            
        # Case 3: If neither of the above, it's an unexpected format
        else:
            print("\nUnexpected results format. Server response:")
            print(json.dumps(results, indent=2))

        print("-" * 25)

    except requests.exceptions.HTTPError as e:
        print(f"Error fetching results: {e.response.json().get('error', e)}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure the server is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Step 8: Create a simple command-line interface
#   This lets users type commands to vote or view results
#   The interface should prompt the user for their voter ID before alloing them to vote or view results.
#   The voter ID must match a registered key.
#   If the user types a vote command, extract the candidate name and send the vote
#   If the user types 'results', fetch and display the current tally
#   NEW If the user types 'status', fetch and display the election status.
def main() -> None:
    print("Welcome to the Voting Client!")
    print("Please enter your Voter ID to proceed.")

    voter_id: Optional[str] = None
    while voter_id is None:
        # The voter ID must match a registered key.
        # We'll check if a private key file exists for this ID.
        input_voter_id = input("Enter your Voter ID (e.g., voter_1): ").strip()
        candidate_keyfile = os.path.join(privateKeyDir, f"{input_voter_id}_private.pem")
        if os.path.exists(candidate_keyfile):
            voter_id = input_voter_id
            if loadPrivateVoterKey(voter_id) is None:
                print("Key file exists but could not be loaded. Please check the key file.")
                voter_id = None
            else:
                print(f"Logged in as {voter_id}.")
        else:
            print(f"No private key found for '{input_voter_id}'. Please try again.")

    print(f"\nCommands: 'vote <candidate_name>', 'results', 'exit'")
    while True:

        try:
            command = input(f"\n{voter_id}> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting client.")
            break

        if not command:
            continue
        
        cmd_lower = command.lower()
        if cmd_lower == "exit":
            print("Exiting client.")
            break

        elif cmd_lower == "results":
            fetchResults()

        elif cmd_lower == "status":
            status = fetchElectionStatus()
            if status:
                print(f"Current Election Status: {status}")
            else:
                print("Failed to retrieve election status.")

        elif cmd_lower.startswith("vote "):
            _, candidate_part = command.split(" ", 1)
            candidate = candidate_part.strip()
            if candidate == "":
                print("Invalid vote command. Usage: 'vote <candidate_name>'")
            else:
                submitVote(voter_id, candidate)
        else:
            print("Unknown command. Please use 'vote <candidate_name>', 'results', or 'exit'.")

if __name__ == "__main__":
    main()