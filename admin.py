# Step 1: Import modules for command-line arguments, JSON handling and HTTP requests.
import sys
import json
import urllib.request
from urllib.error import HTTPError, URLError
from shamir import reconstruct, next_probable_prime_at_least, Share

# Step 2: Define the server base URL that the script will contact. 
# You should send requests to port 5000 on local host.
SERVER_BASE_URL = "http://127.0.0.1:5000"

TALLY_N_SHARES = 5
TALLY_THRESHOLD = 3
TALLY_SHAMIR_PRIME = next_probable_prime_at_least(1000)

# Step 3: Define a function that takes as input a path and sends an empty post request.
#   Define the full URL as the server_url (defined in step 1) and the path input to the function. 
#   Create a Request object with method="POST", an empty JSON body, and Content-Type header
#   Open the URL and print the parsed JSON response
#   In the event of a HTTP Error, attempt to parse and print the JSON error body; otherwise display the HTTP code
#   In the event of other exceptions, your function should print a failure message.
def send_post_request(path):
    full_url = SERVER_BASE_URL + path
    
    try:
        data = json.dumps({}).encode('utf-8')
        req = urllib.request.Request(
            full_url,
            data=data,
            method="POST",
            headers={ 'Content-Type': 'application/json' }
        )
        
        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode('utf-8')
            print(json.loads(response_body))
    
    except HTTPError as e:
        print(f"HTTP Error: {e.code}")
        
        try:
            error_body = e.read().decode('utf-8')
            print(json.loads(error_body))
        
        except json.JSONDecodeError:
            print("Could not parse error response as JSON.")
    
    except URLError as e:
        print(f"Network Error: {e.reason}")
    
    except Exception as e:
        print(f"An unexpected error occured: {e}")
        print ("Failed to send POST request.")

# Step 4: Define a function that fetches the server status.
#   Your function should open the /status endpoint and print the parsed JSON response.
#   In the event of an exception, your function should print a failure message.
def fetch_status():
    status_url = SERVER_BASE_URL + "/status"
    try:
        with urllib.request.urlopen(status_url) as response:
            response_body = response.read().decode('utf-8')
            parsed_json = json.loads(response_body)
            print(parsed_json)
            return parsed_json
    
    except HTTPError as e:
        print(f"HTTP Error: {e.code}")
        
        try:
            error_body = e.read().decode('utf-8')
            print(json.loads(error_body))
        
        except json.JSONDecodeError:
            print("Could not parse error response as JSON.")
    
    except URLError as e:
        print(f"Network Error: {e.reason}")
    
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("Failed to fetch status.")
    
    return None

def publish_tally(reconstructed_tally):
    publish_url = SERVER_BASE_URL + "/publish_tally"
    headers = {'Content-Type': 'application/json'}
    try:
        data = json.dumps(reconstructed_tally).encode('utf-8')
        req = urllib.request.Request(
            publish_url,
            data=data,
            method="POST",
            headers=headers
        )
        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode('utf-8')
            print("\n--- Tally Publication Response ---")
            print(json.loads(response_body))
            print("----------------------------------")
    except HTTPError as e:
        print(f"\nHTTP Error publishing tally: {e.code}")
        try:
            error_body = e.read().decode('utf-8')
            print(json.loads(error_body))
        except json.JSONDecodeError:
            print("Could not parse error response as JSON.")
    except URLError as e:
        print(f"\nNetwork Error publishing tally: {e.reason}")
    except Exception as e:
        print(f"\nAn unexpected error occurred while publishing tally: {e}")
        print("Failed to publish tally.")

def get_tally_shares(share_id: int):
    share_url = f"{SERVER_BASE_URL}/get_tally_shares?share_id={share_id}"
    
    try:
        with urllib.request.urlopen(share_url) as response:
            response_body = response.read().decode('utf-8')
            return json.loads(response_body)
        
    except HTTPError as e:
        print(f"HTTP Error fetching share {share_id}: {e.code}")
        
        try:
            error_body = e.read().decode('utf-8')
            print(json.loads(error_body))
        
        except json.JSONDecodeError:
            print("Could not parse error response as JSON.")

    except URLError as e:
        print(f"Network Error fetching share {share_id}: {e.reason}")
    
    except Exception as e:
        print(f"An unexpected error occured fetching share {share_id}: {e}")
    
    return None

# Tally reconstruction function
def reconstruct_tally_from_shares():
    status_response = fetch_status()
    if status_response is None or status_response.get("status") != "CLOSED":
        print("Error: Election must be CLOSED to reconstruct the tally.")
        return

    print(f"\n--- Reconstructing Tally (requires {TALLY_THRESHOLD} of {TALLY_N_SHARES} shares) ---")
    
    available_share_ids = list(range(1, TALLY_N_SHARES + 1))
    chosen_ids_str = input(f"Enter {TALLY_THRESHOLD} or more share IDs (1-{TALLY_N_SHARES}) separated by commas (e.g., 1,2,{TALLY_THRESHOLD}): ").strip()

    try:
        chosen_ids = sorted(list(set([int(x.strip()) for x in chosen_ids_str.split(',') if x.strip()])))
    except ValueError:
        print("Invalid input: Share IDs must be integers.")
        return

    if len(chosen_ids) < TALLY_THRESHOLD:
        print(f"Error: You must provide at least {TALLY_THRESHOLD} share IDs for reconstruction.")
        return

    for share_id in chosen_ids:
        if share_id not in available_share_ids:
            print(f"Error: Share ID {share_id} is out of valid range (1-{TALLY_N_SHARES}).")
            return

    # Dictionary to hold the collected shares for each candidate
    collected_candidate_shares = {candidate: [] for candidate in ["Alice", "Bob", "Charlie"]}

    print(f"Attempting to retrieve shares for IDs: {chosen_ids}")
    for share_id in chosen_ids:
        response_data = get_tally_shares(share_id)
        if response_data and "candidate_tally_shares" in response_data:
            print(f" Successfully retrieved share {share_id}.")
            for candidate, share_value in response_data["candidate_tally_shares"].items():
                collected_candidate_shares[candidate].append((share_id, share_value))
            
        else:
            print(f" Failed to retrieve share {share_id}. Aborting reconstruction.")
            return
    
    reconstructed_tally = {}
    print("\n--- Reconstructed Final Tally ---")
    for candidate, shares_list in collected_candidate_shares.items():
        if len(shares_list) < TALLY_THRESHOLD:
            print(f"Error: Not enough shares collected for candidate {candidate} to reconstruct tally.")
            continue

        try:
            reconstructed_count = reconstruct(shares_list, TALLY_SHAMIR_PRIME)
            reconstructed_tally[candidate] = reconstructed_count
            print(f"- {candidate}: {reconstructed_count} votes")
        
        except ValueError as e:
            print(f"Error reconstructing tally for {candidate}: {e}. (Possible insufficient or bad shares)")
            reconstructed_tally[candidate] = "Reconstruction Failed"
    print("-" * 35)

    # Check if all candidates were reconstructed successfully
    if all(isinstance(v, int) for v in reconstructed_tally.values()):
        publish_choice = input("\nDo you want to publish this final tally to make it viewable by clients? (yes/no): ").strip().lower()
        if publish_choice == 'yes':
            publish_tally(reconstructed_tally)
        else:
            print("Tally not published.")
    else:
        print("\nSkipping tally publication due to errors in reconstruction.")

# Step 5: Define a small helper function that tells users how to run the script.
#   It should provide the user with the options to Open, Close or Get the status of the election. 
def print_usage():
    print("Usage: python admin.py [open|close|status|reload_keys|reconstruct_tally]")
    print("  open    : Open the election for voting.")
    print("  close   : Close the election.")
    print("  status  : Get the current status of the election.")
    print("  reload_keys : Reload the public keys database from registrar's file.")
    print("  reconstruct_tally : Reconstruct the final vote tally using Shamir Secret Sharing.")

# Step 6: Your main function should parse command-line arguments and map them to actions.
#   It should accept the commands "open", "close", and "status".
#   For "open" and "close", it should call the function defined in step 2. 
#   For "status", it should call the function defined in step 3. 
#   Your function should be able to handle invalid inputs.
def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    action = sys.argv[1].lower()

    if action == "open":
        # NEW: Call the function defined in step 3 (send_post_request)
        send_post_request("/open")
    elif action == "close":
        # NEW: Call the function defined in step 3 (send_post_request)
        send_post_request("/close")
    elif action == "status":
        # NEW: Call the function defined in step 4 (fetch_status)
        fetch_status()
    elif action == "reload_keys":
        send_post_request("/reload_keys")
    elif action == "reconstruct_tally":
        reconstruct_tally_from_shares()
    else:
        print(f"Invalid action: {action}")
        print_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()