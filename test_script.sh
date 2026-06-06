#!/bin/bash
# Script used to test the e-voting system automatically

# Ensure cleanup is run before starting
./cleanup.sh
echo ""

# Start the server in the background
echo "--- Starting the Voting Server ---"
python3 server.py &
SERVER_PID=$!
sleep 2 # timeout to allow server start
echo "Server started with PID: $SERVER_PID"
echo ""

# Registrar registers voters
echo "--- Registrar registering 3 voters ---"
echo "3" | python3 registrar.py
echo ""

# Admin reloads keys and starts election
echo "--- Admin reloading public keys and opening election ---"
python3 admin.py reload_keys
python3 admin.py open
echo ""

# Verify election status
echo "--- Checking election status (should be OPEN) ---"
python3 admin.py status
echo ""

# Clients submit votes
echo "--- Clients submitting votes ---"

# Voter 1 votes for Alice
python3 client.py <<EOF
voter_1
vote Alice
exit
EOF
sleep 1

# Voter 2 votes for Alice
python3 client.py <<EOF
voter_2
vote Alice
exit
EOF
sleep 1

# Voter 3 votes for Bob
python3 client.py <<EOF
voter_3
vote Bob
exit
EOF
sleep 1

# Voter 1 tries to vote again (should be rejected)
echo "--- Voter_1 attempting to vote again (should be rejected) ---"
python3 client.py <<EOF
voter_1
vote Charlie
exit
EOF
sleep 1

echo ""

# Admin closes election
echo "--- Admin closing election ---"
python3 admin.py close
echo ""

# Client tries to get results (should be told tally is not published)
echo "--- Client trying to get results (should state tally not published) ---"
python3 client.py <<EOF
voter_1
results
exit
EOF
echo ""

# Admin reconstructs tally (using 3 shares) and publishes
echo "--- Admin reconstructing tally (using 3 shares) and publishing ---"
python3 admin.py reconstruct_tally <<EOF
1,2,3
yes
EOF
echo ""

# Client gets final results (should show published tally)
echo "--- Client getting final results (should show published tally) ---"
python3 client.py <<EOF
voter_1
results
exit
EOF
echo ""

# Clean up server process
echo "--- Stopping server ---"
kill $SERVER_PID
echo "Server stopped."
echo "--- End-to-End Test Complete ---"
echo ""