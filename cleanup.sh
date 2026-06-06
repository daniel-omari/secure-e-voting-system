#!/bin/bash
# Script for cleaning up the temp files created by running the "test_script.sh"

echo "--- Cleaning up previous test artifacts ---"
rm -f public_keys.json
rm -rf private_keys
pkill -f "python3 server.py" # kill any active server instances
echo "Cleanup complete."