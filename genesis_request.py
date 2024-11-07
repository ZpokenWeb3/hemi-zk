import requests
import json

# Hemi network RPC URL
HEMI_RPC_URL = "https://testnet.rpc.hemi.network/rpc"  

def get_genesis_block_hash(rpc_url):
    # JSON-RPC request payload for block number 0
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": ["0x0", False],  # "0x0" is the hex representation of the block number 0
        "id": 1
    }
    try:
        # Send request to Hemi RPC endpoint
        response = requests.post(rpc_url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        # Extract the hash from the response
        genesis_hash = data["result"]["hash"]
        return genesis_hash
    except Exception as e:
        print(f"Error retrieving genesis block hash: {e}")
        return None

def save_hash_to_json(genesis_hash, filename="hemi_genesis_hash.json"):
    # Write the hash to a JSON file
    data = {"genesis_hash": genesis_hash}
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Genesis block hash saved to {filename}")
    except Exception as e:
        print(f"Error saving hash to file: {e}")

if __name__ == "__main__":
    # Get the genesis block hash
    genesis_hash = get_genesis_block_hash(HEMI_RPC_URL)
    
    # If successful, save to JSON file
    if genesis_hash:
        print(f"Genesis Block Hash: {genesis_hash}")
        save_hash_to_json(genesis_hash)
    else:
        print("Failed to retrieve genesis block hash.")
