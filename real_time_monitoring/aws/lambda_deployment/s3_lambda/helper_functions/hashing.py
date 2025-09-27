import hashlib
def calculate_md5(data: str) -> str:
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    
    # Update the hash object with the data
    md5_hash.update(data.encode('utf-8'))  # Ensure the input is in bytes

    # Return the hexadecimal representation of the hash
    return md5_hash.hexdigest()