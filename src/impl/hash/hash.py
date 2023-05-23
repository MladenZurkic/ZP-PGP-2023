import hashlib

def hash_sha_1(data):
    dataHash = hashlib.sha1(data.encode())
    return dataHash.hexdigest().upper()