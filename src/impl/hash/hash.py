import hashlib

def hashSHA1(data):
    dataHash = hashlib.sha1(data.encode())
    return dataHash.hexdigest().upper()