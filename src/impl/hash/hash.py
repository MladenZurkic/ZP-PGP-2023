import hashlib

def hashSHA1Hex(data):
    dataHash = hashlib.sha1(data.encode())
    return dataHash.hexdigest().upper()

def hashSHA1(data):
    dataHash = hashlib.sha1(data.encode())
    return dataHash.digest()

def hashMD5(data):
    dataHash = hashlib.md5(data.encode())
    return dataHash.digest()
