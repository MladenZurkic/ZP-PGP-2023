import binascii
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class PublicKeyringValues:
    def __init__(self, keyID, publicKey, userID, usedAlgorithm):
        self.timestamp = time.time()
        self.keyID = keyID
        self.publicKey = publicKey
        self.userID = userID
        self.usedAlgorithm = usedAlgorithm


class PublicKeyring:
    # Constructor, used to initialize empty dictionary
    def __init__(self):
        self.publicKeyring = {}

    # Insert received public key
    def insertKey(self, publicKey, userID, usedAlgorithm):
        newKeyIDbin = publicKey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        newKeyID = int(binascii.hexlify(newKeyIDbin), 16) & ((1 << 64) - 1)
        newPublicKey = PublicKeyringValues(
            keyID=newKeyID,
            publicKey=publicKey,
            userID=userID,
            usedAlgorithm=usedAlgorithm
        )

        self.publicKeyring[newKeyID] = newPublicKey

    # Get key that's already in the keyring
    def getKey(self, keyID):
        try:
            return self.publicKeyring[keyID]
        except KeyError as err:
            print('Unos u tabeli s vrednoscu ' + str(err.args[0]) + ' ne postoji...')
            return None



# Test classes...
if __name__ == '__main__':
    pk = PublicKeyring()
    key = rsa.generate_private_key(65537, 512).public_key()
    pk.insertKey(publicKey=key, userID='abcd', usedAlgorithm='RSA')

    pk.getKey(132465)  # Should report error
