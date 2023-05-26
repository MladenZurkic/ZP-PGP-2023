import binascii
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from tabulate import tabulate


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

    def getKeyID(self, publicKey):
        newKeyIDbin = publicKey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return int(binascii.hexlify(newKeyIDbin), 16) & ((1 << 64) - 1)

    # Insert received public key
    def insertKey(self, publicKey, userID, usedAlgorithm):
        # Create new key...
        newKeyID = self.getKeyID(publicKey)

        newPublicKey = PublicKeyringValues(
            keyID=newKeyID,
            publicKey=publicKey,
            userID=userID,
            usedAlgorithm=usedAlgorithm
        )

        self.publicKeyring[newKeyID]: PublicKeyringValues = newPublicKey

    # Get key that's already in the keyring
    def getKey(self, keyID):
        try:
            return self.publicKeyring[keyID]
        except KeyError as err:
            print('Unos u tabeli s vrednoscu ' + str(err.args[0]) + ' ne postoji...')
            return None

    # Used to export key to .pem file
    def exportKey(self):
        pass

    # Used to import key from .pem file
    # TEST NEEDED AFTER IMPLEMENTATION OF exportKey
    def importKey(self, filename):
        with open(filename, 'r') as file:
            dat = file.read()
            userId = dat.split('~')[0]
            mail = dat.split('~')[1]  # Don't know about this...
            usedAlgorithm = dat.split('~')[2]
            publicKey = load_pem_public_key(dat.split('~')[3].encode('utf-8'))
            keyID = self.getKeyID(publicKey)

            newPublicKey = PublicKeyringValues(
                keyID=keyID,
                publicKey=publicKey,
                userID=userId,
                usedAlgorithm=usedAlgorithm
            )

            self.publicKeyring[keyID] = newPublicKey

    # Remove key from keyring
    def removeKey(self, keyID):
        try:
            del self.publicKeyring[keyID]
        except KeyError as err:
            print('Nije moguce obrisati kljuc s vrednoscu ' + str(err.args[0]))

    # Helper function used to print public keyring
    def printKeyring(self):
        for key in self.publicKeyring.keys():
            curr = [[
                self.publicKeyring[key].timestamp,
                self.publicKeyring[key].keyID,
                self.publicKeyring[key].publicKey,
                self.publicKeyring[key].userID,
                self.publicKeyring[key].usedAlgorithm
            ]]
            print(tabulate(curr, headers=["Timestamp", "keyID", "Public Key", "UserID", "Used algorithm"]))


# Test classes...
if __name__ == '__main__':
    pk = PublicKeyring()
    key = rsa.generate_private_key(65537, 512).public_key()
    pk.insertKey(publicKey=key, userID='abcd', usedAlgorithm='RSA')
    pk.printKeyring()
    pk.getKey(132465)  # Should report error
