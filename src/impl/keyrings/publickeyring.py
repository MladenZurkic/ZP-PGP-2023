import binascii
from datetime import datetime
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from tabulate import tabulate

from src.impl.asymmetric.elGamal import elGamalKeyToBytes, elGamalBase64ToKey

PEM_FOLDER = '../../../../pem_files/'


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
        if not isinstance(publicKey, tuple):
            newKeyIDbin = publicKey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            newKeyIDbin = elGamalKeyToBytes(publicKey)

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
    # Returns PublicKeyringValues object?
    def getKey(self, keyID):
        try:
            return self.publicKeyring[keyID]
        except KeyError as err:
            print('Unos u tabeli s vrednoscu ' + str(err.args[0]) + ' ne postoji...')
            return None

    # Used to export key to .pem file
    def exportKey(self, keyID):
        keyToExport: PublicKeyringValues = self.getKey(keyID)
        if keyToExport:
            publicKeyInPEM = keyToExport.publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            outputData = keyToExport.userID + "~#~" + keyToExport.usedAlgorithm + "~#~" + publicKeyInPEM
            filename = f'{PEM_FOLDER}{keyToExport.keyID}.pem'
            with open(filename, 'w') as file:
                file.write(outputData)

    # Used to import key from .pem file
    # TEST NEEDED AFTER IMPLEMENTATION OF exportKey
    def importKey(self, filename):
        with open(filename, 'r') as file:
            dat = file.read()
            userId = dat.split('~#~')[0]
            usedAlgorithm = dat.split('~#~')[1]
            if usedAlgorithm == "ElGamal":
                keyInPEM = dat.split('~#~')[2]
                dat = keyInPEM.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----", "")
                publicKey = elGamalBase64ToKey(dat.encode('utf-8'))
            else:
                publicKey = load_pem_public_key(dat.split('~#~')[2].encode('utf-8'))
            keyID = self.getKeyID(publicKey)

            if keyID in self.publicKeyring.keys():
                print('Ovaj kljuc vec postoji...')
                return -1
            else:
                newPublicKey = PublicKeyringValues(
                    keyID=keyID,
                    publicKey=publicKey,
                    userID=userId,
                    usedAlgorithm=usedAlgorithm
                )
                self.publicKeyring[keyID] = newPublicKey
            return keyID

    # Remove key from keyring
    def removeKey(self, keyID):
        try:
            del self.publicKeyring[keyID]
        except KeyError as err:
            print('Nije moguce obrisati kljuc s vrednoscu ' + str(err.args[0]))

    # Helper function used to print public keyring
    def printKeyring(self):
        printTable = []
        for key in self.publicKeyring.keys():
            if not isinstance(self.publicKeyring[key].publicKey, tuple):
                keyPrint = int(binascii.hexlify(self.publicKeyring[key].publicKey.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )), 16)
            else:
                keyPrint = int(binascii.hexlify(elGamalKeyToBytes(self.publicKeyring[key].publicKey)), 16)
            printTable.append([
                datetime.fromtimestamp(self.publicKeyring[key].timestamp),
                self.publicKeyring[key].keyID,
                keyPrint,
                self.publicKeyring[key].userID,
                self.publicKeyring[key].usedAlgorithm
            ])
        print(tabulate(printTable, headers=["Timestamp", "keyID", "Public Key", "UserID", "Used algorithm"]))


# Test classes...
if __name__ == '__main__':
    pk = PublicKeyring()
    key = rsa.generate_private_key(65537, 512).public_key()
    pk.insertKey(publicKey=key, userID='abcd', usedAlgorithm='RSA')
    pk.printKeyring()

    assert pk.getKey(132465) is None

    pk.exportKey(pk.getKeyID(key))
    assert pk.importKey(f'{PEM_FOLDER}{pk.getKeyID(key)}.pem') == 1

    # Test importing of new key
    key1 = rsa.generate_private_key(65537, 512).public_key()
    pk.insertKey(key1, 'Filip', 'RSA')
    pk.printKeyring()

