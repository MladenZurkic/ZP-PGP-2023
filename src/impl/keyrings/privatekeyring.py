import time
import rsa
from src.impl.hash.hash import hashSHA1, hashMD5
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from pickle import dumps, loads
from pympler import asizeof

import os

BLOCK_SIZE = 32

class PrivateKeyringValues:
    def __init__(self, keyID, publicKey, ecp, userID, usedAlgorithm, length):
        self.timestamp = time.time()
        self.keyID = keyID
        self.publicKey = publicKey
        self.EncryptedPrivateKey = ecp
        self.userID = userID
        self.usedAlgorithm = usedAlgorithm
        self.length = length



class PrivateKeyring:
    def __init__(self):
        self.privateKeyringSigning = {}
        self.privateKeyringEncryption = {}

    def getKeyForSigning(self, keyID):
        try:
            return self.privateKeyringSigning[keyID]
        except KeyError as err:
            print("Nije pronadjen kljuc (Signing): " + str(err.args[0]))
            return None

    def geyKeyForEncryption(self,keyID):
        try:
            return self.privateKeyringEncryption[keyID]
        except KeyError as err:
            print("Nije pronadjen kljuc (Encryption): " + str(err.args[0]))
            return None


    def exportKeyForSigning(self, keyID):
        key = self.privateKeyringSigning[keyID]

        pass

    #Kako da se importuje privatni kljuc, da li saljemo i keyID kada ga exportujemo?
    def importKeyForSigning(self, key):
        pass

    def generateKeys(self, name, email, algo, sizeOfKeys, password):
        hashedPassword = hashMD5(password)
        userID = name + ": " + email
        if algo == "RSA":
            publicKeySigning, privateKeySigning = rsa.newkeys(sizeOfKeys)
            publicKeyEncryption, privateKeyEncryption = rsa.newkeys(sizeOfKeys)
        else:
            #generisanje DSA i ElGamal
            privateKeySigning = 0 #only for testing for now
            publicKeySigning = 0
            privateKeyEncryption = 0
            publicKeyEncryption = 0

        #Initialize TripleDES Algorythm
        key = DES3.adjust_key_parity(hashedPassword)
        cipher = DES3.new(hashedPassword,DES3.MODE_ECB)


        #Encrypting Private keys
        privateKeySigningPadded = pad(dumps(privateKeySigning), BLOCK_SIZE)
        encryptedKeySigning = cipher.encrypt(privateKeySigningPadded)

        privateKeyEncryptionPadded = pad(dumps(privateKeyEncryption), BLOCK_SIZE)
        encryptedKeyEncryption = cipher.encrypt(privateKeyEncryptionPadded)

        #Creating KeyIDs
        print(publicKeySigning)
        print(publicKeyEncryption)


        # #Decrypting - not needed - just tested
        # decrypted = cipher.decrypt(encryptedKeySigning)
        # privateKeySigningUnPadded = unpad(decrypted, BLOCK_SIZE)
        # privateKeySigningDecrypted = loads(privateKeySigningUnPadded)


if __name__ == '__main__':
    pk = PrivateKeyring()
    pk.generateKeys("Mladen", "mladen@gmail.com", "RSA", 2048, "FilipMladen123")