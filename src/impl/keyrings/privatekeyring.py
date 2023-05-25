import time
import rsa
from src.impl.hash.hash import hashSHA1
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from pickle import dumps

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
        hashedPassword = hashSHA1(password)
        userID = name + ": " + email
        if algo == "RSA":
            publicKeySigning, privateKeySigning = rsa.newkeys(sizeOfKeys)
            publicKeyEncryption, privateKeyEncryption = rsa.newkeys(sizeOfKeys)
        else:
            #generisanje DSA i ElGamal
            privateKeySigning = 0 #only for testing for now

        #Encrypting Private keys
        cipher = DES3.new(hashedPassword,DES3.MODE_ECB)
        encryptedKeySigning = cipher.encrypt(dumps(privateKeySigning))
        print(encryptedKeySigning)


if __name__ == '__main__':
    pk = PrivateKeyring()
    pk.generateKeys("Mladen", "mladen@gmail.com", "RSA", 2048, "FilipMladen123")