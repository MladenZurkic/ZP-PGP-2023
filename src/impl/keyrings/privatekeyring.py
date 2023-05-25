import binascii
import time
import struct
from Crypto.Cipher import DES3
from src.impl.hash.hash import  hashMD5
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from src.impl.asymmetric.asymmetric import elGamalGenerateKeys, elGamalKeyToBytes, elGamalBytesToKey

BLOCK_SIZE = 64

class PrivateKeyringValues:
    def __init__(self, keyID, publicKey, ecp, userID, usedAlgorithm, length):
        self.timestamp = time.time()
        self.keyID = keyID
        self.publicKey = publicKey
        self.encryptedPrivateKey = ecp
        self.userID = userID
        self.usedAlgorithm = usedAlgorithm
        self.length = length

    def printValues(self):
        print("Time:" + str(self.timestamp))
        print(self.keyID)
        print(self.publicKey)
        print(self.encryptedPrivateKey)
        print(self.userID)
        print(self.usedAlgorithm)
        print(self.length)


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
            privateKeyEncryption = rsa.generate_private_key(65537, sizeOfKeys)
            publicKeyEncryption = privateKeyEncryption.public_key()
            privateKeySigning = rsa.generate_private_key(65537, sizeOfKeys)
            publicKeySigning = privateKeySigning.public_key()
        else:
            #generisanje DSA i ElGamal
            p, g, x ,y = elGamalGenerateKeys(sizeOfKeys)
            privateKeyEncryption = (p, x)
            publicKeyEncryption = (p, g, y)
            privateKeySigning = dsa.generate_private_key(sizeOfKeys)
            publicKeySigning = privateKeySigning.public_key()

        #Initialize TripleDES Algorythm
        cipher = DES3.new(hashedPassword,DES3.MODE_ECB)


        # Transform Private Keys To Binary
        if not isinstance(privateKeyEncryption,tuple):

            privateKeyEncryptionBinary = privateKeyEncryption.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
        else:
            privateKeyEncryptionBinary = elGamalKeyToBytes(privateKeyEncryption)


        privateKeySigningBinary = privateKeySigning.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())


        #Encrypting Private keys
        privateKeyEncryptionPadded = pad(privateKeyEncryptionBinary, BLOCK_SIZE)
        encryptedKeyEncryption = cipher.encrypt(privateKeyEncryptionPadded)

        privateKeySigningPadded = pad(privateKeySigningBinary, BLOCK_SIZE)
        encryptedKeySigning = cipher.encrypt(privateKeySigningPadded)


        #Generate KeyID for Public Keys


        #Transform Public Keys to Binary
        if not isinstance(publicKeyEncryption, tuple):
            publicKeyEncryptionBinary = publicKeyEncryption.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            publicKeyEncryptionBinary = elGamalKeyToBytes(publicKeyEncryption)

        publicKeySigningBinary = publicKeySigning.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        #Get IDs from Binary Public Keys
        publicKeyEncryptionID = int(binascii.hexlify(publicKeyEncryptionBinary), 16) & ((1 << 64) - 1)
        publicKeySigningID = int(binascii.hexlify(publicKeySigningBinary), 16) & ((1 << 64) - 1)


        #Create and add to Keyring
        newKeyEncyption = PrivateKeyringValues(
            keyID=publicKeyEncryptionID,
            publicKey= publicKeyEncryption,
            ecp= encryptedKeyEncryption,
            userID= name + ": " + email,
            usedAlgorithm= algo,
            length=sizeOfKeys
        )

        self.privateKeyringEncryption[publicKeyEncryptionID] = newKeyEncyption

        newKeySigning = PrivateKeyringValues(
            keyID=publicKeySigningID,
            publicKey=publicKeySigning,
            ecp=encryptedKeySigning,
            userID=name + ": " + email,
            usedAlgorithm=algo,
            length=sizeOfKeys
        )

        self.privateKeyringSigning[publicKeySigningID] = newKeySigning

        # #Decrypting - not needed - just to test

        # test = serialization.load_der_private_key(privateKeyEncryptionBinary, None)
        #
        # decrypt = cipher.decrypt(encryptedKeyEncryption)
        # decryptBytes = unpad(decrypt, BLOCK_SIZE)

        # print(elGamalBytesToKey(decryptBytes))

        # print(len(binary))
        # decrypted = cipher.decrypt(encryptedKeySigning)
        # privateKeySigningUnPadded = unpad(decrypted, BLOCK_SIZE)
        # privateKeySigningDecrypted = loads(privateKeySigningUnPadded)

if __name__ == '__main__':
    pk = PrivateKeyring()
    pk.generateKeys("Mladen", "mladen@gmail.com", "RSA11", 2048, "FilipMladen123")

    #Get Key
    key = list(pk.privateKeyringSigning)
    privateKey = pk.getKeyForSigning(key[0])

    # #Print UserID
    # print(privateKey.userID)
    # privateKey.printValues()


