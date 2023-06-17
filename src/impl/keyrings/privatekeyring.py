import binascii
import time

import Crypto.IO.PEM
from Crypto.Cipher import DES3
from tabulate import tabulate
from datetime import datetime
from Crypto.Util.Padding import pad
from src.impl.hash.hash import  hashMD5
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from src.impl.asymmetric.elGamal import *
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

BLOCK_SIZE = 64
PEM_FOLDER = '../../../../pem_files/'

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

    def getKeyForSigning(self, keyID) -> PrivateKeyringValues or None:
        try:
            return self.privateKeyringSigning[keyID]
        except KeyError as err:
            print("Nije pronadjen kljuc (Signing): " + str(err.args[0]))
            return None

    def getKeyForEncryption(self, keyID) -> PrivateKeyringValues or None:
        try:
            return self.privateKeyringEncryption[keyID]
        except KeyError as err:
            print("Nije pronadjen kljuc (Encryption): " + str(err.args[0]))
            return None

    def exportKey(self, keyID, usage, PATH):
        if usage == "Signing" or usage == 's':
            keyToExport: PrivateKeyringValues = self.getKeyForSigning(keyID)
        elif usage == "Encryption" or usage == 'e':
            keyToExport: PrivateKeyringValues = self.getKeyForEncryption(keyID)
        else:
            print('Navedena neadekvatna upotreba prilikom izvoza!')
            return None

        if keyToExport:
            if keyToExport.usedAlgorithm == "RSA" or keyToExport.usedAlgorithm == "DSA":
                # Public key is either DSA or RSA
                publicKeyInPEM = keyToExport.publicKey.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            else:
                # Public key is ElGamal
                publicKeyInPEM = f"-----BEGIN PUBLIC KEY-----\n{elGamalKeyToBase64(keyToExport.publicKey)}\n-----END PUBLIC KEY-----"

            outputDataPU = keyToExport.userID + "~" + keyToExport.usedAlgorithm + "~" + publicKeyInPEM
            if not PATH:
                filenamePU = f'{PEM_FOLDER}PU_{keyToExport.keyID}.pem'
            else:
                filenamePU = f'{PATH}PU_{keyToExport.keyID}.pem'
            with open(filenamePU, 'w') as file:
                file.write(outputDataPU)

            if keyToExport.usedAlgorithm == "RSA" or keyToExport.usedAlgorithm == "DSA":
                privateKeyInPEM = Crypto.IO.PEM.encode(keyToExport.encryptedPrivateKey, "PRIVATE KEY")
            else:
                privateKeyInPEM = f"-----BEGIN PUBLIC KEY-----\n{elGamalKeyToBase64(keyToExport.encryptedPrivateKey)}\n-----END PUBLIC KEY-----"

            # #CHECK THIS!! encryptedPrivateKey is stored as bytes, this does not work >.<
            # privateKeyInPEM = keyToExport.encryptedPrivateKey.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PrivateFormat.PKCS8,
            #     encryption_algorithm=serialization.NoEncryption()
            # ).decode('utf-8')

            outputDataPR = keyToExport.userID + "~" + usage + "~" + keyToExport.usedAlgorithm + "~" + str(keyToExport.length) + "~" + privateKeyInPEM
            if not PATH:
                filenamePR = f'{PEM_FOLDER}PR_{keyToExport.keyID}.pem'
            else:
                filenamePR = f'{PATH}PR_{keyToExport.keyID}.pem'
            with open(filenamePR, 'w') as file:
                file.write(outputDataPR)

    def getKeyID(self, publicKey):
        if not isinstance(publicKey, tuple):
            newKeyIDbin = publicKey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            newKeyIDbin = elGamalKeyToBytes(publicKey)

        return int(binascii.hexlify(newKeyIDbin), 16) & ((1 << 64) - 1)

    def importKey(self, filename_pu, filename_pr):
        # Load public part of the key
        with open(filename_pu, 'r') as file_pu:
            data = file_pu.read()
            userId = data.split('~')[0]
            usedAlgorithm = data.split('~')[1]
            if usedAlgorithm == "ElGamal":
                keyInPEM = data.split('~')[2]
                dat = keyInPEM.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----", "")
                publicKey = elGamalBase64ToKey(dat.encode('utf-8'))
            else:
                publicKey = load_pem_public_key(data.split('~')[2].encode('utf-8'))
            keyID = self.getKeyID(publicKey=publicKey)

        with open(filename_pr, 'r') as file_pr:
            data = file_pr.read()
            usage = data.split('~')[1]
            length = int(data.split('~')[3])
            if usedAlgorithm == "ElGamal":
                keyInPEM = data.split('~')[4]
                dat = keyInPEM.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----", "")
                encPrivateKey = elGamalBase64ToKey(dat.encode('utf-8'))
            else:
                encPrivateKey = Crypto.IO.PEM.decode(data.split('~')[4])

        newPrivateKey = PrivateKeyringValues(
            keyID=keyID,
            publicKey=publicKey,
            usedAlgorithm=usedAlgorithm,
            userID=userId,
            ecp=encPrivateKey,
            length=length
        )

        if keyID in self.privateKeyringSigning.keys():
            print('Ovaj kljuc vec postoji u prstenu za potpisivanje...')
        elif keyID in self.privateKeyringEncryption.keys():
            print('Ovaj kljuc vec postoji u prstenu za sifrovanje...')
        else:
            if usage == 'Singing' or usage == 's':
                self.privateKeyringSigning[keyID] = newPrivateKey
            elif usage == 'Encryption' or usage == 'e':
                self.privateKeyringEncryption[keyID] = newPrivateKey
            else:
                print('Navedena neadekvatna upotreba prilikom izvoza!')
                return None
        return keyID


    def generateKeys(self, name, email, algo, sizeOfKeys, password):
        hashedPassword = hashMD5(password)
        sizeOfKeys = int(sizeOfKeys)
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


        # Transform Private Keys To Bytes
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


        #Transform Public Keys to Bytes
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
            usedAlgorithm="RSA" if algo == "RSA" else "ElGamal",
            length=sizeOfKeys
        )

        self.privateKeyringEncryption[publicKeyEncryptionID] = newKeyEncyption

        newKeySigning = PrivateKeyringValues(
            keyID=publicKeySigningID,
            publicKey=publicKeySigning,
            ecp=encryptedKeySigning,
            userID=name + ": " + email,
            usedAlgorithm="RSA" if algo == "RSA" else "DSA",
            length=sizeOfKeys
        )

        self.privateKeyringSigning[publicKeySigningID] = newKeySigning

        return publicKeySigningID, publicKeyEncryptionID

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

    # Removes key from PrivateKeyring
    def removeKey(self, keyID):
        if keyID not in self.privateKeyringEncryption.keys() or self.privateKeyringSigning.keys():
            print('Nije moguce obrisati privatni kljuc s vrednoscu ' + keyID)
        else:
            if keyID in self.privateKeyringEncryption.keys():
                del self.privateKeyringEncryption[keyID]
            if keyID in self.privateKeyringSigning.keys():
                del self.privateKeyringSigning


    # Helper function used to print public keyring
    def printKeyring(self, type):
        printTable = []
        if(type.upper() == "SIGNING" or type == "S"):
            keyring = self.privateKeyringSigning
        else:
            keyring = self.privateKeyringEncryption

        for key in keyring.keys():
            if isinstance(keyring[key].publicKey, tuple):
                keyPrint = int(binascii.hexlify(elGamalKeyToBytes(keyring[key].publicKey)), 16)
            else:
                keyPrint = int(binascii.hexlify(keyring[key].publicKey.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )), 16)
            printTable.append([
                datetime.fromtimestamp(keyring[key].timestamp),
                keyring[key].keyID,
                keyPrint,
                keyring[key].encryptedPrivateKey,
                keyring[key].userID,
                keyring[key].usedAlgorithm
            ])
        print(tabulate(printTable, headers=["Timestamp", "keyID", "Public Key", "Encrypted Private Key" ,"UserID", "Used Algorithm"]))



if __name__ == '__main__':
    pk = PrivateKeyring()
    signingKeyID, encyptionKeyID = pk.generateKeys("Mladen", "mladen@gmail.com", "RSA", 2048, "FilipMladen123")

    print("Keys Generated! The IDs of generated keys are: ")
    print("Key for Signing: " + str(signingKeyID))
    print("Key for Encyption: " + str(encyptionKeyID))
    #Get Key
    key = list(pk.privateKeyringSigning)
    print(type(key[0]))
    #Input

    keyIDSigningTest = input("Ubaci keyID za Signing:")
    print(type(keyIDSigningTest))
    privateKey = pk.getKeyForSigning(keyIDSigningTest)

    # #Print UserID
    # print(privateKey.userID)
    # privateKey.printValues()

    # NEED TO TEST IMPORT AND EXPORT


    # privateKey.printValues()
