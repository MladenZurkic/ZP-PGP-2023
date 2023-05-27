import binascii
import time
import struct
from Crypto.Cipher import DES3
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from src.impl.hash.hash import  hashMD5
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from src.impl.asymmetric.asymmetric import elGamalGenerateKeys, elGamalKeyToBytes, elGamalBytesToKey
from src.impl.keyrings.publickeyring import PublicKeyring

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

    def getKeyForSigning(self, keyID):
        try:
            return self.privateKeyringSigning[keyID]
        except KeyError as err:
            print("Nije pronadjen kljuc (Signing): " + str(err.args[0]))
            return None

    def getKeyForEncryption(self, keyID):
        try:
            return self.privateKeyringEncryption[keyID]
        except KeyError as err:
            print("Nije pronadjen kljuc (Encryption): " + str(err.args[0]))
            return None


    def exportKey(self, keyID, usage):
        if usage == 'singing' or usage == 's':
            keyToExport: PrivateKeyringValues = self.getKeyForSigning(keyID)
        elif usage == 'encryption' or usage == 'e':
            keyToExport: PrivateKeyringValues = self.getKeyForEncryption(keyID)
        else:
            print('Navedena neadekvatna upotreba prilikom izvoza!')
            return None

        if keyToExport:
            publicKeyInPEM = keyToExport.publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            outputDataPU = keyToExport.userID + "~" + keyToExport.usedAlgorithm + "~" + publicKeyInPEM
            filenamePU = f'{PEM_FOLDER}PU_{keyToExport.keyID}.pem'
            with open(filenamePU, 'w') as file:
                file.write(outputDataPU)

            privateKeyInPEM = keyToExport.encryptedPrivateKey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            outputDataPR = keyToExport.userID + "~" + keyToExport.usedAlgorithm + "~" + keyToExport.length + "~" + privateKeyInPEM
            filenamePR = f'{PEM_FOLDER}PR_{keyToExport.keyID}.pem'
            with open(filenamePR, 'w') as file:
                file.write(outputDataPR)



    def importKey(self, filename_pu, filename_pr, usage):
        # Load public part of the key
        with open(filename_pu, 'r') as file_pu:
            data = file_pu.read()
            userId = data.split('~')[0]
            usedAlgorithm = data.split('~')[0]
            publicKey = load_pem_public_key(data.split('~')[2].encode('utf-8'))
            keyID = PublicKeyring.getKeyID(publicKey=publicKey)

        with open(filename_pr, 'r') as file_pr:
            data = file_pr.read()
            length = data.split('~')[2]
            encPrivateKey = load_pem_private_key(data.split('~')[3].encode('utf-8'))

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
            if usage == 'singing' or usage == 's':
                self.privateKeyringSigning[keyID] = newPrivateKey
            elif usage == 'encryption' or usage == 'e':
                self.privateKeyringEncryption[keyID] = newPrivateKey
            else:
                print('Navedena neadekvatna upotreba prilikom izvoza!')
                return None


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

    # Removes key from PrivateKeyring
    def removeKey(self, keyID):
        if keyID not in self.privateKeyringEncryption.keys() or self.privateKeyringSigning.keys():
            print('Nije moguce obrisati privatni kljuc s vrednoscu ' + keyID)
        else:
            if keyID in self.privateKeyringEncryption.keys():
                del self.privateKeyringEncryption[keyID]
            if keyID in self.privateKeyringSigning.keys():
                del self.privateKeyringSigning



if __name__ == '__main__':
    pk = PrivateKeyring()
    pk.generateKeys("Mladen", "mladen@gmail.com", "RSA11", 2048, "FilipMladen123")

    #Get Key
    key = list(pk.privateKeyringSigning)
    privateKey = pk.getKeyForSigning(key[0])

    # #Print UserID
    # print(privateKey.userID)
    # privateKey.printValues()

    # NEED TO TEST IMPORT AND EXPORT


