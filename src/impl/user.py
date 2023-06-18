import base64
import binascii

from src.impl.asymmetric import asymmetric
from src.impl.asymmetric.asymmetric import decryptPrivateKey
from src.impl.asymmetric.elGamal import elGamalKeyToBytes
from src.impl.keyrings.privatekeyring import PrivateKeyring
from src.impl.keyrings.publickeyring import PublicKeyring
from src.impl.symmetric.symmetric import SymmetricEncryptionDecryption


class User:

    def __init__(self):
        self.publicKeyring = PublicKeyring()
        self.privateKeyring = PrivateKeyring()


    def generateKeys(self, name, email, algorithm, sizeOfKeys, password):
        signingKeyID, encyptionKeyID = self.privateKeyring.generateKeys(name, email, algorithm, sizeOfKeys, password)

        # # Potrebno je otkomentarisati da bi se kljucevi ubacili u public keyring prilikom generisanja
        # # Koristiti samo za testiranje
        # self.publicKeyring.insertKey(self.privateKeyring.getKeyForSigning(signingKeyID).publicKey, name, usedAlgorithm=algorithm)
        # self.publicKeyring.insertKey(self.privateKeyring.getKeyForEncryption(encyptionKeyID).publicKey, name, usedAlgorithm=algorithm)

        print("Keys Generated! The IDs of generated keys are: ")
        print("Key for Signing: " + str(signingKeyID))
        print("Key for Encyption: " + str(encyptionKeyID))

        print("You can now export them, use them to send data etc.")
        return signingKeyID, encyptionKeyID

    def printKeys(self):
        self.publicKeyring.printKeyring()
        self.privateKeyring.printKeyring("SIGNING")
        self.privateKeyring.printKeyring("ENCRYPTION")


    def signData(self, data, keyID, passphrase):
        privateKey = self.privateKeyring.getKeyForSigning(keyID)
        returnCode, signature = asymmetric.signData(privateKey.usedAlgorithm, privateKey, data, passphrase)
        if returnCode:
            print("ERROR: Could not Sign data!")
            return None
        return base64.b64encode(signature).decode('utf-8')  # BYTES -> STRING


    def verifySignature(self, data, signature, publicKey, algorithm):
        signature = base64.b64decode(signature) # STRING -> BYTES
        returnCode = asymmetric.verifySignedData(algorithm, data, signature, publicKey)

        #Fix return values.
        if returnCode < 0:
            print("Signature is NOT good!")
            return -1
        print("Signature is GOOD!")
        return 0


    def encryptData(self, data, publicKeyID, algorithm):
        encryption = SymmetricEncryptionDecryption(algorithm, self.publicKeyring, self.privateKeyring)
        encryptedData, encryptedSessionKey = encryption.encrypt(publicKeyID, data)

        if isinstance(encryptedSessionKey, tuple):
            encryptedSessionKey = elGamalKeyToBytes(encryptedSessionKey)
        encryptedSessionKeyStr = base64.b64encode(encryptedSessionKey).decode('ascii')
        publicKeyIDStr = str(publicKeyID)

        return encryptedData, encryptedSessionKeyStr, publicKeyIDStr

    def decryptData(self, encodedData, encryptedSessionKeyStr, publicKeyIDStr, password, algorithm):
        encryptedSessionKey = binascii.a2b_base64(encryptedSessionKeyStr)
        decryption = SymmetricEncryptionDecryption(algorithm, self.publicKeyring, self.privateKeyring)
        try:
            publicKeyInt = int(publicKeyIDStr)
        except:
            return -2, None
        return decryption.decrypt(publicKeyInt, password, encodedData, encryptedSessionKey)

if __name__ == '__main__':

    #DOES NOT WORK ANYMORE :(
    user1 = User()
    # def generateKeys(self, name, email, algorithm, sizeOfKeys, password):
    user1.generateKeys("Filip", "filip@gmail.com", "ElGamal", 1024, "sifra")
    #user1.printKeys()

    data = "ZP Projekat 2023"

    # # ****** SIGNATURE PART: ******
    # signature = user1.signData(data)
    #
    # # Uncomment next line if you want to intentionally change signature
    # # signature = signature.replace("A", "y")
    #
    # user1.verifySignature(data, signature)
    #
    # # Simulate sending data:
    # concatData = data + "~#~" + signature
    #
    # # SEND concatData
    # print("SENDING..." + concatData)
    #
    # # Unpack sentData
    # data, signature = concatData.split("~#~")
    #
    # user1.verifySignature(data, signature)
    #
    # # ****** ENCRYPTION PART: ******
    # # Mora sa Filipom, mora da se menja symmetric padding myb
    #
    # encodedData, encryptedSessionKey, publicKeyID = user1.encryptData(concatData)
    #
    # concatSignEncr = encodedData + "~#~" + encryptedSessionKey + "~#~" + publicKeyID
    #
    # print('SENDING ENCRYPTION PART... ' + concatSignEncr)
    #
    # # ****** DECRYPTION PART: ******
    #
    # receivedData = concatSignEncr
    #
    # decryptedData = user1.decryptData(receivedData, input('Password: '))
    #
    # print('DECRYPTED DATA: ' + decryptedData)
    # assert decryptedData == concatData
    #
    # # ****** IMPORT EXPORT: ******
    key = list(user1.privateKeyring.privateKeyringEncryption)
    privateKey = user1.privateKeyring.getKeyForEncryption(key[0])
    publicKey = privateKey.publicKey


    # Ovo radi
    # user1.privateKeyring.exportKey(privateKey.keyID, "e", "C:\\Users\\Mladen\\Desktop\\TestZPFajlovi\\")

    # Ovo radi
    # user1.publicKeyring.importKey("C:/Users/Filip/Desktop/ZP Projekat/pem_files/PU_14487548930483000366.pem")
    # user1.publicKeyring.printKeyring()

    # Ovo radi
    user1.privateKeyring.importKey(
        "C:\\Users\\Mladen\\Desktop\\TestZPFajlovi\\PU_16295181946248991790.pem",
        "C:\\Users\\Mladen\\Desktop\\TestZPFajlovi\\PR_16295181946248991790.pem"
    )
    # user1.privateKeyring.printKeyring("ENCRYPTION")

    user1.publicKeyring.importKey("C:\\Users\\Mladen\\Desktop\\TestZPFajlovi\\PU_16295181946248991790.pem")


    publicKeyID = user1.publicKeyring.getKeyID(publicKey)
    encprivkey = user1.privateKeyring.getKeyForEncryption(publicKeyID)

    user1.printKeys()
    returnCode, key = decryptPrivateKey(encprivkey, "sifra", "e")

    print("KEY")
    print(key)

    encryptedData, encryptedSessionKeyStr, publicKeyIDStr = user1.encryptData("ZP Projekat 2023aa", 16295181946248991790, "AES")

    print("ENCRYPTED DATA")
    print(encryptedData)

    decryptedData = user1.decryptData(encryptedData, encryptedSessionKeyStr, publicKeyIDStr, "sifra", "AES")

    print("DECRYPTED DATA")
    print(decryptedData)


    user1.privateKeyring.removeKey(16295181946248991790)
    user1.privateKeyring.removeKey(16295181946248991791)
    user1.privateKeyring.removeKey(16295181946248991792)
    user1.privateKeyring.removeKey(16295181946248991793)
    user1.privateKeyring.removeKey(publicKeyID)

    user1.printKeys()