import base64
import binascii

from src.impl.asymmetric import asymmetric
from src.impl.keyrings.privatekeyring import PrivateKeyring
from src.impl.keyrings.publickeyring import PublicKeyring
from src.impl.symmetric.symmetric import SymmetricEncryptionDecryption


class User:

    def __init__(self):
        self.publicKeyring = PublicKeyring()
        self.privateKeyring = PrivateKeyring()


    def generateKeys(self, name, email, algorithm, sizeOfKeys, password):
        signingKeyID, encyptionKeyID = self.privateKeyring.generateKeys(name, email, algorithm, sizeOfKeys, password)
        
        self.publicKeyring.insertKey(self.privateKeyring.getKeyForEncryption(encyptionKeyID).publicKey, name, usedAlgorithm=algorithm)

        print("Keys Generated! The IDs of generated keys are: ")
        print("Key for Signing: " + str(signingKeyID))
        print("Key for Encyption: " + str(encyptionKeyID))

        print("You can now export them, use them to send data etc.")


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
        return base64.b64encode(signature).decode('utf-8')


    def verifySignature(self, data, signature, publicKey, algorithm):
        # key = list(user1.privateKeyring.privateKeyringSigning)
        # privateKey = user1.privateKeyring.getKeyForSigning(key[0])
        # publicKey = privateKey.publicKey
        signature = base64.b64decode(signature)
        returnCode = asymmetric.verifySignedData(algorithm, data, signature, publicKey)
        if returnCode:
            print("Signature is NOT good!")
            return
        print("Signature is GOOD!")


    def encryptData(self, data, publicKeyID, algorithm):
        encryption = SymmetricEncryptionDecryption(algorithm, self.publicKeyring, self.privateKeyring)
        encryptedData, encryptedSessionKey = encryption.encrypt(publicKeyID, data)

        encryptedSessionKeyStr = base64.b64encode(encryptedSessionKey).decode('ascii')
        publicKeyIDStr = str(publicKeyID)

        return encryptedData, encryptedSessionKeyStr, publicKeyIDStr

    def decryptData(self, data, password):
        encodedData, encryptedSessionKeyStr, publicKeyIDStr = data.split("~#~")
        encryptedSessionKey = binascii.a2b_base64(encryptedSessionKeyStr)
        decryption = SymmetricEncryptionDecryption("DES3", self.publicKeyring, self.privateKeyring)
        return decryption.decrypt(int(publicKeyIDStr), password, encodedData, encryptedSessionKey)

if __name__ == '__main__':

    #DOES NOT WORK ANYMORE :(
    user1 = User()
    user1.generateKeys()
    user1.printKeys()

    data = "ZP Projekat 2023"

    # ****** SIGNATURE PART: ******
    signature = user1.signData(data)

    # Uncomment next line if you want to intentionally change signature
    # signature = signature.replace("A", "y")

    user1.verifySignature(data, signature)

    # Simulate sending data:
    concatData = data + "~#~" + signature

    # SEND concatData
    print("SENDING..." + concatData)

    # Unpack sentData
    data, signature = concatData.split("~#~")

    user1.verifySignature(data, signature)

    # ****** ENCRYPTION PART: ******
    # Mora sa Filipom, mora da se menja symmetric padding myb

    encodedData, encryptedSessionKey, publicKeyID = user1.encryptData(concatData)

    concatSignEncr = encodedData + "~#~" + encryptedSessionKey + "~#~" + publicKeyID

    print('SENDING ENCRYPTION PART... ' + concatSignEncr)

    # ****** DECRYPTION PART: ******

    receivedData = concatSignEncr

    decryptedData = user1.decryptData(receivedData, input('Password: '))

    print('DECRYPTED DATA: ' + decryptedData)
    assert decryptedData == concatData

    # ****** IMPORT EXPORT: ******
    key = list(user1.privateKeyring.privateKeyringSigning)
    privateKey = user1.privateKeyring.getKeyForSigning(key[0])
    publicKey = privateKey.publicKey


    # Ovo radi
    # user1.privateKeyring.exportKey(privateKey.keyID, "s", "C:/Users/Mladen/Desktop/TestZPExport/")

    # Ovo radi
    # user1.publicKeyring.importKey("C:/Users/Mladen/Desktop/TestZPExport/PU_12983771081721577473.pem")
    # user1.publicKeyring.printKeyring()

    # Ovo radi
    # user1.privateKeyring.importKey("C:/Users/Mladen/Desktop/TestZPExport/PU_12983771081721577473.pem", "C:/Users/Mladen/Desktop/TestZPExport/PR_12983771081721577473.pem", "s")
    # user1.privateKeyring.printKeyring("SIGNING")