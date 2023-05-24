import time


# Class used to store all values of one entry in Public Keyring
class PublicKeyringValues:
    def __init__(self, keyID, publicKey, userID):
        self.timestamp = time.time()
        self.keyID = keyID
        self.publicKey = publicKey
        self.userID = userID


class PublicKeyring:
    # Constructor, used to initialize empty dictionary
    def __init__(self):
        self.publicKeyring = {}

    def generateKey(self, name, email, password, algorithm, keySize):
        pass

    def getKey(self, keyID):
        return self.publicKeyring[keyID]

    
