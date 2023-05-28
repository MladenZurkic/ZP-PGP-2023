import secrets

from Crypto.Cipher import DES3, AES
from base64 import b64encode, b64decode

from src.impl.keyrings.privatekeyring import PrivateKeyring, PrivateKeyringValues
from src.impl.keyrings.publickeyring import PublicKeyring, PublicKeyringValues
from src.impl.asymmetric import asymmetric

# Probably should be replaced by global instances
publicKeyring = PublicKeyring()
privateKeyring = PrivateKeyring()


class SymmetricEncryptionDecryption:
    def __init__(self, encriptionType):
        if encriptionType == '3DES' or encriptionType == 'DES3':
            self.type = DES3
        else:
            self.type = AES

    def encrypt(self, publicKeyID, data):
        sessionKey = secrets.token_bytes(24)
        cipher = self.type.new(sessionKey, self.type.MODE_ECB)
        paddedData = self.padData(data)
        encryptedData = cipher.encrypt(paddedData)
        encodedData = b64encode(encryptedData).decode('utf-8')

        """
        publicKeyringValue: PublicKeyringValues = publicKeyring.getKey(publicKeyID)
        if not publicKeyringValue:
            print('Kljuc sa ID: ' + str(publicKeyID) + ' ne postoji...')
            # return 1, None

        publicKey = publicKeyringValue.publicKey
        """
        # Uncomment after implementation of AsymmetricEncryptionDecryption class
        # encryptedSessionKey = asymmetric.encryptData(GLOBAL_ALGO, publicKey, sessionKey)
        encryptedSessionKey = sessionKey

        return encodedData, encryptedSessionKey#, publicKeyID

    def decrypt(self, keyID, password, encryptedData, encryptedSessionKey):
        privateKeyringValue = privateKeyring.getKeyForEncryption(keyID)
        if not privateKeyringValue:
            print('Kljuc sa ID: ' + str(keyID) + ' ne postoji...')
            # return 1, None

        # Filipe zar ovde ne treba da se prosledi encryptedSessionKey a ne keyID?

        # sessionKey = asymmetric.decryptData(GLOBAL_ALGO, privateKeyringValue, keyID, password)
        sessionKey = encryptedSessionKey
        cipher = self.type.new(sessionKey, self.type.MODE_ECB)
        encryptedData = b64decode(encryptedData)
        decryptedData = cipher.decrypt(encryptedData)
        unpaddedData = self.unpadData(decryptedData)
        return unpaddedData.decode('utf-8')

    def padData(self, data):
        blockSize = self.type.block_size
        paddingSize = blockSize - (len(data) % blockSize)
        padding = bytes([paddingSize] * paddingSize)
        paddedData = data + padding
        return paddedData

    def unpadData(self, data):
        paddingSize = data[-1]
        unpaddedData = data[:-paddingSize]
        return unpaddedData


if __name__ == '__main__':
    # Example usage
    data = b"Hello, World!"
    encryptor = SymmetricEncryptionDecryption('DES3')

    encrypted_data, key = encryptor.encrypt(1234456, data)
    print("Encrypted data:", encrypted_data)

    decrypted_data = encryptor.decrypt(key, encrypted_data)
    print("Decrypted data:", decrypted_data)
