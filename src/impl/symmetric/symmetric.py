import secrets

from Crypto.Cipher import DES3, AES
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.asymmetric import rsa

from src.impl.keyrings.privatekeyring import PrivateKeyring, PrivateKeyringValues
from src.impl.keyrings.publickeyring import PublicKeyring, PublicKeyringValues
from src.impl.asymmetric import asymmetric


GLOBAL_ALGO = 'RSA'


class SymmetricEncryptionDecryption:
    def __init__(self, encriptionType, publicKeyring, privateKeyring):
        if encriptionType == '3DES' or encriptionType == 'DES3':
            self.type = DES3
        else:
            self.type = AES

        self.publicKeyring = publicKeyring
        self.privateKeyring = privateKeyring


    def encrypt(self, publicKeyID, data):
        sessionKey = secrets.token_bytes(24)
        cipher = self.type.new(sessionKey, self.type.MODE_ECB)
        paddedData = self.padData(data)
        encryptedData = cipher.encrypt(paddedData)
        encodedData = b64encode(encryptedData).decode('utf-8')

        publicKeyringValue: PublicKeyringValues = self.publicKeyring.getKey(publicKeyID)
        if not publicKeyringValue:
            print('Kljuc sa ID: ' + str(publicKeyID) + ' ne postoji...')
            # return 1, None

        publicKey = publicKeyringValue.publicKey
        algorithm = publicKeyringValue.usedAlgorithm
        encryptedSessionKey = asymmetric.encryptData(algorithm, publicKey, sessionKey)[1]
        return encodedData, encryptedSessionKey


    def decrypt(self, keyID, password, encryptedData, encryptedSessionKey):
        privateKeyringValue = self.privateKeyring.getKeyForEncryption(keyID)
        if not privateKeyringValue:
            print('Kljuc sa ID: ' + str(keyID) + ' ne postoji...')
            # return 1, None

        algorithm = privateKeyringValue.usedAlgorithm

        sessionKey = asymmetric.decryptData(
            algorithm, privateKeyringValue, encryptedSessionKey, password
        )[1]

        cipher = self.type.new(sessionKey, self.type.MODE_ECB)
        encryptedData = b64decode(encryptedData)
        decryptedData = cipher.decrypt(encryptedData)
        unpaddedData = self.unpadData(decryptedData)
        return unpaddedData.decode('utf-8')


    def padData(self, data):
        blockSize = self.type.block_size
        paddingSize = blockSize - (len(data) % blockSize)
        padding = bytes([paddingSize] * paddingSize)
        if type(data) not in (bytes, bytearray):
            paddedData = data.encode('utf-8') + padding
        else:
            paddedData = data + padding
        return paddedData


    def unpadData(self, data):
        paddingSize = data[-1]
        unpaddedData = data[:-paddingSize]
        return unpaddedData


if __name__ == '__main__':
    # Fill with example keys
    privateKeyring = PrivateKeyring()
    publicKeyring = PublicKeyring()

    tmp, puID = privateKeyring.generateKeys('Filip', 'filip@mail.com', GLOBAL_ALGO, 2048, 'password')
    pu = privateKeyring.getKeyForEncryption(puID).publicKey
    pr = privateKeyring.getKeyForEncryption(puID).encryptedPrivateKey

    publicKeyring.insertKey(pu, 'Filip: filip@mail.com', 'RSA')

    # Example usage
    data = "Hello, World!"
    encryptor = SymmetricEncryptionDecryption('DES3', publicKeyring=publicKeyring, privateKeyring=privateKeyring)

    encrypted_data, key, publicKeyID = encryptor.encrypt(puID, data)
    print("Encrypted data:", encrypted_data)

    decrypted_data = encryptor.decrypt(puID, 'password', encrypted_data, key)
    print("Decrypted data:", decrypted_data)
