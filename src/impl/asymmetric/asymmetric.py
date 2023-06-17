import base64
import pickle
import traceback

from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
from src.impl.hash.hash import hashMD5
from src.impl.keyrings.privatekeyring import PrivateKeyring
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from src.impl.asymmetric.elGamal import *
from src.impl.symmetric.symmetric import SymmetricEncryptionDecryption

BLOCK_SIZE = 64


def testElGamal():
    p, g, x, y = elGamalGenerateKeys(2048)
    publicKey = (p, g, y)
    privateKey = (p, x)

    plaintext = "MLADEN"

    ciphertext = elGamalEncrypt(plaintext, publicKey)
    print(ciphertext)

    plaintextNew = elGamalDecrypt(ciphertext, privateKey)
    print(plaintextNew)

    print("TestElGamalPart2")
    print(publicKey)
    byte = elGamalKeyToBytes(publicKey)
    print(byte)
    print(elGamalBytesToKey(byte))


## MOZE DA BACI ValueError, sluzi da se prepozna kada nastane greska prilikom potpisivanja, ukoliko pascode nije dobro unet
## Bacice tu gresku!
# Works
def signData(algorithm, privateKey, data, passphrase):
    hashedPassword = hashMD5(passphrase)
    encryptedPrivateKey = privateKey.encryptedPrivateKey
    cipher = DES3.new(hashedPassword, DES3.MODE_ECB)

    decryptedPrivateKeyPadded = cipher.decrypt(encryptedPrivateKey)

    try:
        decryptedPrivateKeyBytes = unpad(decryptedPrivateKeyPadded, BLOCK_SIZE)
        decryptedPrivateKey = serialization.load_der_private_key(decryptedPrivateKeyBytes, None)
    except ValueError:
        print("testing ValueError, got to except part")
        return 1, None

    if isinstance(data, (bytes, bytearray)):
        dataBytes = data
    else:
        dataBytes = base64.b64encode(data.encode())

    if(algorithm.upper() == "RSA"):
        sha1Hash = hashes.Hash(hashes.SHA1())

        sha1Hash.update(dataBytes)
        hashValue = sha1Hash.finalize()

        try:
            signature = decryptedPrivateKey.sign(
                hashValue,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        except TypeError:
            #Prosledjeni kljuc je drugacijeg tipa od algoritma koji je upisan da se koristi
            return 2, None
    else:
        try:
            signature = decryptedPrivateKey.sign(
                dataBytes,
                hashes.SHA1()
            )
        except TypeError:
            # Prosledjeni kljuc je drugacijeg tipa od algoritma koji je upisan da se koristi
            return 2, None

    print("SIGNATURE PRILIKOM POTPISA:")
    print(signature)
    return 0, signature

# Works
def verifySignedData(algorithm, data, signature, publicKey):
    if isinstance(data, (bytes, bytearray)):
        dataBytes = data
    else:
        dataBytes = base64.b64encode(data.encode())

    sha1Hash = hashes.Hash(hashes.SHA1())
    sha1Hash.update(dataBytes)
    hashValue = sha1Hash.finalize()

    # Da li cemo da prosledjujemo objekat PublicKeyringValues ili samo publicKey
    publicKeyObject = publicKey.publicKey

    if(algorithm.upper() == "RSA"):
        try:
            publicKeyObject.verify(
                signature,
                hashValue,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        except:
            traceback.print_exc()
            return 1
    else:
        try:
            publicKeyObject.verify(
                signature,
                dataBytes,
                hashes.SHA1()
            )
        except:
            return 1
    return 0


def encryptData(algorithm, publicKey, data):
    if isinstance(data, (bytes, bytearray)):
        dataBytes = data
    else:
        dataBytes = pickle.dumps(data)

    if(algorithm.upper() == "RSA"):
        try:
            ciphertext = publicKey.encrypt(
                dataBytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except:
            return 1, None
    else:
        try:
            ciphertext = elGamalEncrypt(dataBytes, publicKey)
        except:
            return 2, None

    return 0, ciphertext


def decryptPrivateKey(privateKey, passphrase, usage):

    hashedPassword = hashMD5(passphrase)
    encryptedPrivateKey = privateKey.encryptedPrivateKey
    cipher = DES3.new(hashedPassword, DES3.MODE_ECB)

    decryptedPrivateKeyPadded = cipher.decrypt(encryptedPrivateKey)
    algorithm = privateKey.usedAlgorithm

    try:
        decryptedPrivateKeyBytes = unpad(decryptedPrivateKeyPadded, BLOCK_SIZE)
        if (algorithm.upper() == "RSA"):
            decryptedPrivateKey = serialization.load_der_private_key(decryptedPrivateKeyBytes, None)
        else:
            if usage == "Signing" or usage == "s":
                decryptedPrivateKey = serialization.load_der_private_key(decryptedPrivateKeyBytes, None)
            else:
                decryptedPrivateKey = elGamalBase64ToKey(decryptedPrivateKeyBytes)
    except ValueError as err:
        print(err)
        return -1, None
    return 0, decryptedPrivateKey



def decryptData(algorithm, privateKeyValue, data, passphrase):

    hashedPassword = hashMD5(passphrase)
    encryptedPrivateKey = privateKeyValue.encryptedPrivateKey
    cipher = DES3.new(hashedPassword, DES3.MODE_ECB)

    decryptedPrivateKeyPadded = cipher.decrypt(encryptedPrivateKey)

    try:
        decryptedPrivateKeyBytes = unpad(decryptedPrivateKeyPadded, BLOCK_SIZE)
        if(algorithm.upper() == "RSA"):
            decryptedPrivateKey = serialization.load_der_private_key(decryptedPrivateKeyBytes, None)
        else:
            decryptedPrivateKey = elGamalBytesToKey(decryptedPrivateKeyBytes)
    except ValueError as err:
        print("testing ValueError, got to except part")
        print(err)
        return 1, None


    if(algorithm.upper() == "RSA"):
        try:
            plaintext = decryptedPrivateKey.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except:
            return 2, None
    else:
        plaintext = elGamalDecrypt(data, decryptedPrivateKey)

    return 0, plaintext


if __name__ == '__main__':

    testElGamal()

    pk = PrivateKeyring()
    pk.generateKeys("Mladen", "mladen@gmail.com", "RSA", 2048, "123")
    print(pk.privateKeyringSigning.values())

    key = list(pk.privateKeyringSigning)
    privateKey = pk.getKeyForSigning(key[0])
    publicKey = privateKey.publicKey

    returnCode, signature = signData("RSA", privateKey, "Mladen123", "123")

    print(returnCode)
    print(signature)

    #verify signed message
    print(verifySignedData("RSA", "Mladen123", signature, publicKey))


    #Testing Enc/Decr
    print("TestEcryptionDecryptionPart")
    pk.generateKeys("Mladen", "mladen@gmail.com", "DSA+ElGamal", 2048, "123")

    key = list(pk.privateKeyringEncryption)
    privateKey = pk.getKeyForEncryption(key[1])
    publicKey = privateKey.publicKey


    returnCode, encrypted = encryptData("DSA+ElGamal", publicKey, "test123")
    if not returnCode:
        returnCode, decrypted = decryptData("DSA+ElGamal", privateKey, encrypted, "123")
        if not returnCode:
            print(returnCode)
            print(decrypted)
            print("starting data: ",end="")
            print(pickle.loads(decrypted))