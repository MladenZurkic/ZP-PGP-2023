import pickle
import struct

from Crypto.Util import number
import base64

def elGamalGenerateKeys(keySize):
    p = number.getPrime(keySize)
    g = number.getRandomRange(2, p - 1)

    #PrivateKey
    x = number.getRandomRange(2, p - 2)

    #PublicKey
    y = pow(g, x, p)
    return p, g, x, y


def elGamalEncrypt(plaintext, publicKey):
    p, g, y = publicKey

    k = number.getRandomRange(2, p - 1)
    c1 = pow(g, k, p)

    plaintextEncoded = int.from_bytes(plaintext.encode(), 'big')

    c2 = (plaintextEncoded * pow(y, k, p)) % p
    return c1, c2


def elGamalDecrypt(ciphertext, privateKey):
    p, x = privateKey
    c1, c2 = ciphertext

    s = pow(c1, x, p)
    sInverse = number.inverse(s, p)

    plaintextEncoded = (c2 * sInverse) % p
    plaintext = plaintextEncoded.to_bytes((plaintextEncoded.bit_length() + 7) // 8, 'big').decode()
    return plaintext


def elGamalKeyToBytes(key):
        return pickle.dumps(key)


def elGamalBytesToKey(key):
    return pickle.loads(key)

if __name__ == '__main__':
    p, g, x, y  = elGamalGenerateKeys(2048)
    publicKey = (p, g, y)
    privateKey = (p, x)

    plaintext = "MLADEN"

    ciphertext = elGamalEncrypt(plaintext, publicKey)
    print(ciphertext)

    plaintextNew = elGamalDecrypt(ciphertext, privateKey)
    print(plaintextNew)

    print("TEASTA")
    print(publicKey)
    byte = elGamalKeyToBytes(publicKey)
    print(byte)
    print(elGamalBytesToKey(byte))

