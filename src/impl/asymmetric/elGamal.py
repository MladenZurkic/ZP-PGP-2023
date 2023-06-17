import base64
import pickle
from Crypto.Util import number


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

    if not isinstance(plaintext, bytes):
        plaintextBytes = plaintext.encode()
    else:
        plaintextBytes = plaintext
    plaintextEncoded = int.from_bytes(plaintextBytes, 'big')

    c2 = (plaintextEncoded * pow(y, k, p)) % p
    return c1, c2


def elGamalDecrypt(ciphertext, privateKey):
    p, x = privateKey
    c1, c2 = pickle.loads(ciphertext)

    s = pow(c1, x, p)
    sInverse = number.inverse(s, p)

    plaintextEncoded = (c2 * sInverse) % p

    try:
        plaintext = plaintextEncoded.to_bytes((plaintextEncoded.bit_length() + 7) // 8, 'big').decode()
    except:
        plaintext = plaintextEncoded.to_bytes((plaintextEncoded.bit_length() + 7) // 8, 'big')

    return plaintext


def elGamalKeyToBytes(key):
    return pickle.dumps(key)


def elGamalBytesToKey(key):
    return pickle.loads(key)


def elGamalKeyToBase64(key):
    keyBytesList = []
    for element in key:
        byteSize = (element.bit_length() + 7) // 8
        byteValue = element.to_bytes(byteSize, 'big')
        keyBytesList.append(byteValue)

    concatenateKeyBytes = b''.join(keyBytesList)
    encodedKeyBytes = base64.b64encode(concatenateKeyBytes)
    encodedString = encodedKeyBytes.decode('utf-8')

    return encodedString


def elGamalBase64ToKey(key):
    decodedKeyBytes = base64.b64decode(key)
    byteKeySize = len(key) // 4
    bytesKeyList = [
        decodedKeyBytes[i: min(i + byteKeySize, len(decodedKeyBytes))]
        for i in range(0, len(decodedKeyBytes), byteKeySize)
    ]
    decodedKeyTuple = tuple(int.from_bytes(bytesElement, 'big') for bytesElement in bytesKeyList)

    return decodedKeyTuple


if __name__ == '__main__':
    p, g, x, y = elGamalGenerateKeys(1024)
    publicKey = (p, g, y)
    enc = elGamalKeyToBase64(publicKey)
    publicKeyRec = elGamalBase64ToKey(enc)

    print(publicKey == publicKeyRec)
