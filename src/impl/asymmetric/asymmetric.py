import pickle
import struct

from Crypto.Util import number
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import serialization
from src.impl.asymmetric.elGamal import elGamalGenerateKeys, elGamalEncrypt, elGamalKeyToBytes, elGamalBytesToKey, \
    elGamalDecrypt
from src.impl.hash.hash import hashMD5
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

from Crypto.PublicKey.RSA import import_key

from src.impl.keyrings.privatekeyring import PrivateKeyring

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

    print("TEASTA")
    print(publicKey)
    byte = elGamalKeyToBytes(publicKey)
    print(byte)
    print(elGamalBytesToKey(byte))


## MOZE DA BACI ValueError, sluzi da se prepozna kada nastane greska prilikom potpisivanja, ukoliko pascode nije dobro unet
## Bacice tu gresku!
def signData(algorithm, privateKey, data, passphrase):
    hashedPassword = hashMD5(passphrase)
    encryptedPrivateKey = privateKey.encryptedPrivateKey
    cipher = DES3.new(hashedPassword,DES3.MODE_ECB)

    decryptedPrivateKey2 = 0
    decryptedPrivateKey = cipher.decrypt(encryptedPrivateKey)
    decryptedPrivateKeyBytes = unpad(decryptedPrivateKey, BLOCK_SIZE)

    test = import_key(decryptedPrivateKeyBytes)
    print("TEST")
    print(test)
    # decryptedPrivateKey2 = serialization.load_der_private_key(decryptedPrivateKeyBytes, None)


    print(decryptedPrivateKey2)
    hashObject = SHA1.new()
    hashObject.update(data.encode())

    signer = pkcs1_15.new(test)
    signature = signer.sign(hashObject)



    return 1, None

    #*** Ovako vracamo
   # return 0, data

if __name__ == '__main__':
    # # testElGamal()
    # pk = PrivateKeyring()
    # pk.generateKeys("Mladen", "mladen@gmail.com", "RSA", 2048, "123F")
    # print(pk.privateKeyringSigning.values())
    #
    # key = list(pk.privateKeyringSigning)
    # privateKey = pk.getKeyForSigning(key[0])
    #
    # signData("RSA", privateKey, "Mladen123", "123E")


    pk = PrivateKeyring()
    pk.generateKeys("Mladen", "mladen@gmail.com", "RSA", 2048, "123FFFF")
    print(pk.privateKeyringSigning.values())

    key = list(pk.privateKeyringSigning)
    privateKey = pk.getKeyForSigning(key[0])



    print(signData("DSA", privateKey, "Mladen123", "123FFFE"))
    print("Print signdata")


    data = signData("RSA", privateKey, "Filip", "123")
    if(data[0]):
        print("GRESKA")

