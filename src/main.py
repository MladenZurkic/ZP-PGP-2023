from impl.hash.hash import hashSHA1Hex, hashSHA1, hashMD5

if __name__ == '__main__':

    print(len(hashMD5("Test123 Filip Mladen")))
    print(hashSHA1("Test123 Filip Mladen"))
    print(hashSHA1Hex("Test123 Filip Mladen"))