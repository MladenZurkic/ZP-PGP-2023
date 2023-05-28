import base64
import pickle


def encodeToRadix64(data):
    dataBytes = pickle.dumps(data)
    return base64.b64encode(dataBytes)


def decodeFromRadix64(data):
    dataBytes = base64.b64decode(data)
    return pickle.loads(dataBytes)



if __name__ == '__main__':
    data = "test123"
    encoded = encodeToRadix64(data)
    print(encoded)
    decoded = decodeFromRadix64(encoded)
    print(decoded)