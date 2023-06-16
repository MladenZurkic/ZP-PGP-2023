import base64
import pickle


def encodeToRadix64(data):
    # dataBytes = base64.b64decode(data)  # STRING -> BYTES
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')


def decodeFromRadix64(data):
    #data = base64.b64encode(dataBytes).decode('utf-8')  # BYTES -> STRING
    return base64.b64decode(data).decode('utf-8')



if __name__ == '__main__':
    data = "test123"
    encoded = encodeToRadix64(data)
    print(encoded)
    decoded = decodeFromRadix64(encoded)
    print(decoded)