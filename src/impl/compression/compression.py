import pickle
import zlib

def compress(data):
    dataBytes = pickle.dumps(data)
    return zlib.compress(dataBytes)


def decompress(compressedData):
    dataBytes = zlib.decompress(compressedData)
    return pickle.loads(dataBytes)


if __name__ == '__main__':
    data = "test123"
    data2 = b"Mladen i Filip"

    compressedData = compress(data)
    print(compressedData)
    originalData = decompress(compressedData)
    print(originalData)

    compressedData2 = compress(data2)
    print(compressedData2)
    originalData2 = decompress(compressedData2)
    print(originalData2)