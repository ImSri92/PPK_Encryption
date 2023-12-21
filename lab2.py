from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os

def generatePublicPrivateKeyPair():
    generatedPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    generatedPublicKey = generatedPrivateKey.public_key()
    return generatedPrivateKey, generatedPublicKey

def encryptDataWithPrivateKey(privateKey, data):
    cipherText = privateKey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return cipherText

def decryptDataWithPublicKey(publicKey, cipherText):
    try:
        publicKey.verify(
            cipherText,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return data
    except InvalidSignature:
        print("Decryption failed. Invalid signature.")
        return None

def writeToFile(filename, content):
    fileMode = 'wb' if isinstance(content, bytes) else 'w'
    with open(filename, fileMode) as f:
        f.write(content)

def readFromFile(filename, fileMode='rb'):
    with open(filename, fileMode) as f:
        content = f.read()
    return content

if __name__ == "__main__":
    privateKey, publicKey = generatePublicPrivateKeyPair()
    data = b"Hello Professor Berry, From Bhargav Vytla"
    cipherText = encryptDataWithPrivateKey(privateKey, data)
    writeToFile("ciphertext.bin", cipherText)
    cipherTextFromFile = readFromFile("ciphertext.bin")
    decryptedData = decryptDataWithPublicKey(publicKey, cipherTextFromFile)
    if decryptedData:
        writeToFile("decryptedData.txt", decryptedData.decode('utf-8'))