# PPK_Encryption
 Public-Private Key Encryption and Decryption
Public-Private Key Encryption and Decryption

Code Logic:

Key Pair Generation:
generatePublicPrivateKeyPair(): Generates a public-private key pair using the RSA algorithm with a specified public exponent and key size.

Encryption and Decryption Functions:
encryptDataWithPrivateKey(privateKey, data): Encrypts data using the private key, producing a signature using PSS padding and the SHA256 hashing algorithm.
decryptDataWithPublicKey(publicKey, cipherText): Decrypts the cipher text using the public key. Verifies the signature using PSS padding and SHA256 hashing algorithm. If the signature is valid, returns the decrypted data.

File I/O Functions:
writeToFile(filename, content): Writes content to a file with the specified filename.
readFromFile(filename, fileMode='rb'): Reads content from a file with the specified filename and file mode.

Main Execution:
Generates a new public-private key pair.
Defines a sample data to be encrypted.
Encrypts the data using the private key and saves the cipher text to a file named "ciphertext.bin".
Reads the cipher text from the file.
Decrypts the cipher text using the public key. If successful, writes the decrypted data to a file named "decryptedData.txt".

This code demonstrates how to generate an RSA key pair, encrypt data using the private key, and decrypt it using the corresponding public key, showcasing the fundamentals of asymmetric encryption and decryption using the RSA algorithm with the cryptography library in Python.






