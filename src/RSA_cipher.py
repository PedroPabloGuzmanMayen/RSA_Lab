from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from generar_claves import *

def cipher_rsa(message: bytes, public_key_pem: str) -> bytes:
    """
    Cifra un mensaje usando RSA

    Args:
        message (bytes): el mensaje a cifrar en bytes
        public_key_pem (bytes): la llave pública en bytes

    Returns:
        bytes:el mensaje cifrado en bytes
    """
    key = RSA.importKey(open(public_key_pem).read())
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def decipher_rsa(ciphertext: bytes, private_key_pem: str, pwd: str) -> bytes:
    """
    Descifra un mensaje usando RSA

    Args:
        ciphertext (bytes): El texto o mensaje que queremos descifrar en bytes
        private_key_pem (bytes):la llave privada

    Returns:
        bytes: el mensaje descifrado en bytes
    """
    key = RSA.importKey(open(private_key_pem).read(), passphrase = pwd if pwd != '' else None)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)

if __name__ == '__main__':
    while True:
        print('\n--- RSA MENU ---')
        print('1. Encriptar mensaje')
        print('2. Desencriptar mensaje')
        print('3. Salir')

        option = input('Selecciona una opción: ')

        if option == '1':
            message = input('Mensaje a encriptar: ').encode()
            public_path = input('Ruta de la llave pública: ')

            try:
                ciphertext = cipher_rsa(message, public_path)
                print('\nMensaje encriptado (hex):')
                print(ciphertext.hex())
            except Exception as e:
                print(f'Error: {e}')

        elif option == '2':
            ciphertext_hex = input('Mensaje encriptado (hex): ')
            private_path = input('Ruta de la llave privada: ')
            passphrase = input('Passphrase: ')

            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
                plaintext = decipher_rsa(ciphertext, private_path, passphrase)

                print('\nMensaje desencriptado:')
                print(plaintext.decode())
            except Exception as e:
                print(f'Error: {e}')

        elif option == '3':
            print('Saliendo...')
            break

        else:
            print('Opción inválida')