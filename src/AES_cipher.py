import os
from RSA_cipher import *
from Crypto.Cipher import AES, PKCS1_OAEP
from generar_claves import *
import secrets
import base64

def encrypt_document(document: bytes, public_key: str) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Cifra un documento usando AES

    Args:
        document (bytes): los bytes del documento que queremos cifrar
        aes_key (bytes): La llave AES que vamos a usar para cifrar
    Returns:
        El documento cifrado con AES y la llave cifrada con RSA
    
    """
    aes_key = secrets.token_bytes(256// 8)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)

    return ciphertext, cipher_rsa(aes_key, public_key), cipher_aes.nonce, tag

def decrypt_document(cipher_document: bytes, 
                     key_cipher: bytes, 
                     private_key: str, 
                     passphrase: str, 
                     nonce: bytes,
                     tag: bytes) -> bytes:
    """
    Descifra un documento usando una llave RSA y el algoritmo AES GCM

    Args:
        cipher_document (bytes): el documento cifrado en bytes
        key_cipher (bytes): La llave AES cifrada en RSA
        private_key (str): La llave privada para descifrar RSA
        passphrase (str): passphrase de la llave privada
        nonce (bytes): el nonce usado para cifrar en AES
        tag(bytes): la tag generada al cifrar con AES el mensaje original

    Returns:
        El documento descifrado en bytes
    """

    print(f'Adentro, privada{private_key}')
    decrypted_key = decipher_rsa(key_cipher, private_key, passphrase)
    decipher_aes = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)

    return decipher_aes.decrypt_and_verify(cipher_document, tag)


if __name__ == '__main__':

    option = True

    while option:

        print('=== CIFRADO HÍBRIDO (AES + RSA) ===')

        opcion = input('¿Deseas (1) cifrar o (2) descifrar o (3) salir?: ')

        if opcion == '1':

            public_key_path = input('Ruta llave pública: ')

            tipo = input('¿(1) texto o (2) archivo .txt?: ')

            if tipo == '1':
                text = input('Mensaje: ')
                document = text.encode()

            elif tipo == '2':
                file_path = input('Ruta del archivo: ')
                with open(file_path, 'rb') as f:
                    document = f.read()
            else:
                print('Opción inválida')
                exit()

            ciphertext, encrypted_key, nonce, tag = encrypt_document(
                document, public_key_path
            )

            data = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'tag': base64.b64encode(tag).decode()
            }

            print('\n=== DATOS CIFRADOS ===')
            for k, v in data.items():
                print(f'{k}: {v}')

            output_file = input('\nNombre del archivo de salida (ej: encrypted.txt): ')

            with open(output_file, 'w') as f:
                for k, v in data.items():
                    f.write(f'{k}:{v}\n')

            print('Datos guardados correctamente')

        elif opcion == '2':

            private_key_path = input('Ruta llave privada: ')
            passphrase = input('Passphrase: ')
            input_file = input('Ruta del archivo cifrado (.txt): ')

            loaded_data = {}

            with open(input_file, 'r') as f:
                for line in f:
                    k, v = line.strip().split(':')
                    loaded_data[k] = base64.b64decode(v)

            print(f'PRIVADA: {private_key_path}')

            decrypted_document = decrypt_document(
                loaded_data['ciphertext'],
                loaded_data['encrypted_key'],
                private_key_path,
                passphrase,
                loaded_data['nonce'],
                loaded_data['tag']
            )
            """ 

            cipher_document: bytes, 
            key_cipher: bytes, 
            private_key: str, 
            passphrase: str, 
                     nonce: bytes,
                     tag: bytes) -> bytes:
            """

            print('\n=== DOCUMENTO DESCIFRADO ===')
            print(decrypted_document.decode(errors='ignore'))

            guardar = input('\n¿Guardar resultado? (s/n): ')

            if guardar.lower() == 's':
                output_file = input('Nombre del archivo (ej: decrypted.txt): ')
                with open(output_file, 'wb') as f:
                    f.write(decrypted_document)

                print('Archivo guardado')

        elif opcion == '3':
            print('Bye bye!')
            option = False

        else:
            print('Opción inválida')

            