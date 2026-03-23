from Crypto.PublicKey import RSA

def generar_par_claves(bits: int = 3072, 
                       pwd: str= '', 
                       private_route: str = 'keys/private.pem',
                       public_route: str = 'keys/public.pem'
                       ) -> tuple[bytes, bytes]:
    """
    Genera un par de claves para cifrado y descifrado RSA en formato .pem
    Args:
        bits (int): la cantidad de bits de la llave RSA (por defecto 3072)
        pwd (str): passphrase para nuestra llave provada (por defecto vacía)
        private_route (str): la ruta en donde vamos a guardar la llave privada en formato .pem
        public_route (str): la ruta en donde vamos a guardar la llave pública en formato .pem
    Returns:
        private_key (bytes): la llave privada
        public_key (bytes): la llave pública
    """

    key = RSA.generate(bits)
    
    private_key = key.export_key(passphrase = pwd) if pwd != '' else key.export_key()      
    public_key  = key.publickey().export_key()

    with open(private_route, 'wb') as f:
        f.write(private_key)
    with open(public_route, 'wb') as f:
        f.write(public_key)

    print('Clave privada:')
    print(private_key.decode())
    print('\nClave pública:')
    print(public_key.decode())

    return private_key, public_key

if __name__ == '__main__':

    private, public = generar_par_claves(3072, 'lab04uvg', 'keys/private1.pem', 'keys/public1.pem')
    print(f'Llave publica {private},  llave privada {public}')






