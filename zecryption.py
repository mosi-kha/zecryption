import argparse
from hashlib import sha3_256
import subprocess
import os
import sys

while True:
    try:
        from colorama import init, Fore

        from Crypto.PublicKey import RSA
        from Crypto.Cipher import AES, PKCS1_OAEP
        from Crypto.Random import get_random_bytes

        break
    except ModuleNotFoundError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome', 'colorama '])

__version__ = '1.0'


def read_file(path, file_name, mode) -> str:
    if not path:
        path = os.path.join(os.getcwd(), file_name)
    else:
        path = os.path.join(path, file_name)
    response = ''
    try:
        with open(path, mode=mode) as f:
            response = f.read()
            return response
    except FileNotFoundError:
        pass


def write_file(file_name, content, mode):
    try:
        with open(os.path.join(os.getcwd(), file_name), mode=mode) as f:
            f.write(content)
    except Exception as e:
        print(e.__cause__)
        return 0


def check_args_type(arg: str) -> bytes:
    if os.path.isfile(arg):
        with open(file=arg, mode='rb') as f:
            return f.read()

    if os.path.isfile(os.path.join(os.getcwd(), arg)):
        with open(file=os.path.join(os.getcwd(), arg), mode='rb') as f:
            return f.read()
    return arg.encode()


def green_print(text):
    print(f"{Fore.GREEN}{text}")


def red_print(text):
    print(f"{Fore.RED}{text}")


def AES_encrypt(key, data):
    try:
        _key = check_args_type(key)
        _data = check_args_type(data)
        if not _key:  # generate AES128 key
            _key = get_random_bytes(16)  # AES128
            write_file('AES_key.bin', _key, 'wb')

        cipher = AES.new(_key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(_data)
        with open(os.path.join(os.getcwd(), 'AES_encrypted.bin'), 'wb') as f:
            [f.write(x) for x in (cipher.nonce, tag, cipher_text)]
        green_print('Successfully AES Encrypted')
        sys.exit()
    except Exception as ex:
        print(ex.__str__())
        red_print('Failed AES Encryption')
        sys.exit(1)


def AES_decrypt(key):
    try:
        _key = check_args_type(key)
        file = open('AES_encrypted.bin', 'rb')
        nonce, tag, cipher_text = [file.read(x) for x in (16, 16, -1)]

        # let's assume that the key is somehow available again
        cipher = AES.new(_key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(cipher_text, tag)
        print(data)
        write_file('AES_decrypted.txt', data, 'wb')
        green_print('Successfully AES Decrypt')
        sys.exit()
    except Exception as ex:
        print(ex.__str__())
        red_print('Failed AES Decryption')
        sys.exit(1)


def RSA_key_generate(path):
    try:
        key = RSA.generate(2048)
        if args.passphrase:
            private_key = key.export_key(passphrase=args.passphrase)
        else:
            private_key = key.export_key()
        with open(os.path.join(path, "private.pem"), "wb") as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open(os.path.join(path, "public.pem"), "wb") as f:
            f.write(public_key)
        green_print('Successfully RSA Key Generated')
        return public_key
    except Exception as ex:
        print(ex.__cause__)
        red_print('Failed RSA Key Generation')
        sys.exit(1)


def RSA_encrypt(key, data, dest):
    try:
        _key = check_args_type(key)
        _data = check_args_type(data)

        if not _key:
            _key = RSA_key_generate(dest)

        with open(dest, 'RSA_encrypted.bin') as f:
            p_key = RSA.import_key(_key)
            session_key = get_random_bytes(16)

            # Encrypt the session key with the public RSA key
            cipher_rsa = PKCS1_OAEP.new(p_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            # Encrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)
            [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        print('Successfully RSA Encrypted')
        sys.exit()
    except Exception as ex:
        print(ex.__str__())
        red_print('Failed RSA Encryption')
        sys.exit(1)


def RSA_decrypt(data, key, dest):
    try:
        _key = check_args_type(key)

        private_key = RSA.import_key(_key)

        file_in = None
        if os.path.isfile(data):
            with open(file=data, mode='rb') as f:
                file_in = f

        elif os.path.isfile(os.path.join(os.getcwd(), data)):
            with open(file=os.path.join(os.getcwd(), data), mode='rb') as f:
                file_in = f

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        data = data.decode("utf-8")

        # save to file
        _file_name = input('Output File Name with format:')

        with open(os.path.join(dest, _file_name), 'w') as f:
            f.write(data)

        green_print(f'Successfully RSA Decrypted \n View {os.path.join(dest, _file_name)}')
        sys.exit()
    except Exception as ex:
        red_print(f"FAILED: {ex.__str__()}")
        sys.exit(1)


if __name__ == '__main__':
    init()  # colorama

    z_parser = argparse.ArgumentParser(
        prog='Z-Locker',
        description='Zee Encryption and Decryption',
        epilog='Written By Mosi_kha :D')

    z_parser.version = __version__

    z_parser.add_argument(
        '-v',
        '--version',
        action='version'
    )

    z_parser.add_argument(
        'source',
        type=str,
        help='source file location'
    )
    z_parser.add_argument(
        'key',
        action='store',
        help='key or key file'
    )

    z_parser.add_argument(
        '-a',
        '--algorithm',
        action='store',
        choices=['RSA', 'AES', 'sha'],
        required=True
    )

    z_parser.add_argument(
        '-m',
        '--mode',
        action='store',
        choices=['e', 'd'],
        help=' "e" for encryption | "d" for decryption ',
        required=True
    )

    z_parser.add_argument(
        '-d',
        action='store',
        default=os.getcwd(),
        help='Save\'s Directory',
        metavar='Destination',
        dest='destination'
    )

    z_parser.add_argument(
        '-p',
        '--passphrase',
        action='store',
        help='for generate RSA key'
    )

    args = z_parser.parse_args()
    # print(vars(args))

    if args.destination:
        if not os.path.isdir(args.destination):
            raise NotADirectoryError

    if args.mode == 'e' and args.algorithm == 'AES':
        AES_encrypt(key=args.key, data=args.source)
    elif args.mode == 'd' and args.algorithm == 'AES':
        AES_decrypt(key=args.key)
    elif args.mode == 'e' and args.algorithm == 'RSA':
        RSA_encrypt(args.key, args.source, args.destination)
