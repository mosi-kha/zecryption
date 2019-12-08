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


def write_file(file_name, content, mode):
    with open(os.path.join(args.destination, file_name), mode=mode) as f:
        f.write(content)


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


def AES_encrypt(key, source):
    try:
        _key = check_args_type(key)
        _data = check_args_type(source)
        if not _key:  # generate AES128 key
            _key = get_random_bytes(16)  # AES128
            write_file('AES_key.bin', _key, 'wb')

        cipher = AES.new(_key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(_data)

        _file_name = input('Output file name with format(default:`AES_encrypted.bin`): ')
        if not _file_name:
            _file_name = 'AES_encrypted.bin'
        with open(os.path.join(os.getcwd(), _file_name), 'wb') as f:
            [f.write(x) for x in (cipher.nonce, tag, cipher_text)]
        green_print('Successfully AES Encrypted')
        sys.exit()
    except Exception as ex:
        red_print(f'Failed : {ex.__str__()}')
        sys.exit(1)


def AES_decrypt(source, key):
    try:
        _key = check_args_type(key)

        file = None
        if os.path.isfile(source):
            with open(file=source, mode='rb') as f:
                file = f

        elif os.path.isfile(os.path.join(os.getcwd(), source)):
            with open(file=os.path.join(os.getcwd(), source), mode='rb') as f:
                file = f

        nonce, tag, cipher_text = [file.read(x) for x in (16, 16, -1)]

        # let's assume that the key is somehow available again
        cipher = AES.new(_key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(cipher_text, tag)

        _file_name = input('Output File Name with format:')

        write_file(_file_name, data, 'wb')
        green_print('Successfully AES Decrypt')
        sys.exit()
    except Exception as ex:
        red_print(f'Failed: {ex.__str__()}')
        sys.exit(1)


def RSA_key_generate():
    try:
        key = RSA.generate(2048)
        if args.passphrase:
            private_key = key.export_key(passphrase=args.passphrase)
        else:
            private_key = key.export_key()
        with open(os.path.join(args.destination, "private.pem"), "wb") as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open(os.path.join(args.destination, "public.pem"), "wb") as f:
            f.write(public_key)
        green_print('Successfully RSA Key Generated')
        return public_key
    except Exception as ex:
        red_print(f'Failed: {ex.__str__()} ')
        sys.exit(1)


def RSA_encrypt(key, source, dest):
    try:
        _key = check_args_type(key)
        _data = check_args_type(source)

        if not _key:
            _key = RSA_key_generate()

        with open(dest, 'RSA_encrypted.bin') as f:
            p_key = RSA.import_key(_key)
            session_key = get_random_bytes(16)

            # Encrypt the session key with the public RSA key
            cipher_rsa = PKCS1_OAEP.new(p_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            # Encrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(_data)
            [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        print('Successfully RSA Encrypted')
        sys.exit()
    except Exception as ex:
        red_print(f'Failed: {ex.__str__()}')
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
        write_file(_file_name, data, 'w')

        green_print(f'Successfully RSA Decrypted \n View {os.path.join(dest, _file_name)}')
        sys.exit()
    except Exception as ex:
        red_print(f"FAILED: {ex.__str__()}")
        sys.exit(1)


if __name__ == '__main__':
    init()  # colorama

    z_parser = argparse.ArgumentParser(
        prog='Zecryption',
        description='EaZy Encryption and Decryption',
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
        metavar='Passphrase',
        action='store',
        help='for generate RSA key'
    )

    args = z_parser.parse_args()
    # print(vars(args))

    if not os.path.isdir(args.destination):
        raise NotADirectoryError

    if args.mode == 'e' and args.algorithm == 'AES':
        AES_encrypt(key=args.key, source=args.source)
    elif args.mode == 'd' and args.algorithm == 'AES':
        AES_decrypt(source=args.source, key=args.key)
    elif args.mode == 'e' and args.algorithm == 'RSA':
        RSA_encrypt(args.key, args.source, args.destination)
    elif args.mode == 'd' and args.algoritm == 'RSA':
        RSA_decrypt(args.source, args.keym, args.destination)
