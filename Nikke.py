from pathlib import Path
from struct import unpack
from hashlib import sha256
from Crypto.Cipher import AES

import argparse

SIGNATURE = 'NKAB'

def read_string(file, length=0x7FFF, encoding='utf-8'):
    value = file.read(length)
    return value.decode(encoding)

def read_i32(file):
    return int.from_bytes(file.read(4), 'little')

def read_obfs_i16(file):
    value = unpack('<h', file.read(2))[0]
    return value + 100

def decrypt(file):
    header = read_string(file, 4)
    if header != SIGNATURE:
        print('invalid header !!')
        exit(-1)

    version = read_i32(file)
    header_size = read_obfs_i16(file)
    encrypt_mode = read_obfs_i16(file)
    key_length = read_obfs_i16(file)
    encrypted_length = read_obfs_i16(file)

    key = file.read(key_length)
    iv = file.read(key_length)
    block = file.read(encrypted_length)

    hash = sha256(key).digest()
    header = AES.new(hash, AES.MODE_CBC, iv).decrypt(block)

    return header

def parse_args():
    parser = argparse.ArgumentParser('Nikke')
    parser.add_argument('input_folder', type=Path, help='Path to folder with encrypted files.')
    parser.add_argument('output_folder', type=Path, help='Path to folder to save decrypted files.')

    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    input_folder =  args.input_folder
    output_folder =  args.output_folder
    for path in input_folder.iterdir():
        with path.open('rb') as file:
            header = decrypt(file)
            data = file.read()
        
        new_path = Path(output_folder,path.relative_to(input_folder))
        if not new_path.parent.exists():
            new_path.parent.mkdir()

        with new_path.open('wb') as file:
            file.write(header)
            file.write(data)