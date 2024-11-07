import os
import base64
import binascii
import marshal
import zlib
import pickle
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
import hashlib
import pyfiglet
from colorama import Fore, Style, init
import codecs
import random 

# Initialize colorama for colored output
init(autoreset=True)

# Banner text and social media information
banner_text = "NINJA"
social_media_usernames = [
    ("TELEGRAM", "@black_ninja_pk"),
    ("Coder", "@crazy_arain"),
]

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def create_gradient_banner(text):
    fonts = ['slant', 'banner3-D', 'block', 'digital', 'banner', 'isometric1']
    selected_font = random.choice(fonts)
    banner = pyfiglet.figlet_format(text, font=selected_font).splitlines()
    
    colors = [Fore.GREEN + Style.BRIGHT, Fore.YELLOW + Style.BRIGHT, Fore.RED + Style.BRIGHT]
    total_lines = len(banner)
    section_size = total_lines // len(colors)
    
    for i, line in enumerate(banner):
        if i < section_size:
            print(colors[0] + line)
        elif i < section_size * 2:
            print(colors[1] + line)
        else:
            print(colors[2] + line)

def display_banner_and_social():
    clear_console()
    create_gradient_banner(banner_text)
    print(Fore.LIGHTMAGENTA_EX + "Follow us on:")
    for platform_name, username in social_media_usernames:
        print(f"{Fore.CYAN}{platform_name + ':'} {Fore.GREEN}{username}")


# Padding functions for AES encryption
def pad(data):
    padding_length = 16 - (len(data) % 16)
    return data + (chr(padding_length) * padding_length).encode()

def unpad(data):
    return data[:-data[-1]]


# Encoding functions
def en_base2(data):
    return "0" + bin(int(binascii.hexlify(data), 16))[2:]

def en_base16(data):
    return base64.b16encode(data).decode()

def en_base32(data):
    return base64.b32encode(data).decode()

def en_base64(data):
    return base64.b64encode(data).decode()

def en_urlsafe_base64(data):
    return base64.urlsafe_b64encode(data).decode()

def en_marshal(data):
    code = compile(data, '<string>', 'exec')
    return marshal.dumps(code)

def en_zlib_base64(data):
    compressed_data = zlib.compress(data)
    return base64.b64encode(compressed_data).decode()

def en_hex(data):
    return data.hex()

def en_xor_base64(data, key=0x42):
    xor_encoded = ''.join(chr(byte ^ key) for byte in data)
    return base64.b64encode(xor_encoded.encode()).decode()

def en_pickle_base64(data):
    return base64.b64encode(pickle.dumps(data)).decode()

def en_aes_base64_cfb(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    encoded = base64.b64encode(cipher.iv + ciphertext).decode()
    return encoded, key

def en_aes_base64_cbc(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_base64 = base64.b64encode(iv + encrypted_data).decode()
    return encrypted_base64, key

def en_rsa_base64(data):
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher = public_key.encrypt(data, 32)
    encrypted_data = base64.b64encode(cipher[0]).decode()
    return encrypted_data, key.export_key()

def en_des_base64(data):
    key = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = get_random_bytes(8)
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_base64 = base64.b64encode(iv + encrypted_data).decode()
    return encrypted_base64, key

def en_blowfish_base64(data):
    key = get_random_bytes(16)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = get_random_bytes(8)
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_base64 = base64.b64encode(iv + encrypted_data).decode()
    return encrypted_base64, key

def en_sha256_aes_base64(data):
    key = hashlib.sha256(get_random_bytes(16)).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_base64 = base64.b64encode(iv + encrypted_data).decode()
    return encrypted_base64, key


def encode_file(file_path, encoding_type):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
            if encoding_type == "b2":
                encoded_data = en_base2(data)
                exec_code = f'print("{encoded_data}")'
            elif encoding_type == "b16":
                encoded_data = en_base16(data)
                exec_code = f'import base64\nexec(base64.b16decode("{encoded_data}".encode()).decode())'
            elif encoding_type == "b32":
                encoded_data = en_base32(data)
                exec_code = f'import base64\nexec(base64.b32decode("{encoded_data}".encode()).decode())'
            elif encoding_type == "b64":
                encoded_data = en_base64(data)
                exec_code = f'import base64\nexec(base64.b64decode("{encoded_data}".encode()).decode())'
            elif encoding_type == "urlsafe_b64":
                encoded_data = en_urlsafe_base64(data)
                exec_code = f'import base64\nexec(base64.urlsafe_b64decode("{encoded_data}".encode()).decode())'
            elif encoding_type == "marshal":
                code_object = en_marshal(data.decode())
                exec_code = f'import marshal\nexec(marshal.loads({repr(code_object)}))'
            elif encoding_type == "zlib_base64":
                encoded_data = en_zlib_base64(data)
                exec_code = f'import base64, zlib\nexec(zlib.decompress(base64.b64decode("{encoded_data}".encode())).decode())'
            elif encoding_type == "hex":
                encoded_data = en_hex(data)
                exec_code = f'exec(bytes.fromhex("{encoded_data}").decode())'
            elif encoding_type == "xor_base64":
                encoded_data = en_xor_base64(data)
                exec_code = f'import base64; exec("".join(chr(ord(c) ^ 0x42) for c in base64.b64decode("{encoded_data}".encode()).decode()))'
            elif encoding_type == "pickle_base64":
                encoded_data = en_pickle_base64(data)
                exec_code = f'import pickle, base64; exec(pickle.loads(base64.b64decode("{encoded_data}")))'
            elif encoding_type == "aes_base64_cfb":
                encoded_data, key = en_aes_base64_cfb(data)
                exec_code = f'import base64; from Crypto.Cipher import AES; key={key}; iv_ciphertext=base64.b64decode("{encoded_data}"); iv=iv_ciphertext[:16]; ciphertext=iv_ciphertext[16:]; cipher=AES.new(key, AES.MODE_CFB, iv=iv); exec(cipher.decrypt(ciphertext).decode())'
            elif encoding_type == "aes_base64_cbc":
                encoded_data, key = en_aes_base64_cbc(data)
                key_hex = key.hex()
                exec_code = f'''
import base64
from Crypto.Cipher import AES

def pad(data):
    padding_length = 16 - (len(data) % 16)
    return data + (chr(padding_length) * padding_length).encode()

def unpad(data):
    return data[:-data[-1]]

encrypted_data = base64.b64decode("{encoded_data}")
key = bytes.fromhex("{key_hex}")
iv = encrypted_data[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
original_data = unpad(cipher.decrypt(encrypted_data[16:]))
exec(original_data.decode())
                '''
            elif encoding_type == "rsa":
                encoded_data, key = en_rsa_base64(data)
                exec_code = f'import base64; from Crypto.PublicKey import RSA; key = RSA.import_key({repr(key)}); encrypted_data = base64.b64decode("{encoded_data}"); decrypted_data = key.decrypt(encrypted_data); exec(decrypted_data.decode())'
            elif encoding_type == "des":
                encoded_data, key = en_des_base64(data)
                exec_code = f'import base64; from Crypto.Cipher import DES3; key = {repr(key)}; encrypted_data = base64.b64decode("{encoded_data}"); iv = encrypted_data[:8]; cipher = DES3.new(key, DES3.MODE_CBC, iv=iv); decrypted_data = cipher.decrypt(encrypted_data[8:]); exec(decrypted_data.decode())'
            elif encoding_type == "blowfish":
                encoded_data, key = en_blowfish_base64(data)
                exec_code = f'import base64; from Crypto.Cipher import Blowfish; key = {repr(key)}; encrypted_data = base64.b64decode("{encoded_data}"); iv = encrypted_data[:8]; cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv); decrypted_data = cipher.decrypt(encrypted_data[8:]); exec(decrypted_data.decode())'
            elif encoding_type == "sha256_aes":
                encoded_data, key = en_sha256_aes_base64(data)
                exec_code = f'import base64; from Crypto.Cipher import AES; key = {repr(key)}; encrypted_data = base64.b64decode("{encoded_data}"); iv = encrypted_data[:16]; cipher = AES.new(key, AES.MODE_CBC, iv=iv); decrypted_data = cipher.decrypt(encrypted_data[16:]); exec(decrypted_data.decode())'
            else:
                print("Error: Unsupported Encoding Type")
                return None
            
            # Write the encoded file with self-decoding functionality
            output_file_path = f"{file_path}_{encoding_type}_encoded.py"
            with open(output_file_path, 'w') as output_file:
                output_file.write(exec_code)

            print(Fore.GREEN + f"File encoded successfully: {output_file_path}")
    except Exception as e:
        print(Fore.RED + f"Error encoding file: {e}")

def quit_program():
    print(Fore.RED + "Exiting the program...")
    sys.exit()  # This will terminate the program

def exec_menu(choice):
    encoding_options = {
        "1": "b2",
        "2": "b16",
        "3": "b32",
        "4": "b64",
        "5": "urlsafe_b64",
        "6": "marshal",
        "7": "zlib_base64",
        "8": "hex",
        "9": "xor_base64",
        "10": "pickle_base64",
        "11": "aes_base64_cfb",
        "12": "aes_base64_cbc",
        "13": "rsa",
        "14": "des",
        "15": "blowfish",
        "16": "sha256_aes",
        "0": "quit",  # Added the quit option
    }

    if choice == "0":
        quit_program()  # Call quit_program if the user chooses to quit
    else:
        encoding_type = encoding_options.get(choice)
        if encoding_type:
            file_path = input(Fore.YELLOW + "Enter the file path to encode: ")
            encode_file(file_path, encoding_type)
        else:
            print(Fore.RED + "Invalid choice")

def main_menu():
    print(Fore.LIGHTCYAN_EX + "\nEncoding Menu:")
    print(Fore.LIGHTYELLOW_EX + "1. Binary (Base2)")
    print(Fore.LIGHTGREEN_EX + "2. Base16 (Hexadecimal)")
    print(Fore.LIGHTCYAN_EX + "3. Base32")
    print(Fore.LIGHTYELLOW_EX + "4. Base64")
    print(Fore.LIGHTGREEN_EX + "5. URL-safe Base64")
    print(Fore.LIGHTCYAN_EX + "6. Marshal (Python bytecode)")
    print(Fore.LIGHTYELLOW_EX + "7. zlib (Base64)")
    print(Fore.LIGHTGREEN_EX + "8. Hexadecimal")
    print(Fore.LIGHTCYAN_EX + "9. XOR (Base64)")
    print(Fore.LIGHTYELLOW_EX + "10. Pickle (Base64)")
    print(Fore.LIGHTGREEN_EX + "11. AES (Base64 CFB)")
    print(Fore.LIGHTCYAN_EX + "12. AES (Base64 CBC)")
    print(Fore.LIGHTYELLOW_EX + "13. RSA")
    print(Fore.LIGHTGREEN_EX + "14. DES")
    print(Fore.LIGHTCYAN_EX + "15. Blowfish")
    print(Fore.LIGHTYELLOW_EX + "16. SHA256 + AES")
    print(Fore.RED + "0. Quit")  # Added the quit option

    choice = input(Fore.GREEN + ">>>>:")
    exec_menu(choice)

if __name__ == "__main__":
    display_banner_and_social()
    main_menu()
