import os
import base64
import binascii
import marshal
import zlib
import pickle
import sys
import random
import pyfiglet
from colorama import Fore, Style, init

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

# Decoding functions
def decode_base2(encoded_data):
    return bytes.fromhex(hex(int(encoded_data, 2))[2:]).decode()

def decode_base16(encoded_data):
    return base64.b16decode(encoded_data).decode()

def decode_base32(encoded_data):
    return base64.b32decode(encoded_data).decode()

def decode_base64(encoded_data):
    return base64.b64decode(encoded_data).decode()

def decode_urlsafe_base64(encoded_data):
    return base64.urlsafe_b64decode(encoded_data).decode()

def decode_marshal(encoded_data):
    code_object = marshal.loads(encoded_data)
    exec(code_object)

def decode_zlib_base64(encoded_data):
    compressed_data = base64.b64decode(encoded_data)
    decompressed_data = zlib.decompress(compressed_data)
    return decompressed_data.decode()

def decode_hex(encoded_data):
    return bytes.fromhex(encoded_data).decode()

def decode_xor_base64(encoded_data, key=0x42):
    xor_encoded = base64.b64decode(encoded_data).decode()
    return ''.join(chr(ord(c) ^ key) for c in xor_encoded)

def decode_pickle_base64(encoded_data):
    data = base64.b64decode(encoded_data)
    return pickle.loads(data)

# Decoding execution function
def try_decoding(encoded_data, file_path):
    results = []

    try:
        results.append(f"Base2 Decode: {decode_base2(encoded_data)}")
    except Exception:
        results.append("Base2 failed.")

    try:
        results.append(f"Base16 Decode: {decode_base16(encoded_data)}")
    except Exception:
        results.append("Base16 failed.")

    try:
        results.append(f"Base32 Decode: {decode_base32(encoded_data)}")
    except Exception:
        results.append("Base32 failed.")

    try:
        results.append(f"Base64 Decode: {decode_base64(encoded_data)}")
    except Exception:
        results.append("Base64 failed.")

    try:
        results.append(f"URL-safe Base64 Decode: {decode_urlsafe_base64(encoded_data)}")
    except Exception:
        results.append("URL-safe Base64 failed.")

    try:
        results.append(f"Marshal Decode: {decode_marshal(encoded_data)}")
    except Exception:
        results.append("Marshal failed.")

    try:
        results.append(f"zlib Base64 Decode: {decode_zlib_base64(encoded_data)}")
    except Exception:
        results.append("zlib Base64 failed.")

    try:
        results.append(f"Hex Decode: {decode_hex(encoded_data)}")
    except Exception:
        results.append("Hex failed.")

    try:
        results.append(f"XOR Base64 Decode: {decode_xor_base64(encoded_data)}")
    except Exception:
        results.append("XOR Base64 failed.")

    try:
        results.append(f"Pickle Base64 Decode: {decode_pickle_base64(encoded_data)}")
    except Exception:
        results.append("Pickle Base64 failed.")

    # Display results
    for result in results:
        print(result)

    # Save the decoded result to a new file
    decoded_file_name = os.path.splitext(file_path)[0] + "_decoded.py"
    with open(decoded_file_name, "w") as decoded_file:
        for result in results:
            decoded_file.write(result + "\n")

    print(Fore.GREEN + f"\nDecoding complete. Results saved to {decoded_file_name}.")

# Main menu for user interaction
def main_menu():
    print(Fore.LIGHTCYAN_EX + "\nDecoding Menu:")
    print(Fore.LIGHTYELLOW_EX + "1. Try all decoding methods automatically")
    print(Fore.RED + "0. Quit")
    
    choice = input(Fore.GREEN + ">>>>:")
    
    if choice == "0":
        sys.exit()
    elif choice == "1":
        file_path = input(Fore.YELLOW + "Enter the file path containing encoded data: ")
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                encoded_data = file.read()
                try_decoding(encoded_data, file_path)
        else:
            print(Fore.RED + "The file path does not exist.")
    else:
        print(Fore.RED + "Invalid choice.")

if __name__ == "__main__":
    display_banner_and_social()
    main_menu()
