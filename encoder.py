import os
import base64
import binascii
import subprocess
import requests
import time
import sys
from colorama import Fore, init

# Initialize colorama for colored output
init(autoreset=True)

def check_for_updates():
    print(Fore.YELLOW + "Checking for updates...")
    repo_url = 'BLACK-NINJA-PK/Encoder-Decoder'
    api_url = f'https://api.github.com/repos/{repo_url}/commits/main'
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        latest_commit = response.json().get('sha')
        
        try:
            current_commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode()
        except subprocess.CalledProcessError:
            print(Fore.RED + "Error: Could not retrieve the current commit. Are you in a Git repository?")
            return

        if latest_commit != current_commit:
            print(Fore.RED + "New update available. Updating...")
            update_script()
        else:
            print(Fore.GREEN + "Your script is up to date.")
    except requests.RequestException as e:
        print(Fore.RED + f"Failed to check for updates: {e}")

def update_script():
    try:
        subprocess.run(["git", "pull"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(Fore.GREEN + "Script updated successfully!")
        time.sleep(2)
        print(Fore.CYAN + f"\nTo run the script again, use the command:\npython {os.path.basename(__file__)}")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Failed to update the script: {e}")
    except PermissionError:
        print(Fore.RED + "Permission denied. Try running the script with elevated permissions (e.g., 'sudo').")

# Encoding functions
def en_base2(data):
    return "0" + bin(int(binascii.hexlify(data), 16))[2:]

def en_base16(data):
    return base64.b16encode(data).decode()

def en_base32(data):
    return base64.b32encode(data).decode()

def en_base58(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, 'big')
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    return encoded

def en_base64(data):
    return base64.b64encode(data).decode()

def en_urlsafe_base64(data):
    return base64.urlsafe_b64encode(data).decode()

def en_all(data):
    return (
        "Binary: " + en_base2(data) + "\n" +
        "Base16: " + en_base16(data) + "\n" +
        "Base32: " + en_base32(data) + "\n" +
        "Base58: " + en_base58(data) + "\n" +
        "Base64: " + en_base64(data) + "\n" +
        "URL-safe Base64: " + en_urlsafe_base64(data)
    )

def encode_file(file_path, encoding_type):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        if encoding_type == "b":
            return "Binary: " + en_base2(data)
        elif encoding_type == "b16":
            return "Base16: " + en_base16(data)
        elif encoding_type == "b32":
            return "Base32: " + en_base32(data)
        elif encoding_type == "b58":
            return "Base58: " + en_base58(data)
        elif encoding_type == "b64":
            return "Base64: " + en_base64(data)
        elif encoding_type == "urlsafe_b64":
            return "URL-safe Base64: " + en_urlsafe_base64(data)
        elif encoding_type == "all":
            return en_all(data)
        else:
            print("Error: Unsupported Encoding Type")
            return None
    except FileNotFoundError:
        print("Error: File not found. Please check the file path.")
        return None

def save_encoded_data_to_file(original_file_path, encoded_data):
    base_name, ext = os.path.splitext(original_file_path)
    new_file_name = f"{base_name}_encoded{ext}"

    with open(new_file_name, 'w') as encoded_file:
        encoded_file.write(encoded_data)

    print(f"Encoded data saved to: {new_file_name}")

def main_menu():
    print("\nEncoding Menu:")
    print("1. Binary (Base2)")
    print("2. Base16 (Hexadecimal)")
    print("3. Base32")
    print("4. Base58")
    print("5. Base64")
    print("6. URL-safe Base64")
    print("7. Encode with All Methods")
    print("0. Quit")
    choice = input(" >>  ")
    exec_menu(choice)

def exec_menu(choice):
    if choice == '1':
        encode_option("b")
    elif choice == '2':
        encode_option("b16")
    elif choice == '3':
        encode_option("b32")
    elif choice == '4':
        encode_option("b58")
    elif choice == '5':
        encode_option("b64")
    elif choice == '6':
        encode_option("urlsafe_b64")
    elif choice == '7':
        encode_option("all")
    elif choice == '0':
        exit_()
    else:
        print("Invalid selection, please try again.")
        main_menu()

def encode_option(encoding_type):
    file_path = input("Enter the path to the file you want to encode: ")
    if os.path.isfile(file_path):
        encoded_data = encode_file(file_path, encoding_type)
        if encoded_data:
            print("Encoded Data:\n", encoded_data)
            save_choice = input("Do you want to save the encoded data to a file? (y/n): ").lower()
            if save_choice == 'y':
                save_encoded_data_to_file(file_path, encoded_data)
    else:
        print("Error: File not found.")
    main_menu()

def exit_():
    print("Exiting the program.")
    exit()

if __name__ == "__main__":
    check_for_updates()
    main_menu()
