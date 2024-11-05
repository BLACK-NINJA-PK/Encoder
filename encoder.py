import base64
import binascii
import os

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

        encoded_results = ""
        if encoding_type == "b":
            encoded_results = "Binary: " + en_base2(data)
        elif encoding_type == "b16":
            encoded_results = "Base16: " + en_base16(data)
        elif encoding_type == "b32":
            encoded_results = "Base32: " + en_base32(data)
        elif encoding_type == "b58":
            encoded_results = "Base58: " + en_base58(data)
        elif encoding_type == "b64":
            encoded_results = "Base64: " + en_base64(data)
        elif encoding_type == "urlsafe_b64":
            encoded_results = "URL-safe Base64: " + en_urlsafe_base64(data)
        elif encoding_type == "all":
            encoded_results = en_all(data)
        else:
            print("Error: Unsupported Encoding Type")
            return

        # Save to a new file
        save_encoded_file(file_path, encoded_results)

    except FileNotFoundError:
        print("Error: File not found. Please check the file path.")

def save_encoded_file(original_file_path, encoded_data):
    # Create a new filename
    base_name = os.path.basename(original_file_path)
    name, ext = os.path.splitext(base_name)
    new_file_name = f"{name}_encoded.txt"
    
    # Write the encoded data to a new file
    with open(new_file_name, 'w') as encoded_file:
        encoded_file.write(encoded_data)
    
    print(f"Encoded data saved to: {new_file_name}")

# Main menu
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

# Execute menu
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
        encode_file(file_path, encoding_type)
    else:
        print("Error: File not found.")
    main_menu()

def exit_():
    print("Exiting the program.")
    exit()

# Start the program
if __name__ == "__main__":
    main_menu()