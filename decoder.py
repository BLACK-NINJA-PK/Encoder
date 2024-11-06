import base64
import binascii
import zlib
import marshal
import pickle
import os

# Decode Binary (Base2)
def decode_binary(binary_str):
    return ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))

# Decode Hexadecimal (Base16)
def decode_base16(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

# Decode Base32
def decode_base32(base32_str):
    return base64.b32decode(base32_str).decode('utf-8')

# Decode Base64
def decode_base64(base64_str):
    return base64.b64decode(base64_str).decode('utf-8')

# Decode URL-safe Base64
def decode_url_safe_base64(url_safe_base64_str):
    return base64.urlsafe_b64decode(url_safe_base64_str).decode('utf-8')

# Decode Marshal (Python bytecode)
def decode_marshal(marshal_str):
    return marshal.loads(base64.b64decode(marshal_str))

# Decode zlib (Base64)
def decode_zlib_base64(zlib_base64_str):
    decoded_data = base64.b64decode(zlib_base64_str)
    return zlib.decompress(decoded_data).decode('utf-8')

# Decode Hexadecimal
def decode_hex(hex_str):
    return binascii.unhexlify(hex_str).decode('utf-8')

# Decode XOR (Base64)
def decode_xor_base64(xor_base64_str, key=0xAA):
    decoded_data = base64.b64decode(xor_base64_str)
    return ''.join(chr(byte ^ key) for byte in decoded_data)

# Decode Pickle (Base64)
def decode_pickle_base64(pickle_base64_str):
    decoded_data = base64.b64decode(pickle_base64_str)
    return pickle.loads(decoded_data)

# Try decoding with all methods
def try_decoding(encoded_data):
    results = []

    try:
        decoded_data = base64.b64decode(encoded_data)
        results.append(f"Base64 Decode: {decoded_data.decode('utf-8')}")
    except Exception as e:
        results.append("Base64 failed.")

    try:
        decoded_data = base64.b32decode(encoded_data)
        results.append(f"Base32 Decode: {decoded_data.decode('utf-8')}")
    except Exception as e:
        results.append("Base32 failed.")

    try:
        decoded_data = bytes.fromhex(encoded_data)
        results.append(f"Hex Decode: {decoded_data.decode('utf-8')}")
    except Exception as e:
        results.append("Hex failed.")

    try:
        decoded_data = base64.b64decode(encoded_data)
        decompressed_data = zlib.decompress(decoded_data)
        results.append(f"Zlib Decode: {decompressed_data.decode('utf-8')}")
    except Exception as e:
        results.append("Zlib failed.")

    try:
        decoded_data = base64.b64decode(encoded_data)
        result = marshal.loads(decoded_data)
        results.append(f"Marshal Decode: {result}")
    except Exception as e:
        results.append("Marshal failed.")

    try:
        decoded_data = base64.b64decode(encoded_data)
        result = pickle.loads(decoded_data)
        results.append(f"Pickle Decode: {result}")
    except Exception as e:
        results.append("Pickle failed.")

    try:
        xor_keys = [0xAA, 0xFF, 0x00]  # Common XOR keys
        for key in xor_keys:
            decoded_data = base64.b64decode(encoded_data)
            xor_decoded = ''.join(chr(byte ^ key) for byte in decoded_data)
            results.append(f"XOR (key {hex(key)}) Decode: {xor_decoded}")
    except Exception as e:
        results.append("XOR failed.")

    try:
        decoded_data = base64.urlsafe_b64decode(encoded_data)
        results.append(f"URL-safe Base64 Decode: {decoded_data.decode('utf-8')}")
    except Exception as e:
        results.append("URL-safe Base64 failed.")

    try:
        decoded_data = decode_binary(encoded_data)
        results.append(f"Binary (Base2) Decode: {decoded_data}")
    except Exception as e:
        results.append("Binary failed.")

    # Save the results to a file
    with open("decoded_output.txt", "w") as f:
        for line in results:
            f.write(line + "\n")
    
    print("Decoding complete. Results saved to decoded_output.txt.")

def main():
    print("Choose an option:")
    print("1. Manually choose a decoding method")
    print("2. Try all decoding methods automatically")
    choice = input("Enter your choice (1/2): ")

    if choice == '1':
        print("Available decoding methods:")
        print("1. Base64")
        print("2. Base32")
        print("3. Hexadecimal")
        print("4. Zlib (Base64)")
        print("5. Marshal")
        print("6. Pickle")
        print("7. XOR (Base64)")
        print("8. URL-safe Base64")
        print("9. Binary (Base2)")
        method = input("Choose a method to decode (1-9): ")

        encoded_data = input("Enter the encoded data: ")

        if method == '1':
            print(decode_base64(encoded_data))
        elif method == '2':
            print(decode_base32(encoded_data))
        elif method == '3':
            print(decode_hex(encoded_data))
        elif method == '4':
            print(decode_zlib_base64(encoded_data))
        elif method == '5':
            print(decode_marshal(encoded_data))
        elif method == '6':
            print(decode_pickle_base64(encoded_data))
        elif method == '7':
            print(decode_xor_base64(encoded_data))
        elif method == '8':
            print(decode_url_safe_base64(encoded_data))
        elif method == '9':
            print(decode_binary(encoded_data))
        else:
            print("Invalid method chosen.")
    elif choice == '2':
        # Automatically try all decoding methods
        file_path = input("Enter the file path containing encoded data: ")

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                encoded_data = file.read()
                try_decoding(encoded_data)
        else:
            print("The file path does not exist.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
