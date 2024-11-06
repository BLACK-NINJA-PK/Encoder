import base64
import binascii
import zlib
import marshal
import pickle

def decode_unknown_data(encoded_data):
    try:
        # Try decoding as Base64
        try:
            decoded_data = base64.b64decode(encoded_data)
            print("Base64 Decode:", decoded_data.decode('utf-8'))
        except Exception as e:
            print("Base64 failed:", e)

        # Try decoding as Base32
        try:
            decoded_data = base64.b32decode(encoded_data)
            print("Base32 Decode:", decoded_data.decode('utf-8'))
        except Exception as e:
            print("Base32 failed:", e)

        # Try decoding as Hex
        try:
            decoded_data = bytes.fromhex(encoded_data)
            print("Hex Decode:", decoded_data.decode('utf-8'))
        except Exception as e:
            print("Hex failed:", e)

        # Try decoding as zlib-compressed Base64
        try:
            decoded_data = base64.b64decode(encoded_data)
            decompressed_data = zlib.decompress(decoded_data)
            print("Zlib Decode:", decompressed_data.decode('utf-8'))
        except Exception as e:
            print("Zlib failed:", e)

        # Try decoding as Marshal
        try:
            decoded_data = base64.b64decode(encoded_data)
            result = marshal.loads(decoded_data)
            print("Marshal Decode:", result)
        except Exception as e:
            print("Marshal failed:", e)

        # Try decoding as Pickle
        try:
            decoded_data = base64.b64decode(encoded_data)
            result = pickle.loads(decoded_data)
            print("Pickle Decode:", result)
        except Exception as e:
            print("Pickle failed:", e)

        # Brute force XOR decode (common XOR keys)
        xor_keys = [0xAA, 0xFF, 0x00]  # You can expand this list with more common XOR keys
        for key in xor_keys:
            try:
                decoded_data = base64.b64decode(encoded_data)
                xor_decoded = ''.join(chr(byte ^ key) for byte in decoded_data)
                print(f"XOR (key {hex(key)}) Decode:", xor_decoded)
            except Exception as e:
                print(f"XOR with key {hex(key)} failed:", e)

    except Exception as e:
        print("Error during decoding:", e)

# Test with an encoded data string (use any unknown encoded string here)
encoded_data = "SGVsbG8gd29ybGQh"  # Example: Base64 encoding for "Hello world!"
decode_unknown_data(encoded_data)

