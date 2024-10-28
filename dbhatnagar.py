import sys

# Function to convert hexadecimal string to text
def hex_string_to_text(hex_string):
    return bytes.fromhex(hex_string).decode("utf-8")

# Function to extract Unicode values from hexadecimal input
def extract_unicode(hex_input):
    byte_data = bytes.fromhex(hex_input)
    result_string = byte_data.decode("latin-1")
    unicode_values = [ord(c) for c in result_string]
    return unicode_values

# Function to perform left rotation
def left_rotate(value, shift):
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

# Function to convert hexadecimal string to bits array
def hex_string_to_bits(hex_string):
    binary_string = bin(int(hex_string, 16))[2:]
    bits_array = [int(bit) for bit in binary_string]
    return bits_array

# Function to check for a valid value
def check_valid_value():
    for i in range(100):
        print(f"Running loop {i}")
        res = Salsa20Cipher().encrypt(**{**input_params, "rounds": i})
        print(res)
        if res == "91418d3f013015b6dab24e443db06166ea4188":
            print(i)
            return
    print("Can't find")

# Function to convert text to hexadecimal
def text_to_hex(text):
    return text.encode("utf-8").hex()

# Function to get inputs from command line arguments
def get_inputs():
    if len(sys.argv) != 5:
        print("Usage: python3 ./salsa20.py <key_size> <key> <nonce> <text>")
        sys.exit(1)

    try:
        key_size = int(sys.argv[1])
        key_hex = sys.argv[2]
        nonce_hex = sys.argv[3]
        text_hex = sys.argv[4]

        key = extract_unicode(key_hex)
        nonce = extract_unicode(nonce_hex[:16])
        text = extract_unicode(text_hex)

        return [key_size, key, nonce, text]
    except ValueError as ve:
        print("Error: Invalid input. Please ensure all inputs are in the correct format.")
        print(str(ve))
        sys.exit(1)

# Function to create hexadecimal string from Unicode list
def create_hexadecimal(unicode_list):
    result_string = "".join(chr(code) for code in unicode_list)
    byte_data = result_string.encode("latin-1")
    hex_output = byte_data.hex()
    return hex_output

# Function to split array into chunks of given length
def split_array(arr, length):
    return [arr[i : i + length] for i in range(0, len(arr), length)]

# Function to convert bits array to hexadecimal string
def bits_to_hex_string(bits):
    binary_string = "".join(str(bit) for bit in bits)
    integer_value = int(binary_string, 2)
    hex_string = hex(integer_value)[2:]
    print(hex_string)
    return hex_string


class Salsa20Cipher:
    # Function to perform little-endian conversion
    def __little_endian(self, b):
        return b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24)

    # Function to perform Salsa20 hash
    def __salsa20_hash(self, x, n):
        x = [self.__little_endian(x[i : i + 4]) for i in range(0, len(x), 4)]
        z = self.__double_round(x)
        for _ in range(n - 1):
            z = self.__double_round(z)
        result = []
        for i in range(16):
            result.extend(self.__little_endian_inv((z[i] + x[i]) % (1 << 32)))
        return result

    # Function to perform Salsa20 expansion
    def __salsa20_expansion(self, key_size, key, nonce):
        if key_size == 256 and len(key) == 32:
            k0 = key[:16]
            k1 = key[16:]
            sigma = list(b"expand 32-byte k")
        elif key_size == 128 and len(key) == 16:
            k0 = key
            k1 = key
            sigma = list(b"expand 16-byte k")
        elif key_size == 64 and len(key) == 8:
            k0 = key + key
            k1 = k0
            sigma = list(b"expand 08-byte k")
        else:
            raise ValueError("Key must be either 64, 128 or 256 Bit long")
        x = sigma[:4] + k0 + sigma[4:8] + nonce + sigma[8:12] + k1 + sigma[12:]
        return self.__salsa20_hash(x, 6)

    # Function to perform double round
    def __double_round(self, x):
        return self.__row_round(self.__column_round(x))

    # Function to perform column round
    def __column_round(self, y):
        z0, z4, z8, z12 = self.__quarter_round([y[0], y[4], y[8], y[12]])
        z5, z9, z13, z1 = self.__quarter_round([y[5], y[9], y[13], y[1]])
        z10, z14, z2, z6 = self.__quarter_round([y[10], y[14], y[2], y[6]])
        z15, z3, z7, z11 = self.__quarter_round([y[15], y[3], y[7], y[11]])
        return [z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15]

    # Function to perform row round
    def __row_round(self, y):
        z0, z1, z2, z3 = self.__quarter_round([y[0], y[1], y[2], y[3]])
        z5, z6, z7, z4 = self.__quarter_round([y[5], y[6], y[7], y[4]])
        z10, z11, z8, z9 = self.__quarter_round([y[10], y[11], y[8], y[9]])
        z15, z12, z13, z14 = self.__quarter_round([y[15], y[12], y[13], y[14]])
        return [z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15]

    # Function to perform quarter round
    def __quarter_round(self, y):
        z1 = y[1] ^ left_rotate((y[0] + y[3]) % (1 << 32), 7)
        z2 = y[2] ^ left_rotate((z1 + y[0]) % (1 << 32), 9)
        z3 = y[3] ^ left_rotate((z2 + z1) % (1 << 32), 13)
        z0 = y[0] ^ left_rotate((z3 + z2) % (1 << 32), 18)
        return [z0, z1, z2, z3]

    # Function to perform inverse little-endian conversion
    def __little_endian_inv(self, v):
        return [(v >> (i * 8)) & 0xFF for i in range(4)]

    # Function to encrypt using Salsa20 algorithm
    def encrypt(self, key_size, key, nonce, message):
        cipher_text = message
        for i in range(0, len(message), 64):
            expanded_key = self.__salsa20_expansion(key_size, key, nonce + list(i.to_bytes(8)))
            cipher_text[i : i + 64] = [ci ^ xi for ci, xi in zip(cipher_text[i : i + 64], expanded_key)]
        result_hex_string = create_hexadecimal(cipher_text)
        return result_hex_string

if __name__ == "__main__":
    input_params = get_inputs()
    cipher_text = Salsa20Cipher().encrypt(*input_params)
    print(cipher_text)
