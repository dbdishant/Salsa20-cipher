# Salsa20/12 Cipher Implementation

**Prog language used** -> Python3
**Status**-> salsa20.py file contains all the expected functions for Salsa20/12 cipher and they're all complete. 

---

In order to execute the code use below command in the terminal->
$ python salsa20.py 128 "deadbeefdeadbeefdeadbeefdeadbeef" "1234567890abcdef" "546869736973706c61696e74657874"
$

* The first argument (e.g., 128) specifies the key size in bits.
* The second argument is the key in hexadecimal format.
* The third argument is the nonce (also in hexadecimal format).
* The fourth argument is the plaintext message, also represented in hexadecimal.

---

### Description of the code->
1. Input Parsing (get_inputs): The script starts by parsing command-line arguments to obtain input parameters required for the Salsa20 encryption algorithm. These parameters include the key size, key, nonce, and plaintext message. If the input format is incorrect, an error message is displayed.

2. Hexadecimal Conversion (hex_to_text, extract_unicode, text_to_hex, create_hexadecimal): These functions handle the conversion between hexadecimal strings and text (Unicode). hex_to_text converts a hexadecimal string to its corresponding text representation. extract_unicode converts a hexadecimal string to a list of Unicode code points. text_to_hex converts text to its hexadecimal representation, and create_hexadecimal converts a list of Unicode code points back to a hexadecimal string.

3. Bitwise Operations (rotate_left, hex_string_to_bits, bits_to_hex_string): These functions perform bitwise operations required for the Salsa20 algorithm. rotate_left performs a left rotation on a value. hex_string_to_bits converts a hexadecimal string to a list of bits. bits_to_hex_string converts a list of bits to its corresponding hexadecimal string.

4. Salsa20 Encryption (Salsa20Cipher): This class implements the Salsa20 encryption algorithm. It contains methods for various steps of the algorithm, including hashing, expansion, double round, column round, row round, and quarter round. The encrypt method takes the key size, key, nonce, and plaintext message as input and returns the encrypted ciphertext.

5. Main Execution: In the __main__ block, the script first obtains input parameters using get_inputs. Then, it encrypts the plaintext message using the Salsa20  algorithm and prints the resulting ciphertext.

---

### Test cases used and logs

### All the below test cases were working!!
1. Test Case 1
$ python salsa20.py 64 "9add4d0ca0098aaa" "3769208a28190ec0" "54686973697361706c61696e74657874"
$
OUTPUT -> 4db0c1de8b570799b87c214d46ba5bce

2. Test Case 2
$ python salsa20.py 128 "014689370014c327d3fbca723b39ea9e" "d6f2cdeb82f905e2" "7465787420666f722031323862697420656e6372797470696f6e"
$
OUTPUT -> 4fb0717e6fcbf05e16c8006240cdde1ccc33b9e24990e94675db

3. Test Case 3
$ python salsa20.py 128 "00112233445566778899aabbccddeeff" "0000000000000000" "5468697320697320612074657374206d6573736167652e"
$ 
OUTPUT-> b31da5c873b1be81d0841866078225b6cca7fdf7ec0663

4. Test Case 4
$ python salsa20.py 256 "fb423b4a0be74f7d1e5091158b5b2a510d1e5161dc7ab8dfd495d19949adf3a3" "11d4d7e4e368c8e9" "54686973697364656372797074656474657874"
$
OUTPUT-> 91418d3f013015b6dab24e443db06166ea4188

5. Test Case 5
$ python salsa20.py 128 "deadbeefdeadbeefdeadbeefdeadbeef" "1234567890abcdef" "546869736973706c61696e74657874"
$
OUTPUT-> a1c7720e1abadb96e5a2600d0ce028
