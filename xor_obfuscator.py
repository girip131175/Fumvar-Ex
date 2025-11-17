import os
import sys
import random

def xor_encrypt(data, key):
    """
    Parameters:
    data (bytes): The input data to be encrypted.
    key (list): A list of integers representing the encryption key.

    Returns:
        bytes: The encrypted data.
    """
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def write_c_stub(enc_data, key):
    """
    Generates a C stub that contains the encrypted data and decryption logic.
    The stub decrypts and writes the original EXE file to disk, then executes it.

    Args:
        enc_data (bytes): The XOR-encrypted EXE data.
        key (list of int): The XOR key used for encryption.
    
    Writes:
        A C file named "stub.c" containing the decryption logic and obfuscated data.
    """
    key_str = ", ".join(map(str, key))
    c_code = f"""#include <stdio.h>
#include <stdlib.h>
unsigned char data[] = {{{', '.join(f'0x{b:02X}' for b in enc_data)}}};
unsigned char key[] = {{{key_str}}};
void decrypt() {{
    int len = sizeof(data), klen = sizeof(key);
    for(int i = 0; i < len; i++) data[i] ^= key[i % klen];
    FILE *fp = fopen("decrypted.exe", "wb");
    fwrite(data, len, 1, fp);
    fclose(fp);
    system("decrypted.exe");
}}
int main() {{ decrypt(); return 0; }}
"""
    with open("stub.c", "w") as f:
        f.write(c_code)

def xor_obfuscate(input_file, output_file):
    """
    Obfuscates an input EXE file using XOR encryption and generates an obfuscated EXE.

    Args:
        input_file (str): Path to the original EXE file.
        output_file (str): Path to save the obfuscated EXE.

    Process:
        1. Reads the original EXE file.
        2. Encrypts it using a 4-byte XOR key.
        3. Generates a C stub that contains the encrypted data and decryption logic.
        4. Compiles the stub using GCC to produce the final obfuscated EXE. 
    """
    with open(input_file, "rb") as f:
        data = f.read()
    
    key = [random.randint(1, 255) for _ in range(4)]  # 4-byte key for stronger encryption
    enc_data = xor_encrypt(data, key)

    write_c_stub(enc_data, key)
    os.system(f"gcc stub.c -o {output_file}")  # Use GCC for cross-platform compilation

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python obfuscate.py <input.exe> <output.exe>")
        sys.exit(1)
    
    xor_obfuscate(sys.argv[1], sys.argv[2])