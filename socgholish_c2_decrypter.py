# Joe Avanzato
# https://github.com/joeavanzato/socgholish_c2_unpacker
# Designed to decrypt encrypted python reverse shells dropped by SocGholish

import sys
import re
# Typically needed by the payload
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2, HKDF
import zlib
import os
import base64
from Crypto.Hash import SHA256
import hashlib

def read_file_to_string(file_path):
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()
            return file_content
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except IOError:
        print(f"Error: Could not read file: {file_path}")
        return None

def main():
    filePath = sys.argv[1]
    print("Decrypting File: "+filePath)
    data = read_file_to_string(filePath)
    if data is None:
        exit()
    decrypted = run(data)
    with open("decrypted_source.txt", "w") as f:
        f.write(decrypted)

    print("Decrypted output saved to decrypted_source.txt")


def rreplace(s, old, new):
    try:
        place = s.rindex(old)
        return ''.join((s[:place],new,s[place+len(old):]))
    except ValueError:
        return s

def run (data):
    global tmp_data
    tmp_data = data
    run_id = 0
    loc = {}
    pattern_pbkdf = r'key\s*=\s*pbkdf2[a-zA-Z0-9_]+\('
    replacement_pbkdf = "key = PBKDF2("
    pattern_b85 = r'data\s*=\s*b85_[a-zA-Z0-9_]+\(enc\)'
    replacement_b85 = "data = base64.b85decode(enc)"
    pattern_zlib = r'data\s*=\s*decomp_[a-zA-Z0-9_]+\('
    replacement_zlib = "data = zlib.decompress("
    pattern_cha= r'cipher\s*=\s*chacha[a-zA-Z0-9_]+\('
    replacement_cha = "cipher = ChaCha20.new("
    pattern_aesnew = r'cipher\s*=\s*aesnew[a-zA-Z0-9_]+\('
    replacement_aesnew = "cipher = AES.new("
    pattern_decode = r'return\s*decode[a-zA-Z0-9_]+\(data\)'
    replacement_decode  = "return data.decode('utf-8')"
    
    for i in range(1000):
        # Some checks for strings typically in the final payload
        if "ConnectionTimeoutOccuredError" in tmp_data and "ConnectionRefusedError" in tmp_data:
            return tmp_data

        print(f"Run Number: {run_id}")
        print("###################################################################### RAW DATA")
        print(tmp_data)
        # May need to adjust this based on the payload in question
        tmp_data = tmp_data.replace("['vm', 'virtual']", "['nonsense']")
        tmp_data = tmp_data.replace("__debug__", "__nonsense__")
        # We want to avoid actually exec the code, just the decode piece, so we modify the file in-line
        tmp_data = tmp_data.replace("exec(", "returned=")
        tmp_data = tmp_data.replace("def launch_hidden():", "def launch_hidden2():") # Rename
        tmp_data = tmp_data.replace("launch_hidden()", "#launch_hidden()") # Comment out
        tmp_data = rreplace(tmp_data, ')', '')

        # Now we want to replace the other random vars
        tmp_data = re.sub(pattern_b85, replacement_b85, tmp_data, 1)
        tmp_data = re.sub(pattern_pbkdf, replacement_pbkdf, tmp_data, 1)
        tmp_data = re.sub(pattern_aesnew, replacement_aesnew, tmp_data, 1)
        tmp_data = re.sub(pattern_cha, replacement_cha, tmp_data, 1)
        tmp_data = re.sub(pattern_zlib, replacement_zlib, tmp_data, 1)
        tmp_data = re.sub(pattern_decode, replacement_decode, tmp_data, 1)

        # Find and replace hw key for current run - this algorithm may change in future payloads, we observed static before
        key_pattern = re.compile("return b'(?P<hw_key>[0-9A-Z]{30,35})'")
        matches = key_pattern.search(tmp_data)
        if matches is not None:
            pattern_hwkey = r'hw_key\s=\sget_hw_key\(\)'
            replacement_hwkey = f"hw_key = b'{matches.group('hw_key')}'"
            tmp_data = re.sub(pattern_hwkey, replacement_hwkey, tmp_data, 1)

        print("###################################################################### CLEANED DATA")
        print(tmp_data)
        # Probably could have passed globals() directly but had some other plans that I later on changed
        exec_globals = globals().copy()
        exec(tmp_data, exec_globals, loc)
        tmp_data = loc['returned']
        #tmp_data = exec(data, globals(), loc)
        run_id += 1


main()
