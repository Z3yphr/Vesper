"""
c_integration.py - Demonstrates calling a C function from Python using ctypes
"""
import ctypes
import os

# Load the compiled DLL/shared library
lib_path = os.path.join(os.path.dirname(__file__), 'simple_hash.dll')
simple_hash = ctypes.CDLL(lib_path)

# Set argument and return types
simple_hash.simple_xor_hash.argtypes = [ctypes.c_char_p]
simple_hash.simple_xor_hash.restype = ctypes.c_uint32

def hash_string_py(input_str):
    """Hashes a string using the C simple_xor_hash function."""
    return simple_hash.simple_xor_hash(input_str.encode('utf-8'))

if __name__ == "__main__":
    test = "password123"
    print(f"Hash for '{test}': {hash_string_py(test)}")
