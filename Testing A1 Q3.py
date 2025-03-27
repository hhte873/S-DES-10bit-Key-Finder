# This code implements a brute-force search for the key used in the Simplified Data Encryption Standard (S-DES) algorithm.
# It takes a list of plaintext-ciphertext pairs and tries all possible 10-bit keys to find the one that matches all pairs.
# The S-DES algorithm includes key scheduling, permutation operations, and the f_K function used in the encryption process.
# The code is structured into several functions for clarity and modularity, including functions for applying permutations, S-boxes, and the main encryption function.

# === S-DES Tables ===
P10_data = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8_data = [6, 3, 7, 4, 8, 5, 10, 9]
IP_data = [2, 6, 3, 1, 4, 8, 5, 7]
IPinv_data = [4, 1, 3, 5, 7, 2, 8, 6]
EP_data = [4, 1, 2, 3, 2, 3, 4, 1]
P4_data = [2, 4, 3, 1]
SW_data = [5, 6, 7, 8, 1, 2, 3, 4]
LS1_data = [2, 3, 4, 5, 1]
LS2_data = [3, 4, 5, 1, 2]
S0_data = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1_data = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

# === Permutation and Helper Functions ===
def ApplyPermutation(X, permutation):
    # Returns a permuted list according to given permutation indexes (1-based)
    return [X[permutation[j]-1] for j in range(len(permutation))]

def ApplySBox(X, SBox):
    # This function applies the SDES SBox (by table look up)
    r = 2*X[0] + X[3]
    c = 2*X[1] + X[2]
    o = SBox[r][c]
    return [o >> 1 & 1, o & 1]  # Return 2-bit output as list

def concatenate(left, right):
    # Joins two bit lists together.
    return left + right

def LeftHalfBits(block):
    # Returns the left half bits from block.
    return block[:len(block)//2]

def RightHalfBits(block):
    # Returns the right half bits from block.
    return block[len(block)//2:]

def XorBlock(block1, block2):
    # Xors two blocks together.
    if len(block1) != len(block2):
        raise ValueError("XorBlock arguments must be same length")
    return [(b1 ^ b2) for b1, b2 in zip(block1, block2)]

def bitstring_to_list(s):
    # Converts string like "01010101" to [0, 1, 0, 1, 0, 1, 0, 1]
    return [int(c) for c in s.strip() if c in '01']

def list_to_bitstring(lst):
    # Converts list like [0,1,0,1] to "0101"
    return ''.join(str(x) for x in lst)

# === Permutation Operations ===
def P10(X): return ApplyPermutation(X, P10_data)
def P8(X): return ApplyPermutation(X, P8_data)
def IP(X): return ApplyPermutation(X, IP_data)
def IPinv(X): return ApplyPermutation(X, IPinv_data)
def EP(X): return ApplyPermutation(X, EP_data)
def P4(X): return ApplyPermutation(X, P4_data)
def SW(X): return ApplyPermutation(X, SW_data)
def LS1(X): return ApplyPermutation(X, LS1_data)
def LS2(X): return ApplyPermutation(X, LS2_data)
def S0(X): return ApplySBox(X, S0_data)
def S1(X): return ApplySBox(X, S1_data)

# === Key Scheduling ===
def SDESKeySchedule(K):
    # Expands an SDES Key (bit list) into the two round keys.
    temp_K = P10(K)
    left_temp_K = LeftHalfBits(temp_K)
    right_temp_K = RightHalfBits(temp_K)
    K1left = LS1(left_temp_K)
    K1right = LS1(right_temp_K)
    K1temp = concatenate(K1left, K1right)
    K1 = P8(K1temp)
    K2left = LS2(K1left)
    K2right = LS2(K1right)
    K2temp = concatenate(K2left, K2right)
    K2 = P8(K2temp)
    return (K1, K2)

# === f_K Function ===
def f_K(block, K):
    # Performs the f_K function with the supplied block and K.
    left_block = LeftHalfBits(block)
    right_block = RightHalfBits(block)
    temp_block1 = EP(right_block)
    temp_block2 = XorBlock(temp_block1, K)
    left_temp_block2 = LeftHalfBits(temp_block2)
    right_temp_block2 = RightHalfBits(temp_block2)
    S0_out = S0(left_temp_block2)
    S1_out = S1(right_temp_block2)
    temp_block3 = concatenate(S0_out, S1_out)
    temp_block4 = P4(temp_block3)
    temp_block5 = XorBlock(temp_block4, left_block)
    output_block = concatenate(temp_block5, right_block)
    return output_block

# === Full SDES Encryption ===
def SDESEncrypt(plaintext_block, K):
    # Performs a single SDES plaintext block encryption.
    (K1, K2) = SDESKeySchedule(K)
    temp_block1 = IP(plaintext_block)
    temp_block2 = f_K(temp_block1, K1)
    temp_block3 = SW(temp_block2)
    temp_block4 = f_K(temp_block3, K2)
    output_block = IPinv(temp_block4)
    return output_block

# === Brute-force 10-bit key search ===
def find_sdes_key(pairs):
    # Try all 1024 (2^10) possible keys to find the one that matches all plaintext-ciphertext pairs
    for k in range(1024):
        key_bits = [int(x) for x in f"{k:010b}"]  # Generate 10-bit key
        all_match = True
        for pt, ct in pairs:
            pt_bits = bitstring_to_list(pt)
            expected_ct_bits = bitstring_to_list(ct)
            encrypted = SDESEncrypt(pt_bits, key_bits)
            if encrypted != expected_ct_bits:
                all_match = False
                break  # Exit early if any pair doesn't match
        if all_match:
            return key_bits  # Return the key if all pairs match
    return None

# === Usage ===
# Provide plaintext-ciphertext pairs as a list of tuples (bitstring, bitstring)
pairs = [
    ("00000111", "01100101"),
    ("00001100", "00110111"),
    ("00001111", "01001011"),
    ("00000010", "11010001"),
    ("00000001", "11101011"),
    ("00001011", "00001010"),
    ("00000100", "00001000"),
    ("00000110", "10110100"),
    ("00000000", "01001101"),
    ("00001000", "10110010"),
    ("00001001", "01110101"),
    ("00000101", "10101010"),
    ("10101010", "10010100"),
    ("00001010", "11111010"),
    ("00001101", "00010000"),
    ("00001110", "01011111"),
    ("00000011", "00100100")
]

key_found = find_sdes_key(pairs)
if key_found:
    print("Found Key:", ''.join(map(str, key_found)))
else:
    print("No matching key found.")