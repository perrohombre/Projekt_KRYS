"""
Implementacja algorytmu DES (Data Encryption Standard)
Autorzy: Projekt KRYS - Kryptografia Stosowana
"""

import numpy as np
from typing import List, Tuple

# ============================================================================
# TABLICE PERMUTACJI I STAŁE DES
# ============================================================================

# Permutacja początkowa (IP)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Permutacja końcowa (FP) - odwrotność IP
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Permutacja rozszerzająca E (32 -> 48 bitów)
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutacja P (po S-blokach)
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# Permuted Choice 1 (PC-1) - wybór 56 bitów z 64-bitowego klucza
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted Choice 2 (PC-2) - wybór 48 bitów z 56-bitowego klucza
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Liczba rotacji w lewo dla każdej rundy
ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-bloki (8 bloków, każdy 4x16)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]


# ============================================================================
# FUNKCJE POMOCNICZE
# ============================================================================

def hex_to_bits(hex_string: str) -> List[int]:
    """Konwertuje string heksadecymalny na listę bitów."""
    # Usuwamy prefiks 0x jeśli istnieje
    hex_string = hex_string.replace("0x", "").replace(" ", "")
    # Konwertujemy na int, potem na bity
    num = int(hex_string, 16)
    # Konwertujemy na 64 bity (dla DES)
    bits = []
    for i in range(64):
        bits.append((num >> (63 - i)) & 1)
    return bits


def bits_to_hex(bits: List[int]) -> str:
    """Konwertuje listę bitów na string heksadecymalny."""
    num = 0
    for bit in bits:
        num = (num << 1) | bit
    return format(num, '016X')


def bits_to_int(bits: List[int]) -> int:
    """Konwertuje listę bitów na liczbę całkowitą."""
    result = 0
    for bit in bits:
        result = (result << 1) | bit
    return result


def int_to_bits(num: int, length: int) -> List[int]:
    """Konwertuje liczbę całkowitą na listę bitów o zadanej długości."""
    bits = []
    for i in range(length):
        bits.append((num >> (length - 1 - i)) & 1)
    return bits


def permute(bits: List[int], table: List[int]) -> List[int]:
    """Wykonuje permutację bitów według zadanej tablicy."""
    return [bits[i - 1] for i in table]


def left_rotate(bits: List[int], n: int) -> List[int]:
    """Rotacja cykliczna w lewo o n pozycji."""
    return bits[n:] + bits[:n]


def xor(bits1: List[int], bits2: List[int]) -> List[int]:
    """Wykonuje operację XOR na dwóch listach bitów."""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]


# ============================================================================
# GENEROWANIE PODKLUCZY
# ============================================================================

def generate_subkeys(key: List[int]) -> List[List[int]]:
    """
    Generuje 16 podkluczy (po 48 bitów każdy) z 64-bitowego klucza.
    
    Args:
        key: 64-bitowy klucz główny (lista bitów)
        
    Returns:
        Lista 16 podkluczy, każdy po 48 bitów
    """
    # Permutacja PC-1: wybieramy 56 bitów z 64
    key_56 = permute(key, PC1)
    
    # Dzielimy na dwie połowy po 28 bitów
    C = key_56[:28]
    D = key_56[28:]
    
    subkeys = []
    
    for round_num in range(16):
        # Rotacja w lewo
        C = left_rotate(C, ROTATIONS[round_num])
        D = left_rotate(D, ROTATIONS[round_num])
        
        # Łączymy i stosujemy PC-2
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)
    
    return subkeys


# ============================================================================
# FUNKCJA FEISTELA
# ============================================================================

def s_box_substitution(bits_48: List[int]) -> List[int]:
    """
    Wykonuje podstawienie S-bloków (48 bitów -> 32 bity).
    
    Args:
        bits_48: 48-bitowe wejście
        
    Returns:
        32-bitowe wyjście po podstawieniu S-bloków
    """
    output = []
    
    for i in range(8):
        # Wycinamy 6 bitów dla i-tego S-bloku
        block = bits_48[i * 6:(i + 1) * 6]
        
        # Bity skrajne (0 i 5) określają wiersz
        row = (block[0] << 1) | block[5]
        
        # Bity środkowe (1-4) określają kolumnę
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        
        # Pobieramy wartość z S-bloku
        val = S_BOXES[i][row][col]
        
        # Konwertujemy na 4 bity
        output.extend(int_to_bits(val, 4))
    
    return output


def feistel_function(R: List[int], subkey: List[int]) -> List[int]:
    """
    Funkcja Feistela f(R, K).
    
    Args:
        R: 32-bitowa prawa połowa
        subkey: 48-bitowy podklucz
        
    Returns:
        32-bitowy wynik funkcji Feistela
    """
    # 1. Rozszerzenie E: 32 -> 48 bitów
    expanded = permute(R, E)
    
    # 2. XOR z podkluczem
    xored = xor(expanded, subkey)
    
    # 3. Podstawienie S-bloków: 48 -> 32 bity
    substituted = s_box_substitution(xored)
    
    # 4. Permutacja P
    output = permute(substituted, P)
    
    return output


# ============================================================================
# SZYFROWANIE / DESZYFROWANIE DES
# ============================================================================

def des_encrypt_block(plaintext: List[int], key: List[int]) -> List[int]:
    """
    Szyfruje pojedynczy 64-bitowy blok algorytmem DES.
    
    Args:
        plaintext: 64-bitowy tekst jawny
        key: 64-bitowy klucz
        
    Returns:
        64-bitowy szyfrogram
    """
    # Generujemy podklucze
    subkeys = generate_subkeys(key)
    
    # Permutacja początkowa
    permuted = permute(plaintext, IP)
    
    # Dzielimy na lewą i prawą połowę
    L = permuted[:32]
    R = permuted[32:]
    
    # 16 rund Feistela
    for i in range(16):
        # Zapisujemy starą prawą połowę
        old_R = R.copy()
        
        # Obliczamy f(R, K_i)
        f_result = feistel_function(R, subkeys[i])
        
        # Nowa prawa połowa = L XOR f(R, K_i)
        R = xor(L, f_result)
        
        # Nowa lewa połowa = stara prawa połowa
        L = old_R
    
    # Po ostatniej rundzie łączymy R + L (zamiana!)
    combined = R + L
    
    # Permutacja końcowa
    ciphertext = permute(combined, FP)
    
    return ciphertext


def des_decrypt_block(ciphertext: List[int], key: List[int]) -> List[int]:
    """
    Deszyfruje pojedynczy 64-bitowy blok algorytmem DES.
    
    Args:
        ciphertext: 64-bitowy szyfrogram
        key: 64-bitowy klucz
        
    Returns:
        64-bitowy tekst jawny
    """
    # Generujemy podklucze
    subkeys = generate_subkeys(key)
    
    # Permutacja początkowa
    permuted = permute(ciphertext, IP)
    
    # Dzielimy na lewą i prawą połowę
    L = permuted[:32]
    R = permuted[32:]
    
    # 16 rund Feistela z odwróconą kolejnością podkluczy
    for i in range(15, -1, -1):
        old_R = R.copy()
        f_result = feistel_function(R, subkeys[i])
        R = xor(L, f_result)
        L = old_R
    
    # Łączymy R + L
    combined = R + L
    
    # Permutacja końcowa
    plaintext = permute(combined, FP)
    
    return plaintext


def des_encrypt_block_rounds(plaintext: List[int], key: List[int], num_rounds: int = 16) -> Tuple[List[int], List[int], List[int]]:
    """
    Szyfruje blok DES z określoną liczbą rund (dla analizy).
    
    Args:
        plaintext: 64-bitowy tekst jawny
        key: 64-bitowy klucz
        num_rounds: liczba rund (domyślnie 16)
        
    Returns:
        Tuple (ciphertext, L_final, R_final)
    """
    subkeys = generate_subkeys(key)
    permuted = permute(plaintext, IP)
    
    L = permuted[:32]
    R = permuted[32:]
    
    for i in range(num_rounds):
        old_R = R.copy()
        f_result = feistel_function(R, subkeys[i])
        R = xor(L, f_result)
        L = old_R
    
    combined = R + L
    ciphertext = permute(combined, FP)
    
    return ciphertext, L, R


# ============================================================================
# FUNKCJE WYSOKIEGO POZIOMU
# ============================================================================

def encrypt(plaintext_hex: str, key_hex: str) -> str:
    """
    Szyfruje tekst jawny podany w formacie heksadecymalnym.
    
    Args:
        plaintext_hex: Tekst jawny w hex (16 znaków = 64 bity)
        key_hex: Klucz w hex (16 znaków = 64 bity)
        
    Returns:
        Szyfrogram w formacie hex
    """
    plaintext_bits = hex_to_bits(plaintext_hex)
    key_bits = hex_to_bits(key_hex)
    ciphertext_bits = des_encrypt_block(plaintext_bits, key_bits)
    return bits_to_hex(ciphertext_bits)


def decrypt(ciphertext_hex: str, key_hex: str) -> str:
    """
    Deszyfruje szyfrogram podany w formacie heksadecymalnym.
    
    Args:
        ciphertext_hex: Szyfrogram w hex (16 znaków = 64 bity)
        key_hex: Klucz w hex (16 znaków = 64 bity)
        
    Returns:
        Tekst jawny w formacie hex
    """
    ciphertext_bits = hex_to_bits(ciphertext_hex)
    key_bits = hex_to_bits(key_hex)
    plaintext_bits = des_decrypt_block(ciphertext_bits, key_bits)
    return bits_to_hex(plaintext_bits)


# ============================================================================
# TESTY
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("TEST IMPLEMENTACJI DES")
    print("=" * 60)
    
    # Wektory testowe z oficjalnej specyfikacji DES
    test_vectors = [
        {
            "key": "133457799BBCDFF1",
            "plaintext": "0123456789ABCDEF",
            "expected": "85E813540F0AB405"
        },
        {
            "key": "0E329232EA6D0D73",
            "plaintext": "8787878787878787",
            "expected": "0000000000000000"
        }
    ]
    
    print("\n1. Test szyfrowania i deszyfrowania:")
    print("-" * 40)
    
    for i, tv in enumerate(test_vectors):
        ciphertext = encrypt(tv["plaintext"], tv["key"])
        decrypted = decrypt(ciphertext, tv["key"])
        
        print(f"\nTest {i + 1}:")
        print(f"  Klucz:          {tv['key']}")
        print(f"  Tekst jawny:    {tv['plaintext']}")
        print(f"  Szyfrogram:     {ciphertext}")
        print(f"  Oczekiwany:     {tv['expected']}")
        print(f"  Odszyfrowany:   {decrypted}")
        print(f"  Zgodność:       {'✓ TAK' if ciphertext == tv['expected'] else '✗ NIE'}")
        print(f"  Roundtrip:      {'✓ TAK' if decrypted == tv['plaintext'] else '✗ NIE'}")
    
    print("\n2. Test z losowym kluczem:")
    print("-" * 40)
    
    import random
    random_key = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
    random_plaintext = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
    
    encrypted = encrypt(random_plaintext, random_key)
    decrypted = decrypt(encrypted, random_key)
    
    print(f"  Klucz:        {random_key}")
    print(f"  Plaintext:    {random_plaintext}")
    print(f"  Ciphertext:   {encrypted}")
    print(f"  Decrypted:    {decrypted}")
    print(f"  Roundtrip:    {'✓ TAK' if decrypted == random_plaintext else '✗ NIE'}")
    
    print("\n" + "=" * 60)
    print("TESTY ZAKOŃCZONE")
    print("=" * 60)
