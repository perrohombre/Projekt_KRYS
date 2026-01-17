"""
Atak różnicowy na algorytm DES
Implementacja kryptoanalizy różnicowej dla zredukowanych wersji DES

Autorzy: Projekt KRYS - Kryptografia Stosowana
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from des import (
    S_BOXES, E, P, IP, FP,
    hex_to_bits, bits_to_hex, bits_to_int, int_to_bits,
    permute, xor, generate_subkeys, feistel_function,
    s_box_substitution, des_encrypt_block, des_encrypt_block_rounds
)


# ============================================================================
# DIFFERENTIAL DISTRIBUTION TABLE (DDT)
# ============================================================================

def compute_ddt(sbox: List[List[int]]) -> np.ndarray:
    """
    Oblicza tabelę rozkładu różnicowego (DDT) dla S-bloku.
    
    DDT[delta_x][delta_y] = liczba par (x, x') takich że:
    - x XOR x' = delta_x
    - S(x) XOR S(x') = delta_y
    
    Args:
        sbox: S-blok w formacie 4x16 (4 wiersze, 16 kolumn)
        
    Returns:
        Macierz DDT o wymiarach 64x16
    """
    ddt = np.zeros((64, 16), dtype=int)
    
    # Dla każdej możliwej wartości wejściowej x (0-63)
    for x in range(64):
        # Dla każdej możliwej różnicy wejściowej delta_x (0-63)
        for delta_x in range(64):
            # Obliczamy x' = x XOR delta_x
            x_prime = x ^ delta_x
            
            # Obliczamy wartości S-bloku
            # Wiersz: bity 0 i 5 (skrajne)
            row_x = ((x >> 5) & 1) << 1 | (x & 1)
            col_x = (x >> 1) & 0x0F
            
            row_x_prime = ((x_prime >> 5) & 1) << 1 | (x_prime & 1)
            col_x_prime = (x_prime >> 1) & 0x0F
            
            y = sbox[row_x][col_x]
            y_prime = sbox[row_x_prime][col_x_prime]
            
            # Różnica wyjściowa
            delta_y = y ^ y_prime
            
            # Zwiększamy licznik
            ddt[delta_x][delta_y] += 1
    
    return ddt


def compute_all_ddts() -> List[np.ndarray]:
    """
    Oblicza tablice DDT dla wszystkich 8 S-bloków DES.
    
    Returns:
        Lista 8 macierzy DDT
    """
    ddts = []
    for i, sbox in enumerate(S_BOXES):
        ddt = compute_ddt(sbox)
        ddts.append(ddt)
    return ddts


def get_ddt_probability(ddt: np.ndarray, delta_in: int, delta_out: int) -> float:
    """
    Zwraca prawdopodobieństwo przejścia różnicowego przez S-blok.
    
    Args:
        ddt: Tablica DDT dla S-bloku
        delta_in: Różnica wejściowa (6 bitów)
        delta_out: Różnica wyjściowa (4 bity)
        
    Returns:
        Prawdopodobieństwo (count / 64)
    """
    return ddt[delta_in][delta_out] / 64.0


def find_best_differentials(ddt: np.ndarray, top_n: int = 5) -> List[Tuple[int, int, int, float]]:
    """
    Znajduje najlepsze charakterystyki różnicowe dla S-bloku.
    
    Args:
        ddt: Tablica DDT
        top_n: Liczba najlepszych przejść do zwrócenia
        
    Returns:
        Lista krotek (delta_in, delta_out, count, probability)
    """
    differentials = []
    
    for delta_in in range(1, 64):  # Pomijamy delta_in = 0
        for delta_out in range(16):
            count = ddt[delta_in][delta_out]
            if count > 0:
                prob = count / 64.0
                differentials.append((delta_in, delta_out, count, prob))
    
    # Sortujemy po prawdopodobieństwie (malejąco)
    differentials.sort(key=lambda x: x[2], reverse=True)
    
    return differentials[:top_n]


# ============================================================================
# CHARAKTERYSTYKI RÓŻNICOWE
# ============================================================================

class DifferentialCharacteristic:
    """Reprezentuje wielorundową charakterystykę różnicową."""
    
    def __init__(self, num_rounds: int):
        self.num_rounds = num_rounds
        self.input_diff = None  # Różnica wejściowa (L0, R0)
        self.round_diffs = []   # Lista różnic po każdej rundzie
        self.probability = 1.0
        self.active_sboxes = []  # Aktywne S-bloki w każdej rundzie
    
    def __str__(self):
        return f"Charakterystyka {self.num_rounds}-rundowa, p = {self.probability:.6e}"


def build_4_round_characteristic() -> DifferentialCharacteristic:
    """
    Buduje znaną 4-rundową charakterystykę różnicową dla DES.
    
    Używa przybliżenia iteracyjnego opartego na najlepszych
    przejściach różnicowych przez S-bloki.
    
    Returns:
        Charakterystyka różnicowa
    """
    char = DifferentialCharacteristic(4)
    
    # Znana dobra charakterystyka dla 4 rund DES
    # Delta_L0 = 0x40080000, Delta_R0 = 0x04000000
    char.input_diff = (0x40080000, 0x04000000)
    
    # Prawdopodobieństwo obliczone na podstawie DDT
    # Ta charakterystyka ma p ≈ 1/16 na rundę aktywną
    char.probability = (1/16) ** 2  # Dwie aktywne rundy
    
    return char


def build_6_round_characteristic() -> DifferentialCharacteristic:
    """
    Buduje 6-rundową charakterystykę różnicową dla DES.
    
    Returns:
        Charakterystyka różnicowa
    """
    char = DifferentialCharacteristic(6)
    
    # Charakterystyka 6-rundowa z publikacji Biham-Shamir
    char.input_diff = (0x00000000, 0x60000000)
    char.probability = 2**-8
    
    return char


# ============================================================================
# ATAK RÓŻNICOWY
# ============================================================================

class DifferentialAttack:
    """Implementacja ataku różnicowego na zredukowany DES."""
    
    def __init__(self, num_rounds: int = 4):
        """
        Inicjalizuje atak.
        
        Args:
            num_rounds: Liczba rund DES do ataku (domyślnie 4)
        """
        self.num_rounds = num_rounds
        self.ddts = compute_all_ddts()
        self.characteristic = None
        self.key_candidates = defaultdict(int)
        
    def set_characteristic(self, characteristic: DifferentialCharacteristic):
        """Ustawia charakterystykę różnicową do wykorzystania w ataku."""
        self.characteristic = characteristic
        
    def generate_plaintext_pair(self, delta_L: int, delta_R: int) -> Tuple[List[int], List[int]]:
        """
        Generuje parę tekstów jawnych z zadaną różnicą.
        
        Args:
            delta_L: Różnica lewej połowy (32 bity)
            delta_R: Różnica prawej połowy (32 bity)
            
        Returns:
            Para (P, P') gdzie P XOR P' = (delta_L || delta_R)
        """
        import random
        
        # Generujemy losowy tekst jawny P
        P = [random.randint(0, 1) for _ in range(64)]
        
        # Obliczamy P' = P XOR delta
        delta = int_to_bits(delta_L, 32) + int_to_bits(delta_R, 32)
        P_prime = xor(P, delta)
        
        return P, P_prime
    
    def collect_pairs(self, 
                      oracle_func, 
                      num_pairs: int,
                      delta_L: int,
                      delta_R: int) -> List[Tuple]:
        """
        Zbiera pary tekst jawny - szyfrogram.
        
        Args:
            oracle_func: Funkcja szyfrująca (przyjmuje plaintext, zwraca ciphertext)
            num_pairs: Liczba par do zebrania
            delta_L: Różnica lewej połowy
            delta_R: Różnica prawej połowy
            
        Returns:
            Lista krotek (P, P', C, C')
        """
        pairs = []
        
        for _ in range(num_pairs):
            P, P_prime = self.generate_plaintext_pair(delta_L, delta_R)
            
            C = oracle_func(P)
            C_prime = oracle_func(P_prime)
            
            pairs.append((P, P_prime, C, C_prime))
        
        return pairs
    
    def partial_decrypt_last_round(self, 
                                   C: List[int], 
                                   subkey_guess: List[int],
                                   sbox_index: int) -> int:
        """
        Częściowe odszyfrowanie ostatniej rundy dla jednego S-bloku.
        
        Args:
            C: Szyfrogram (64 bity)
            subkey_guess: Zgadywane 6 bitów podklucza
            sbox_index: Indeks S-bloku (0-7)
            
        Returns:
            Wyjście S-bloku (4 bity)
        """
        # Odwracamy permutację końcową
        after_ip_inv = permute(C, IP)  # To jest odwrotność FP
        
        # Po ostatniej rundzie: L16 || R16 (ale zamienione przed FP)
        R16 = after_ip_inv[:32]
        L16 = after_ip_inv[32:]
        
        # R15 = L16
        R15 = L16
        
        # Rozszerzamy R15
        expanded_R15 = permute(R15, E)
        
        # Wyciągamy 6 bitów dla danego S-bloku
        start = sbox_index * 6
        input_bits = expanded_R15[start:start + 6]
        
        # XOR z zgadywanym fragmentem klucza
        xored = xor(input_bits, subkey_guess)
        
        # Podstawienie S-bloku
        xored_int = bits_to_int(xored)
        row = ((xored_int >> 5) & 1) << 1 | (xored_int & 1)
        col = (xored_int >> 1) & 0x0F
        
        sbox_output = S_BOXES[sbox_index][row][col]
        
        return sbox_output
    
    def attack_sbox(self,
                    pairs: List[Tuple],
                    sbox_index: int,
                    expected_output_diff: int) -> Tuple[int, Dict[int, int]]:
        """
        Atak na pojedynczy S-blok ostatniej rundy.
        
        Args:
            pairs: Lista par (P, P', C, C')
            sbox_index: Indeks S-bloku do zaatakowania
            expected_output_diff: Oczekiwana różnica wyjściowa
            
        Returns:
            Tuple (best_key, scores_dict)
        """
        scores = defaultdict(int)
        
        for P, P_prime, C, C_prime in pairs:
            for key_guess in range(64):
                key_bits = int_to_bits(key_guess, 6)
                
                # Częściowe odszyfrowanie dla obu szyfrogramów
                out1 = self.partial_decrypt_last_round(C, key_bits, sbox_index)
                out2 = self.partial_decrypt_last_round(C_prime, key_bits, sbox_index)
                
                # Sprawdzamy czy różnica wyjściowa zgadza się z oczekiwaną
                output_diff = out1 ^ out2
                
                if output_diff == expected_output_diff:
                    scores[key_guess] += 1
        
        # Znajdź klucz z najwyższym wynikiem
        best_key = max(scores.keys(), key=lambda k: scores[k]) if scores else 0
        
        return best_key, dict(scores)
    
    def run_attack(self, 
                   oracle_func,
                   num_pairs: int = 256) -> Dict[int, int]:
        """
        Przeprowadza pełny atak różnicowy.
        
        Args:
            oracle_func: Funkcja szyfrująca (oracle)
            num_pairs: Liczba par do wykorzystania
            
        Returns:
            Słownik {sbox_index: recovered_key_bits}
        """
        if self.characteristic is None:
            self.characteristic = build_4_round_characteristic()
        
        delta_L, delta_R = self.characteristic.input_diff
        
        print(f"\n{'=' * 60}")
        print(f"ATAK RÓŻNICOWY NA {self.num_rounds}-RUNDOWY DES")
        print(f"{'=' * 60}")
        print(f"Charakterystyka: ΔL = {delta_L:08X}, ΔR = {delta_R:08X}")
        print(f"Prawdopodobieństwo: {self.characteristic.probability:.2e}")
        print(f"Liczba par: {num_pairs}")
        
        # Zbieramy pary
        print(f"\n[1] Zbieranie par tekst jawny - szyfrogram...")
        pairs = self.collect_pairs(oracle_func, num_pairs, delta_L, delta_R)
        print(f"    Zebrano {len(pairs)} par")
        
        # Atak na każdy S-blok
        print(f"\n[2] Atak na S-bloki ostatniej rundy...")
        recovered_keys = {}
        
        for sbox_idx in range(8):
            # Dla uproszczenia zakładamy oczekiwaną różnicę = 0
            # W pełnym ataku należy to wyliczyć z charakterystyki
            expected_diff = 0
            
            best_key, scores = self.attack_sbox(pairs, sbox_idx, expected_diff)
            recovered_keys[sbox_idx] = best_key
            
            if scores:
                max_score = max(scores.values())
                print(f"    S-blok {sbox_idx + 1}: klucz = {best_key:02X} "
                      f"(6 bitów: {best_key:06b}), score = {max_score}")
            else:
                print(f"    S-blok {sbox_idx + 1}: brak wyników")
        
        # Składamy odzyskane fragmenty klucza
        print(f"\n[3] Składanie odzyskanego podklucza...")
        subkey_bits = []
        for i in range(8):
            subkey_bits.extend(int_to_bits(recovered_keys[i], 6))
        
        subkey_int = bits_to_int(subkey_bits)
        print(f"    Odzyskany podklucz K{self.num_rounds}: {subkey_int:012X}")
        
        print(f"\n{'=' * 60}")
        print("ATAK ZAKOŃCZONY")
        print(f"{'=' * 60}")
        
        return recovered_keys


# ============================================================================
# DEMONSTRACJA I TESTY
# ============================================================================

def demonstrate_ddt():
    """Demonstracja tabeli DDT dla S-bloku."""
    print("\n" + "=" * 60)
    print("ANALIZA DDT DLA S-BLOKÓW DES")
    print("=" * 60)
    
    ddts = compute_all_ddts()
    
    for i, ddt in enumerate(ddts):
        print(f"\nS-blok {i + 1}:")
        print("-" * 40)
        
        # Najlepsze przejścia różnicowe
        best = find_best_differentials(ddt, top_n=5)
        
        print(f"{'Δ_in':>8} {'Δ_out':>8} {'Count':>8} {'Prob':>12}")
        print("-" * 40)
        
        for delta_in, delta_out, count, prob in best:
            print(f"{delta_in:>8} {delta_out:>8} {count:>8} {prob:>12.4f}")
        
        # Statystyki
        nonzero = np.count_nonzero(ddt)
        max_val = np.max(ddt[1:, :])  # Pomijamy delta_in = 0
        print(f"\nNiezerowych wpisów: {nonzero}")
        print(f"Maksymalna wartość (delta_in ≠ 0): {max_val}")


def demonstrate_attack():
    """Demonstracja ataku różnicowego na 4-rundowy DES."""
    print("\n" + "=" * 60)
    print("DEMONSTRACJA ATAKU RÓŻNICOWEGO")
    print("=" * 60)
    
    # Klucz do odzyskania (losowy)
    import random
    random.seed(42)  # Dla powtarzalności
    
    key_hex = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
    key_bits = hex_to_bits(key_hex)
    
    print(f"\nKlucz (do odzyskania): {key_hex}")
    
    # Tworzymy oracle - funkcję szyfrującą z nieznanym kluczem
    def oracle(plaintext_bits):
        # Używamy zredukowanego DES (4 rundy)
        ciphertext, _, _ = des_encrypt_block_rounds(plaintext_bits, key_bits, num_rounds=4)
        return ciphertext
    
    # Przeprowadzamy atak
    attack = DifferentialAttack(num_rounds=4)
    attack.set_characteristic(build_4_round_characteristic())
    
    recovered_keys = attack.run_attack(oracle, num_pairs=500)
    
    # Weryfikacja
    print("\n" + "=" * 60)
    print("WERYFIKACJA")
    print("=" * 60)
    
    # Generujemy prawdziwe podklucze
    true_subkeys = generate_subkeys(key_bits)
    true_k4 = true_subkeys[3]  # K4 (indeksowane od 0)
    
    print(f"\nPrawdziwy podklucz K4:")
    for i in range(8):
        true_6bits = bits_to_int(true_k4[i*6:(i+1)*6])
        recovered = recovered_keys.get(i, -1)
        match = "✓" if true_6bits == recovered else "✗"
        print(f"  S-blok {i+1}: prawdziwy = {true_6bits:02X}, "
              f"odzyskany = {recovered:02X} {match}")


if __name__ == "__main__":
    # Analiza DDT
    demonstrate_ddt()
    
    # Demonstracja ataku
    demonstrate_attack()
