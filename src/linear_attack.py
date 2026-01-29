"""
Atak liniowy na algorytm DES
Implementacja kryptoanalizy liniowej (metoda Matsui)

Autorzy: Projekt KRYS - Kryptografia Stosowana
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from des import (
    S_BOXES, E, P, IP, FP,
    hex_to_bits, bits_to_hex, bits_to_int, int_to_bits,
    permute, xor, generate_subkeys, feistel_function,
    des_encrypt_block, des_encrypt_block_rounds
)


# ============================================================================
# LINEAR APPROXIMATION TABLE (LAT)
# ============================================================================

def parity(x: int) -> int:
    """Oblicza parzystość liczby (XOR wszystkich bitów)."""
    result = 0
    while x:
        result ^= (x & 1)
        x >>= 1
    return result


def compute_lat(sbox: List[List[int]]) -> np.ndarray:
    """
    Oblicza tabelę przybliżeń liniowych (LAT) dla S-bloku.
    
    LAT[α][β] = #{x : parity(x & α) = parity(S(x) & β)} - 32
    
    Args:
        sbox: S-blok w formacie 4x16
        
    Returns:
        Macierz LAT o wymiarach 64x16
    """
    lat = np.zeros((64, 16), dtype=int)
    
    for alpha in range(64):  # Maska wejściowa (6 bitów)
        for beta in range(16):  # Maska wyjściowa (4 bity)
            count = 0
            
            for x in range(64):
                # Obliczamy wartość S-bloku dla x
                row = ((x >> 5) & 1) << 1 | (x & 1)
                col = (x >> 1) & 0x0F
                sx = sbox[row][col]
                
                # Sprawdzamy równość parzystości
                input_parity = parity(x & alpha)
                output_parity = parity(sx & beta)
                
                if input_parity == output_parity:
                    count += 1
            
            # LAT przechowuje odchylenie od 32 (wartości neutralnej)
            lat[alpha][beta] = count - 32
    
    return lat


def compute_all_lats() -> List[np.ndarray]:
    """
    Oblicza tablice LAT dla wszystkich 8 S-bloków DES.
    
    Returns:
        Lista 8 macierzy LAT
    """
    lats = []
    for sbox in S_BOXES:
        lat = compute_lat(sbox)
        lats.append(lat)
    return lats


def get_bias(lat: np.ndarray, alpha: int, beta: int) -> float:
    """
    Zwraca bias dla danego przybliżenia liniowego.
    
    Bias ε = |p - 1/2| gdzie p to prawdopodobieństwo że
    przybliżenie liniowe jest spełnione.
    
    Args:
        lat: Tablica LAT dla S-bloku
        alpha: Maska wejściowa (6 bitów)
        beta: Maska wyjściowa (4 bity)
        
    Returns:
        Wartość biasu
    """
    return abs(lat[alpha][beta]) / 64.0


def find_best_approximations(lat: np.ndarray, top_n: int = 5) -> List[Tuple[int, int, int, float]]:
    """
    Znajduje najlepsze przybliżenia liniowe dla S-bloku.
    
    Args:
        lat: Tablica LAT
        top_n: Liczba najlepszych przybliżeń do zwrócenia
        
    Returns:
        Lista krotek (alpha, beta, lat_value, bias)
    """
    approximations = []
    
    for alpha in range(1, 64):  # Pomijamy alpha = 0
        for beta in range(1, 16):  # Pomijamy beta = 0
            lat_val = lat[alpha][beta]
            if lat_val != 0:
                bias = abs(lat_val) / 64.0
                approximations.append((alpha, beta, lat_val, bias))
    
    # Sortujemy po wartości bezwzględnej LAT (malejąco)
    approximations.sort(key=lambda x: abs(x[2]), reverse=True)
    
    return approximations[:top_n]


def best_lat_mask(lat: np.ndarray) -> Tuple[int, int, int]:
    """
    Zwraca (alpha, beta, lat_value) o maksymalnej wartości |LAT|.
    Pomija maski zerowe.
    """
    best_alpha = 0
    best_beta = 0
    best_lat = 0
    
    for alpha in range(1, 64):
        for beta in range(1, 16):
            lat_val = lat[alpha][beta]
            if abs(lat_val) > abs(best_lat):
                best_lat = lat_val
                best_alpha = alpha
                best_beta = beta
    
    return best_alpha, best_beta, best_lat


# ============================================================================
# LEMAT O STOSIE (PILING-UP LEMMA)
# ============================================================================

def piling_up_lemma(biases: List[float]) -> float:
    """
    Oblicza całkowity bias dla złożenia przybliżeń liniowych
    za pomocą lematu o stosie.
    
    ε_total = 2^(n-1) * ∏ε_i
    
    Args:
        biases: Lista biasów poszczególnych przybliżeń
        
    Returns:
        Całkowity bias złożonego przybliżenia
    """
    n = len(biases)
    product = 1.0
    for bias in biases:
        product *= bias
    
    return (2 ** (n - 1)) * product


def estimate_required_pairs(bias: float, success_probability: float = 0.95) -> int:
    """
    Szacuje liczbę par tekst jawny-szyfrogram potrzebnych
    do sukcesu ataku z zadanym prawdopodobieństwem.
    
    N ≈ c / ε²
    
    Args:
        bias: Całkowity bias charakterystyki
        success_probability: Żądane prawdopodobieństwo sukcesu
        
    Returns:
        Szacowana liczba potrzebnych par
    """
    if bias == 0:
        return float('inf')
    
    # Stała c zależy od prawdopodobieństwa sukcesu
    # Dla P ≈ 0.95, c ≈ 8
    c = 8.0
    
    return int(c / (bias ** 2))


# ============================================================================
# CHARAKTERYSTYKA LINIOWA
# ============================================================================

class LinearCharacteristic:
    """Reprezentuje wielorundową charakterystykę liniową."""
    
    def __init__(self, num_rounds: int):
        self.num_rounds = num_rounds
        self.input_mask = None      # Maska bitów tekstu jawnego
        self.output_mask = None     # Maska bitów szyfrogramu
        self.key_mask = None        # Maska bitów klucza
        self.bias = 0.0
        self.approximations = []    # Przybliżenia dla każdej rundy
    
    def __str__(self):
        return f"Charakterystyka liniowa {self.num_rounds}-rundowa, bias = {self.bias:.6e}"


def build_3_round_characteristic() -> LinearCharacteristic:
    """
    Buduje 3-rundową charakterystykę liniową dla DES.
    
    Wykorzystuje najlepsze przybliżenie S-bloku 5, które ma
    najwyższy bias spośród wszystkich S-bloków DES.
    
    Returns:
        Charakterystyka liniowa
    """
    char = LinearCharacteristic(3)
    
    # S-blok 5 ma najlepsze przybliżenie z biasem ≈ 20/64 = 0.3125
    # α = 16 (010000), β = 15 (1111)
    
    # Dla 3 rund bias ≈ 2^2 * (20/64)^3
    char.bias = 4 * (20/64) ** 3
    
    return char


def build_14_round_characteristic() -> LinearCharacteristic:
    """
    Buduje 14-rundową charakterystykę liniową dla ataku na pełny DES.
    (Charakterystyka Matsui)
    
    Returns:
        Charakterystyka liniowa
    """
    char = LinearCharacteristic(14)
    
    # Bias dla pełnego 16-rundowego DES
    # ε ≈ 1.19 × 10^-7
    char.bias = 1.19e-7
    
    return char


# ============================================================================
# ATAK LINIOWY (ALGORYTM MATSUI 2)
# ============================================================================

class LinearAttack:
    """Implementacja ataku liniowego na zredukowany DES (Algorytm Matsui 2)."""
    
    def __init__(self, num_rounds: int = 4):
        """
        Inicjalizuje atak.
        
        Args:
            num_rounds: Liczba rund DES do ataku
        """
        self.num_rounds = num_rounds
        self.lats = compute_all_lats()
        self.characteristic = None
        
    def set_characteristic(self, characteristic: LinearCharacteristic):
        """Ustawia charakterystykę liniową do wykorzystania."""
        self.characteristic = characteristic
        
    def compute_approximation_value(self,
                                    ciphertext: List[int],
                                    subkey_guess: List[int],
                                    sbox_index: int,
                                    alpha: int,
                                    beta: int) -> int:
        """
        Oblicza wartość przybliżenia liniowego dla danej pary P-C
        i zgadywanego fragmentu klucza.
        
        Args:
            ciphertext: Szyfrogram (64 bity)
            subkey_guess: Zgadywane 6 bitów podklucza
            sbox_index: Indeks S-bloku
            alpha: Maska wejściowa (6 bitów)
            beta: Maska wyjściowa (4 bity)
            
        Returns:
            Wartość przybliżenia (0 lub 1)
        """
        # Odwracamy permutację końcową
        after_ip_inv = permute(ciphertext, IP)
        
        R16 = after_ip_inv[:32]
        L16 = after_ip_inv[32:]
        
        R15 = L16
        
        # Rozszerzamy R15
        expanded_R15 = permute(R15, E)
        
        # Wyciągamy 6 bitów dla danego S-bloku
        start = sbox_index * 6
        input_bits = expanded_R15[start:start + 6]
        
        # XOR z zgadywanym fragmentem klucza
        xored = xor(input_bits, subkey_guess)
        xored_int = bits_to_int(xored)
        
        # Podstawienie S-bloku
        row = ((xored_int >> 5) & 1) << 1 | (xored_int & 1)
        col = (xored_int >> 1) & 0x0F
        sbox_output = S_BOXES[sbox_index][row][col]
        
        input_parity = parity(xored_int & alpha)
        output_parity = parity(sbox_output & beta)
        
        return 0 if input_parity == output_parity else 1
    
    def attack_sbox(self,
                    pairs: List[Tuple[List[int], List[int]]],
                    sbox_index: int) -> Tuple[int, Dict[int, int]]:
        """
        Algorytm Matsui 2 - atak na pojedynczy S-blok.
        
        Args:
            pairs: Lista par (plaintext, ciphertext)
            sbox_index: Indeks S-bloku do zaatakowania
            
        Returns:
            Tuple (best_key, counters_dict)
        """
        counters = defaultdict(int)
        N = len(pairs)
        
        lat = self.lats[sbox_index]
        alpha, beta, lat_val = best_lat_mask(lat)
        bias = abs(lat_val) / 64.0
        
        print(f"    S-blok {sbox_index + 1}: wybrane maski "
              f"α={alpha:02d}, β={beta:02d}, |LAT|={abs(lat_val):02d}, bias={bias:.4f}")
        
        for plaintext, ciphertext in pairs:
            for key_guess in range(64):
                key_bits = int_to_bits(key_guess, 6)
                
                # Obliczamy wartość przybliżenia
                approx_val = self.compute_approximation_value(
                    ciphertext, key_bits, sbox_index, alpha, beta
                )
                
                # Jeśli przybliżenie jest spełnione, zwiększamy licznik
                if approx_val == 0:
                    counters[key_guess] += 1
        
        # Znajdujemy klucz z największym odchyleniem od N/2
        best_key = 0
        max_deviation = 0
        
        for key, count in counters.items():
            deviation = abs(count - N // 2)
            if deviation > max_deviation:
                max_deviation = deviation
                best_key = key
        
        return best_key, dict(counters)
    
    def run_attack(self,
                   pairs: List[Tuple[List[int], List[int]]]) -> Dict[int, int]:
        """
        Przeprowadza pełny atak liniowy.
        
        Args:
            pairs: Lista par (plaintext, ciphertext)
            
        Returns:
            Słownik {sbox_index: recovered_key_bits}
        """
        print(f"\n{'=' * 60}")
        print(f"ATAK LINIOWY NA {self.num_rounds}-RUNDOWY DES")
        print(f"{'=' * 60}")
        print(f"Liczba par: {len(pairs)}")
        
        if self.characteristic:
            print(f"Bias charakterystyki: {self.characteristic.bias:.2e}")
            estimated_pairs = estimate_required_pairs(self.characteristic.bias)
            print(f"Szacowana liczba potrzebnych par: {estimated_pairs}")
        
        # Atak na każdy S-blok
        print(f"\n[1] Atak na S-bloki ostatniej rundy (Algorytm Matsui 2)...")
        recovered_keys = {}
        
        for sbox_idx in range(8):
            best_key, counters = self.attack_sbox(pairs, sbox_idx)
            recovered_keys[sbox_idx] = best_key
            
            if counters:
                N = len(pairs)
                count = counters.get(best_key, 0)
                deviation = abs(count - N // 2)
                print(f"    S-blok {sbox_idx + 1}: klucz = {best_key:02X} "
                      f"(6 bitów: {best_key:06b}), |T - N/2| = {deviation}")
        
        # Składamy odzyskane fragmenty klucza
        print(f"\n[2] Składanie odzyskanego podklucza...")
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

def demonstrate_lat():
    """Demonstracja tabeli LAT dla S-bloków."""
    print("\n" + "=" * 60)
    print("ANALIZA LAT DLA S-BLOKÓW DES")
    print("=" * 60)
    
    lats = compute_all_lats()
    
    for i, lat in enumerate(lats):
        print(f"\nS-blok {i + 1}:")
        print("-" * 50)
        
        # Najlepsze przybliżenia liniowe
        best = find_best_approximations(lat, top_n=5)
        
        print(f"{'α (in)':>8} {'β (out)':>8} {'LAT val':>10} {'Bias':>12}")
        print("-" * 50)
        
        for alpha, beta, lat_val, bias in best:
            print(f"{alpha:>8} {beta:>8} {lat_val:>+10} {bias:>12.4f}")
        
        # Statystyki
        max_abs_val = np.max(np.abs(lat[1:, 1:]))
        print(f"\nMaksymalna wartość |LAT|: {max_abs_val}")
        print(f"Odpowiadający bias: {max_abs_val / 64:.4f}")


def demonstrate_piling_up():
    """Demonstracja lematu o stosie."""
    print("\n" + "=" * 60)
    print("LEMAT O STOSIE (PILING-UP LEMMA)")
    print("=" * 60)
    
    # Przykład: łączymy przybliżenia z biasami
    biases = [0.3125, 0.3125, 0.3125]  # 3 rundy z biasem 20/64
    
    total_bias = piling_up_lemma(biases)
    required_pairs = estimate_required_pairs(total_bias)
    
    print(f"\nBiasy poszczególnych przybliżeń: {biases}")
    print(f"Całkowity bias (lemat o stosie): {total_bias:.6f}")
    print(f"Szacowana liczba potrzebnych par: {required_pairs}")
    
    # Dla pełnego DES
    print("\n" + "-" * 40)
    print("Dla pełnego 16-rundowego DES (Matsui 1994):")
    full_des_bias = 1.19e-7
    full_des_pairs = estimate_required_pairs(full_des_bias)
    print(f"Bias: {full_des_bias:.2e}")
    print(f"Wymagana liczba par: {full_des_pairs:.2e} ≈ 2^43")


def demonstrate_attack(num_rounds: int = 4):
    """Demonstracja ataku liniowego na zredukowany DES."""
    print("\n" + "=" * 60)
    print("DEMONSTRACJA ATAKU LINIOWEGO")
    print("=" * 60)
    
    import random
    random.seed(42)
    
    # Klucz do odzyskania
    key_hex = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
    key_bits = hex_to_bits(key_hex)
    
    print(f"\nKlucz (do odzyskania): {key_hex}")
    
    if num_rounds != 4:
        print(f"\n⚠️  Żądana liczba rund: {num_rounds}")
        print("    Demonstracja używa stałej charakterystyki 4-rundowej.")
        print("    Użyte rundy: 4")
        num_rounds = 4
    
    # Zbieramy pary tekst jawny - szyfrogram
    num_pairs = 1000
    pairs = []
    
    print(f"\n[1] Generowanie {num_pairs} par tekst jawny - szyfrogram...")
    
    for _ in range(num_pairs):
        # Losowy tekst jawny
        plaintext = [random.randint(0, 1) for _ in range(64)]
        
        # Szyfrujemy z ograniczoną liczbą rund
        ciphertext, _, _ = des_encrypt_block_rounds(plaintext, key_bits, num_rounds=num_rounds)
        
        pairs.append((plaintext, ciphertext))
    
    print(f"    Wygenerowano {len(pairs)} par")
    
    # Przeprowadzamy atak
    attack = LinearAttack(num_rounds=num_rounds)
    attack.set_characteristic(build_3_round_characteristic())
    
    recovered_keys = attack.run_attack(pairs)
    
    # Weryfikacja
    print("\n" + "=" * 60)
    print("WERYFIKACJA")
    print("=" * 60)
    
    true_subkeys = generate_subkeys(key_bits)
    true_k4 = true_subkeys[3]
    
    matches = 0
    print(f"\nPrawdziwy podklucz K4:")
    for i in range(8):
        true_6bits = bits_to_int(true_k4[i*6:(i+1)*6])
        recovered = recovered_keys.get(i, -1)
        match = "✓" if true_6bits == recovered else "✗"
        if true_6bits == recovered:
            matches += 1
        print(f"  S-blok {i+1}: prawdziwy = {true_6bits:02X}, "
              f"odzyskany = {recovered:02X} {match}")
    
    print(f"\nOdzyskano poprawnie: {matches}/8 fragmentów klucza")


if __name__ == "__main__":
    # Analiza LAT
    demonstrate_lat()
    
    # Demonstracja lematu o stosie
    demonstrate_piling_up()
    
    # Demonstracja ataku
    demonstrate_attack()
