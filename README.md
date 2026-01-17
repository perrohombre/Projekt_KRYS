# Ataki różnicowy i liniowy na DES

> **Projekt KRYS** — Kryptografia Stosowana  
> Politechnika Warszawska, 2026

## 📋 Opis projektu

Projekt zawiera pełną implementację algorytmu **DES (Data Encryption Standard)** oraz dwóch klasycznych ataków kryptanalitycznych:

| Atak | Metoda | Autorzy | Rok |
|------|--------|---------|-----|
| **Różnicowy** | Differential Cryptanalysis | Eli Biham, Adi Shamir | 1990 |
| **Liniowy** | Linear Cryptanalysis (Matsui 2) | Mitsuru Matsui | 1993 |

Implementacja umożliwia:
- Szyfrowanie i deszyfrowanie bloków 64-bitowych algorytmem DES
- Generowanie tablic DDT (Differential Distribution Table) dla S-bloków
- Generowanie tablic LAT (Linear Approximation Table) dla S-bloków
- Przeprowadzenie demonstracyjnych ataków na zredukowane wersje DES (4-8 rund)
- Analizę słabości strukturalnych S-bloków DES

---

## 📁 Struktura projektu

```
KRYS/
├── src/
│   ├── des.py                  # Pełna implementacja algorytmu DES
│   ├── differential_attack.py  # Atak różnicowy (DDT, charakterystyki)
│   ├── linear_attack.py        # Atak liniowy (LAT, Matsui 2)
│   └── main.py                 # Główny moduł demonstracyjny
├── .venv/                      # Środowisko wirtualne Python
├── requirements.txt            # Zależności Python
└── README.md                   # Dokumentacja (ten plik)
```

---

## 🔧 Wymagania techniczne

### System operacyjny
- macOS 10.15+ / Linux / Windows 10+

### Python
- **Python 3.8** lub nowszy (testowane na Python 3.13)

### Biblioteki
- `numpy >= 1.20.0` — operacje na tablicach i macierzach

---

## 🚀 Instrukcja instalacji i uruchomienia

### 1. Klonowanie repozytorium
```bash
git clone <repo-url>
cd KRYS
```

### 2. Utworzenie środowiska wirtualnego
```bash
python3 -m venv .venv
```

### 3. Aktywacja środowiska

**macOS / Linux:**
```bash
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
.venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
.venv\Scripts\activate.bat
```

### 4. Instalacja zależności
```bash
pip install -r requirements.txt
```

### 5. Uruchomienie programu

**Wszystkie demonstracje:**
```bash
cd src
python main.py
```

**Poszczególne moduły:**
```bash
python main.py --test-des        # Testy implementacji DES
python main.py --analyze-ddt     # Analiza tablic DDT
python main.py --differential    # Demonstracja ataku różnicowego
python main.py --analyze-lat     # Analiza tablic LAT
python main.py --linear          # Demonstracja ataku liniowego
python main.py --all             # Wszystko (domyślnie)
```

---

## 📊 Otrzymane wyniki

### Test implementacji DES

```
============================================================
TEST IMPLEMENTACJI DES
============================================================

Test 1:
  Klucz:          133457799BBCDFF1
  Tekst jawny:    0123456789ABCDEF
  Szyfrogram:     85E813540F0AB405
  Oczekiwany:     85E813540F0AB405
  Zgodność:       ✓ TAK
  Roundtrip:      ✓ TAK

Test 2:
  Klucz:          0E329232EA6D0D73
  Tekst jawny:    8787878787878787
  Szyfrogram:     0000000000000000
  Zgodność:       ✓ TAK
```

✅ **Implementacja DES jest zgodna z oficjalną specyfikacją FIPS 46-3**

---

### Analiza DDT (Atak różnicowy)

Najlepsze przejścia różnicowe dla S-bloków DES:

| S-blok | Δ_in | Δ_out | Count | Prawdopodobieństwo |
|--------|------|-------|-------|-------------------|
| S1 | 52 | 2 | 16 | 0.2500 (1/4) |
| S2 | 8 | 10 | 16 | 0.2500 (1/4) |
| S3 | 32 | 13 | 16 | 0.2500 (1/4) |
| S4 | 1 | 5 | 16 | 0.2500 (1/4) |
| S5 | 5 | 10 | 16 | 0.2500 (1/4) |
| S6 | 1 | 13 | 16 | 0.2500 (1/4) |
| S7 | 34 | 2 | 16 | 0.2500 (1/4) |
| S8 | 22 | 13 | 16 | 0.2500 (1/4) |

**Wniosek:** Maksymalne prawdopodobieństwo przejścia różnicowego przez S-blok wynosi **1/4** (16/64), co jest zgodne z projektem DES ograniczającym skuteczność ataków różnicowych.

---

### Analiza LAT (Atak liniowy)

Najlepsze przybliżenia liniowe dla S-bloków DES:

| S-blok | α (maska wej.) | β (maska wyj.) | LAT | Bias |
|--------|----------------|----------------|-----|------|
| **S5** | 16 | 15 | **-20** | **0.3125** |
| S1 | 16 | 15 | -18 | 0.2812 |
| S7 | 59 | 4 | -18 | 0.2812 |
| S2 | 34 | 11 | -16 | 0.2500 |
| S3 | 34 | 15 | +16 | 0.2500 |

⚠️ **S-blok 5 ma najwyższy bias (20/64 ≈ 0.3125)** — jest to znana "pięta achillesowa" DES, wykorzystana przez Matsui do złamania algorytmu.

---

### Demonstracja ataku różnicowego (4 rundy)

```
============================================================
ATAK RÓŻNICOWY NA 4-RUNDOWY DES
============================================================
Charakterystyka: ΔL = 40080000, ΔR = 04000000
Prawdopodobieństwo: 3.91e-03
Liczba par: 500

[1] Zbieranie par tekst jawny - szyfrogram...
    Zebrano 500 par

[2] Atak na S-bloki ostatniej rundy...
    S-blok 1: klucz = 29, score = 38
    S-blok 2: klucz = 01, score = 49
    S-blok 3: klucz = 04, score = 42
    ...
```

---

## 📈 Złożoność ataków — podsumowanie teoretyczne

| Liczba rund | Atak różnicowy | Atak liniowy | Brute-force |
|-------------|----------------|--------------|-------------|
| 4 | 2⁴ par | 2⁸ par | 2⁵⁶ |
| 6 | 2⁸ par | 2¹² par | 2⁵⁶ |
| 8 | 2¹⁶ par | 2²⁰ par | 2⁵⁶ |
| 12 | 2⁴³ par | 2³⁸ par | 2⁵⁶ |
| **16 (pełny)** | **2⁴⁷ par** | **2⁴³ par** | **2⁵⁶** |

**Wnioski:**
1. Atak liniowy (2⁴³) jest bardziej efektywny niż brute-force (2⁵⁶) dla pełnego DES
2. Atak różnicowy (2⁴⁷) również jest lepszy niż brute-force, ale gorszy od liniowego
3. Dla zredukowanych wersji DES (≤8 rund) oba ataki są praktycznie wykonalne

---

## 🔬 Opis modułów

### `des.py` — Implementacja DES
- Wszystkie tablice permutacji (IP, FP, E, P, PC-1, PC-2)
- 8 S-bloków zgodnych ze specyfikacją FIPS 46-3
- Generowanie 16 podkluczy 48-bitowych
- Funkcja Feistela z rozszerzeniem E i permutacją P
- Funkcje wysokiego poziomu: `encrypt()`, `decrypt()`

### `differential_attack.py` — Kryptoanaliza różnicowa
- `compute_ddt()` — obliczanie tablic DDT dla S-bloków
- `find_best_differentials()` — wyszukiwanie optymalnych przejść
- `DifferentialCharacteristic` — klasa charakterystyki wielorundowej
- `DifferentialAttack` — pełny atak z częściowym odszyfrowaniem

### `linear_attack.py` — Kryptoanaliza liniowa
- `compute_lat()` — obliczanie tablic LAT dla S-bloków
- `piling_up_lemma()` — łączenie przybliżeń (lemat o stosie)
- `estimate_required_pairs()` — szacowanie liczby par
- `LinearAttack` — implementacja algorytmu Matsui 2

---

## 📚 Przykłady użycia API

### Szyfrowanie i deszyfrowanie
```python
from des import encrypt, decrypt

# Szyfrowanie
ciphertext = encrypt("0123456789ABCDEF", "133457799BBCDFF1")
print(f"Szyfrogram: {ciphertext}")  # 85E813540F0AB405

# Deszyfrowanie
plaintext = decrypt(ciphertext, "133457799BBCDFF1")
print(f"Plaintext: {plaintext}")    # 0123456789ABCDEF
```

### Analiza DDT
```python
from differential_attack import compute_ddt, find_best_differentials, S_BOXES

ddt = compute_ddt(S_BOXES[4])  # S-blok 5
best = find_best_differentials(ddt, top_n=5)
for delta_in, delta_out, count, prob in best:
    print(f"Δin={delta_in}, Δout={delta_out}, p={prob:.4f}")
```

### Analiza LAT
```python
from linear_attack import compute_lat, find_best_approximations, S_BOXES

lat = compute_lat(S_BOXES[4])  # S-blok 5
best = find_best_approximations(lat, top_n=5)
for alpha, beta, lat_val, bias in best:
    print(f"α={alpha}, β={beta}, LAT={lat_val:+d}, bias={bias:.4f}")
```

---

## 👥 Autorzy

**Projekt KRYS — Kryptografia Stosowana**

| Imię i nazwisko | Rola |
|-----------------|------|
| Maja Zglinicka | Dokumentacja teoretyczna |
| Patryk Kosiński | Implementacja DES |
| Eryk Głąb | Atak różnicowy |
| Tomasz Lewiński | Atak liniowy |
| Aleksander Gajowniczek | Integracja i testy |
| Juliusz Kluge | Analiza MILP |

---

## 📖 Bibliografia

1. Biham, E., Shamir, A. — *"Differential Cryptanalysis of the Data Encryption Standard"*, Springer-Verlag, 1993
2. Matsui, M. — *"Linear Cryptanalysis Method for DES Cipher"*, EUROCRYPT 1993
3. NIST — *"Data Encryption Standard (DES)"*, FIPS PUB 46-3, 1999
4. Heys, H.M. — *"A Tutorial on Linear and Differential Cryptanalysis"*, Cryptologia, 2002

---

## 📄 Licencja

Projekt edukacyjny — Politechnika Warszawska, 2026
