"""
Główny moduł demonstracyjny dla ataków na DES
Uruchamia wszystkie demonstracje i testy

Autorzy: Projekt KRYS - Kryptografia Stosowana
"""

import sys
import argparse


def run_des_tests():
    """Uruchamia testy implementacji DES."""
    print("\n" + "=" * 70)
    print(" " * 20 + "TESTY ALGORYTMU DES")
    print("=" * 70)
    
    from des import encrypt, decrypt
    
    # Wektory testowe
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
        },
        {
            "key": "0000000000000000",
            "plaintext": "0000000000000000",
            "expected": "8CA64DE9C1B123A7"
        }
    ]
    
    all_passed = True
    
    for i, tv in enumerate(test_vectors):
        ciphertext = encrypt(tv["plaintext"], tv["key"])
        decrypted = decrypt(ciphertext, tv["key"])
        
        encrypt_ok = ciphertext == tv["expected"]
        decrypt_ok = decrypted == tv["plaintext"]
        
        status = "✓ PASS" if (encrypt_ok and decrypt_ok) else "✗ FAIL"
        
        print(f"\nTest {i + 1}: {status}")
        print(f"  Klucz:        {tv['key']}")
        print(f"  Plaintext:    {tv['plaintext']}")
        print(f"  Ciphertext:   {ciphertext}")
        print(f"  Expected:     {tv['expected']}")
        print(f"  Decrypted:    {decrypted}")
        
        if not (encrypt_ok and decrypt_ok):
            all_passed = False
    
    return all_passed


def run_differential_analysis():
    """Uruchamia analizę różnicową (DDT)."""
    print("\n" + "=" * 70)
    print(" " * 15 + "ANALIZA TABLIC DDT (ATAK RÓŻNICOWY)")
    print("=" * 70)
    
    from differential_attack import demonstrate_ddt
    demonstrate_ddt()


def run_differential_attack(num_rounds: int = 4):
    """Uruchamia demonstrację ataku różnicowego."""
    print("\n" + "=" * 70)
    print(" " * 15 + "DEMONSTRACJA ATAKU RÓŻNICOWEGO")
    print("=" * 70)
    
    from differential_attack import demonstrate_attack
    
    if num_rounds != 4:
        print(f"\n⚠️  Żądana liczba rund: {num_rounds}")
        print("    Demonstracja używa stałej charakterystyki 4-rundowej.")
        print("    Użyte rundy: 4")
        num_rounds = 4
    
    print(f"\nUżywane rundy (demo): {num_rounds}")
    print("Uwaga: pełny DES wymaga ok. 2^47 par dla ataku różnicowego.")
    demonstrate_attack(num_rounds=num_rounds)


def run_linear_analysis():
    """Uruchamia analizę liniową (LAT)."""
    print("\n" + "=" * 70)
    print(" " * 15 + "ANALIZA TABLIC LAT (ATAK LINIOWY)")
    print("=" * 70)
    
    from linear_attack import demonstrate_lat, demonstrate_piling_up
    demonstrate_lat()
    demonstrate_piling_up()


def run_linear_attack(num_rounds: int = 4):
    """Uruchamia demonstrację ataku liniowego."""
    print("\n" + "=" * 70)
    print(" " * 15 + "DEMONSTRACJA ATAKU LINIOWEGO")
    print("=" * 70)
    
    from linear_attack import demonstrate_attack
    
    if num_rounds != 4:
        print(f"\n⚠️  Żądana liczba rund: {num_rounds}")
        print("    Demonstracja używa stałej charakterystyki 4-rundowej.")
        print("    Użyte rundy: 4")
        num_rounds = 4
    
    print(f"\nUżywane rundy (demo): {num_rounds}")
    print("Uwaga: pełny DES wymaga ok. 2^43 par dla ataku liniowego.")
    demonstrate_attack(num_rounds=num_rounds)


def run_all(num_rounds: int = 4):
    """Uruchamia wszystkie demonstracje."""
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + " " * 10 + "ATAKI RÓŻNICOWY I LINIOWY NA DES" + " " * 25 + "#")
    print("#" + " " * 10 + "Projekt KRYS - Kryptografia Stosowana" + " " * 20 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)
    
    # 1. Testy DES
    print("\n\n" + "▶" * 30)
    print("FAZA 1: TESTOWANIE IMPLEMENTACJI DES")
    print("▶" * 30)
    des_ok = run_des_tests()
    
    if not des_ok:
        print("\n⚠️  UWAGA: Testy DES nie przeszły pomyślnie!")
        print("    Sprawdź implementację przed kontynuowaniem.")
        return
    
    print("\n✅ Wszystkie testy DES przeszły pomyślnie!")
    
    # 2. Analiza DDT
    print("\n\n" + "▶" * 30)
    print("FAZA 2: ANALIZA TABLIC DDT")
    print("▶" * 30)
    run_differential_analysis()
    
    # 3. Atak różnicowy
    print("\n\n" + "▶" * 30)
    print("FAZA 3: ATAK RÓŻNICOWY")
    print("▶" * 30)
    if num_rounds >= 16:
        print("\n⚠️  Ostrzeżenie: pełny 16-rundowy DES jest niepraktyczny")
        print("    dla demonstracyjnych ataków (wymaga ~2^43–2^47 par).")
    run_differential_attack(num_rounds)
    
    # 4. Analiza LAT
    print("\n\n" + "▶" * 30)
    print("FAZA 4: ANALIZA TABLIC LAT")
    print("▶" * 30)
    run_linear_analysis()
    
    # 5. Atak liniowy
    print("\n\n" + "▶" * 30)
    print("FAZA 5: ATAK LINIOWY")
    print("▶" * 30)
    if num_rounds >= 16:
        print("\n⚠️  Ostrzeżenie: pełny 16-rundowy DES jest niepraktyczny")
        print("    dla demonstracyjnych ataków (wymaga ~2^43–2^47 par).")
    run_linear_attack(num_rounds)
    
    # Podsumowanie
    print("\n\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + " " * 20 + "DEMONSTRACJA ZAKOŃCZONA" + " " * 25 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)


def main():
    """Główna funkcja programu."""
    parser = argparse.ArgumentParser(
        description="Ataki różnicowy i liniowy na DES",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Przykłady użycia:
  python main.py                    # Uruchom wszystkie demonstracje
  python main.py --test-des         # Tylko testy DES
  python main.py --differential     # Tylko atak różnicowy
  python main.py --linear           # Tylko atak liniowy
  python main.py --analyze-ddt      # Tylko analiza DDT
  python main.py --analyze-lat      # Tylko analiza LAT
        """
    )
    
    parser.add_argument('--test-des', action='store_true',
                        help='Uruchom testy implementacji DES')
    parser.add_argument('--differential', action='store_true',
                        help='Uruchom demonstrację ataku różnicowego')
    parser.add_argument('--linear', action='store_true',
                        help='Uruchom demonstrację ataku liniowego')
    parser.add_argument('--analyze-ddt', action='store_true',
                        help='Uruchom analizę tablic DDT')
    parser.add_argument('--analyze-lat', action='store_true',
                        help='Uruchom analizę tablic LAT')
    parser.add_argument('--all', action='store_true',
                        help='Uruchom wszystkie demonstracje (domyślnie)')
    parser.add_argument('--rounds', type=int, default=4,
                        help='Liczba rund używana w demonstracjach ataków (domyślnie 4)')
    
    args = parser.parse_args()
    
    # Jeśli nie wybrano żadnej opcji, uruchom wszystko
    if not any([args.test_des, args.differential, args.linear,
                args.analyze_ddt, args.analyze_lat, args.all]):
        args.all = True
    
    if args.all:
        run_all(args.rounds)
    else:
        if args.test_des:
            run_des_tests()
        if args.analyze_ddt:
            run_differential_analysis()
        if args.differential:
            if args.rounds >= 16:
                print("\n⚠️  Ostrzeżenie: pełny 16-rundowy DES jest niepraktyczny")
                print("    dla demonstracyjnych ataków (wymaga ~2^43–2^47 par).")
            run_differential_attack(args.rounds)
        if args.analyze_lat:
            run_linear_analysis()
        if args.linear:
            if args.rounds >= 16:
                print("\n⚠️  Ostrzeżenie: pełny 16-rundowy DES jest niepraktyczny")
                print("    dla demonstracyjnych ataków (wymaga ~2^43–2^47 par).")
            run_linear_attack(args.rounds)


if __name__ == "__main__":
    main()
