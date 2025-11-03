import csv
from collections import Counter
import re


def count_letter_frequencies(text):
    letters = [ch.lower() for ch in text if ch.isalpha()]
    return Counter(letters)


def find_common_words(text, length):
    # Extract words (sequences of letters)
    words = re.findall(r'[a-z]+', text.lower())
    # Filter by length
    words_of_length = [w for w in words if len(w) == length]
    return Counter(words_of_length)


def create_mapping(ciphertext):
    mapping = {}
    used_plaintext = set()  # Track which plaintext letters are already used

    # Count letter frequencies
    letter_freq = count_letter_frequencies(ciphertext)
    most_common_letters = letter_freq.most_common()

    # Step 1: Most common letter -> 'e'
    if most_common_letters:
        most_common_letter = most_common_letters[0][0]
        mapping[most_common_letter] = 'e'
        used_plaintext.add('e')
        print(f"[1] Most common letter '{most_common_letter}' -> 'e'")

    # Step 2: Most common 3-letter word that ends with the letter mapped to 'e' -> 'the'
    three_letter_words = find_common_words(ciphertext, 3)
    if three_letter_words:
        # Find which cipher letter maps to 'e'
        cipher_e = None
        for cipher_ch, plain_ch in mapping.items():
            if plain_ch == 'e':
                cipher_e = cipher_ch
                break

        # Find the most common 3-letter word ending with the cipher letter for 'e'
        most_common_3 = None
        if cipher_e:
            for word, count in three_letter_words.most_common():
                if word[-1] == cipher_e:  # Last letter matches cipher 'e'
                    most_common_3 = word
                    break

        if most_common_3:
            print(f"[2] Most common 3-letter word ending with '{cipher_e}': '{most_common_3}' -> 'the'")
            for i, cipher_ch in enumerate(most_common_3):
                plain_ch = 'the'[i]
                if cipher_ch not in mapping and plain_ch not in used_plaintext:
                    mapping[cipher_ch] = plain_ch
                    used_plaintext.add(plain_ch)
                    print(f"    '{cipher_ch}' -> '{plain_ch}'")
                elif cipher_ch in mapping:
                    print(f"    '{cipher_ch}' already mapped to '{mapping[cipher_ch]}', skipping")
                elif plain_ch in used_plaintext:
                    print(f"    plaintext '{plain_ch}' already used, skipping cipher letter '{cipher_ch}'")
        else:
            print(f"[2] No 3-letter word found ending with '{cipher_e}' (cipher for 'e')")

    # Step 3: Most common 2-letter word -> 'to'
    two_letter_words = find_common_words(ciphertext, 2)
    if two_letter_words:
        most_common_2 = two_letter_words.most_common(1)[0][0]
        print(f"[3] Most common 2-letter word '{most_common_2}' -> 'to'")
        for i, cipher_ch in enumerate(most_common_2):
            plain_ch = 'to'[i]
            if cipher_ch not in mapping and plain_ch not in used_plaintext:
                mapping[cipher_ch] = plain_ch
                used_plaintext.add(plain_ch)
                print(f"    '{cipher_ch}' -> '{plain_ch}'")
            elif cipher_ch in mapping:
                print(f"    '{cipher_ch}' already mapped to '{mapping[cipher_ch]}', skipping")
            elif plain_ch in used_plaintext:
                print(f"    plaintext '{plain_ch}' already used, skipping cipher letter '{cipher_ch}'")

    # Step 4: 2nd most common letter -> 't'
    if len(most_common_letters) >= 2:
        second_common_letter = most_common_letters[1][0]
        if second_common_letter not in mapping and 't' not in used_plaintext:
            mapping[second_common_letter] = 't'
            used_plaintext.add('t')
            print(f"[4] 2nd most common letter '{second_common_letter}' -> 't'")
        elif second_common_letter in mapping:
            print(f"[4] 2nd most common letter '{second_common_letter}' already mapped to '{mapping[second_common_letter]}', skipping")
        elif 't' in used_plaintext:
            print(f"[4] plaintext 't' already used, skipping")

    # Step 5: Manual corrections based on pattern recognition
    # cti -> and, ENbrNEEfrNb -> ENGINEERING
    print("\n[5] Applying manual corrections...")
    manual_mappings = {
        'c': 'a',
        't': 'n',
        'i': 'd',
        'b': 'g',
        'r': 'i',
        'f': 'r',
        'n': 'b',
        'w': 'u',
        'a': 'l',
        'u': 's',
        'k': 'c',
        'p': 'y',
        'q': 'm',
        'd': 'p',
        'x': 'f',
        'v': 'x',
        's': 'v'
    }

    for cipher_ch, plain_ch in manual_mappings.items():
        if cipher_ch not in mapping and plain_ch not in used_plaintext:
            mapping[cipher_ch] = plain_ch
            used_plaintext.add(plain_ch)
            print(f"    '{cipher_ch}' -> '{plain_ch}'")
        elif cipher_ch in mapping:
            print(f"    '{cipher_ch}' already mapped to '{mapping[cipher_ch]}', skipping")
        elif plain_ch in used_plaintext:
            print(f"    plaintext '{plain_ch}' already used, skipping cipher letter '{cipher_ch}'")

    return mapping


def decode_text(ciphertext, mapping):
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            lower_ch = ch.lower()
            if lower_ch in mapping:
                # Letter was mapped - make it UPPERCASE
                result.append(mapping[lower_ch].upper())
            else:
                # Letter was not mapped - keep it lowercase
                result.append(lower_ch)
        else:
            # Keep spaces and punctuation unchanged
            result.append(ch)

    return ''.join(result)


def save_mapping_to_csv(mapping, cipher_freq, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['cipher_letter', 'cipher_count', 'plaintext_letter'])
        for cipher_letter in sorted(mapping.keys()):
            plaintext_letter = mapping[cipher_letter]
            count = cipher_freq.get(cipher_letter, 0)
            writer.writerow([cipher_letter, count, plaintext_letter])


def main():
    # File paths
    cipher_file = "../../cipher.txt"

    # Read ciphertext
    print("[*] Reading ciphertext...")
    with open(cipher_file, 'r') as f:
        ciphertext = f.read()

    # Create substitution mapping using 4 rules
    print("\n[*] Creating substitution mapping using 4 rules...")
    print("="*80)
    mapping = create_mapping(ciphertext)
    print("="*80)

    # Count letter frequencies for CSV
    cipher_freq = count_letter_frequencies(ciphertext)

    # Decode the ciphertext
    print("\n[*] Decoding ciphertext...")
    decoded_text = decode_text(ciphertext, mapping)

    # Save to cipher_copy.txt
    cipher_copy_file = "cipher_copy.txt"
    with open(cipher_copy_file, 'w') as f:
        f.write(decoded_text)
    print(f"[+] Decoded text saved to {cipher_copy_file}")

    # Save mapping to CSV
    mapping_csv = "mappings.csv"
    save_mapping_to_csv(mapping, cipher_freq, mapping_csv)
    print(f"[+] Substitution mapping saved to {mapping_csv}")

    # Print results
    print("\n" + "="*80)
    print("DECODED TEXT (UPPERCASE = replaced, lowercase = not matched)")
    print("="*80)
    print(decoded_text)
    print("\n" + "="*80)

    # Print mapping summary
    print("\n" + "="*80)
    print("FINAL SUBSTITUTION MAPPING")
    print("="*80)
    for cipher_letter in sorted(mapping.keys()):
        plaintext_letter = mapping[cipher_letter]
        count = cipher_freq[cipher_letter]
        print(f"{cipher_letter} -> {plaintext_letter} (appeared {count} times)")
    print("="*80)

    print(f"\n[*] Total mappings created: {len(mapping)}")


if __name__ == "__main__":
    main()
