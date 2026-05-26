"""
Below are the key steps in DES  algorithm to be implemented. 

1. Initial Permutation (IP)
2. Key Generation (K)
3. Rounds of Encryption (16 rounds)
4. Final Permutation (IP^-1) """   
"""
Plaintext (64) → IP → (L0|R0)
→ 16 x [ Li = Ri-1; Ri = Li-1 XOR f(Ri-1, Ki) ]
→ swap → IP^-1  → Ciphertext (64)

Key (64) → PC-1 → (C0|D0) → rotations → PC-2 → K1..K16 (48 each)


Reference document for data and clarifications : 
https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf

https://en.wikipedia.org/wiki/DES_supplementary_material


"""


ip_table = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
pc1_table = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
pc2_table = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
e_box_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
p_box_table = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
ip_inverse_table = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

s_boxes = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

def text_to_binary(text):
    # print(f"\ntext_to_binary() Input: {text}")
    binarystr = ''
    for character in text:
        binarystr += format(ord(character), '08b')
    padded_binary = binarystr.ljust(64, '0')
    # print(f"\ntext_to_binary() Output: {padded_binary}")
    return padded_binary

def binary_to_text(binarystr):
    text = ''
    for i in range(0, len(binarystr), 8):
        byte = binarystr[i:i+8]
        text += chr(int(byte, 2))
    # print(f"\nbinary_to_text() Output text: {text}")
    return text

def pad(text):
    amount_to_fill = 8 - (len(text) % 8)
    padding_byte = chr(amount_to_fill)
    padded_result = text + (padding_byte * amount_to_fill)
    # print(f"\npad() Original text: {text} | Padded text: {padded_result}")
    return padded_result

def unpad(text):
    amount_to_remove = ord(text[-1])
    unpadded_result = text[:-amount_to_remove]
    return unpadded_result

def generate_round_keys(secret_key):
    # print(f"\ngenerate_round_keys() Generating round keys for secret key: {secret_key)}")
    binary_key = text_to_binary(secret_key)
    
    pc1_key = ''
    for bit in pc1_table:
        pc1_key += binary_key[bit - 1]
    # print(f"\ngenerate_round_keys() PC-1 Key (56-bit): {pc1_key}")
        
    lefthalf = pc1_key[:28]
    righthalf = pc1_key[28:]
    
    rnd_keys = []
    
    for round_number in range(16):
        shift_amount = shift_schedule[round_number]
        
        lefthalf = lefthalf[shift_amount:] + lefthalf[:shift_amount]
        righthalf = righthalf[shift_amount:] + righthalf[:shift_amount]
        
        combined = lefthalf + righthalf
        
        round_key = ''
        for bit in pc2_table:
            round_key += combined[bit - 1]
            
        rnd_keys.append(round_key)
        # print(f"generate_round_keys()ound {round_number + 1} Key (48-bit): {round_key}")
        
    return rnd_keys

def process_block(binary_data, rnd_keys):
    # print(f"\n process_block() Initial 64-bit block: {binary_data}")
    ip_result = ''
    for i in range(64):
        ip_result += binary_data[ip_table[i] - 1]
    # print(f"process_block() After IP permutation: {ip_result}")
        
    lefthalf = ip_result[:32]
    righthalf = ip_result[32:]
    
    for round_number in range(16):
        # print(f"\n--- process_block() Round {round_number + 1} ---")
        # print(f" L{round_number}: {lefthalf}")
        # print(f" R{round_number}: {righthalf}")
        
        expanded_right = ''
        for i in e_box_table:
            expanded_right += righthalf[i - 1]
        # print(f" Expanded Right (48-bit): {expanded_right}")
            
        current_round_key = rnd_keys[round_number]
        xor_reslt = ''
        for i in range(48):
            xor_reslt += str(int(expanded_right[i]) ^ int(current_round_key[i]))
            
        six_bit_chunks = [xor_reslt[i:i+6] for i in range(0, 48, 6)]
        substituted_data = ''
        
        for i in range(8):
            row = int(six_bit_chunks[i][0] + six_bit_chunks[i][-1], 2)
            col = int(six_bit_chunks[i][1:-1], 2)
            s_box_value = s_boxes[i][row][col]
            substituted_data += format(s_box_value, '04b')
        # print(f"S-Box Substitution:  {substituted_data}")
            
        p_box_result = ''
        for i in p_box_table:
            p_box_result += substituted_data[i - 1]
        # print(f" P-Box Permutation:   {p_box_result}")
            
        new_righthalf = ''
        for i in range(32):
            new_righthalf += str(int(lefthalf[i]) ^ int(p_box_result[i]))
            
        lefthalf = righthalf
        righthalf = new_righthalf

    final_result = righthalf + lefthalf
    # print(f"\n process_block() Pre-FP 64-bit state (R16 + L16): {final_result}")
    
    fp_result = ''
    for i in range(64):
        fp_result += final_result[ip_inverse_table[i] - 1]
    # print(f" process_block() Final 64-bit block after FP:{fp_result}")
        
    return fp_result

def encrypt_message(plain_txt, secret_key):
    # print("\n========== STARTING ENCRYPTION ==========")
    rnd_keys = generate_round_keys(secret_key)
    padded_text = pad(plain_txt)
    
    ciphertext = ""
    
    for i in range(0, len(padded_text), 8):
        block = padded_text[i:i+8]
        # print(f"\n encrypt_message() Processing block string: {block}")
        binary_block = text_to_binary(block)
        cipher_binary_block = process_block(binary_block, rnd_keys)
        ciphertext += binary_to_text(cipher_binary_block)
        
    return ciphertext

def decrypt_message(ciphertext, secret_key):
    # print("\n========== STARTING DECRYPTION ==========")
    rnd_keys = generate_round_keys(secret_key)
    rnd_keys.reverse() 
    # print("decrypt_message() Round keys reversed for decryption.")
    
    full_deciphered_message = ""
    
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        # print(f"\n decrypt_message() Processing block string: {block}")
        binary_block = text_to_binary(block)
        deciphered_binary_block = process_block(binary_block, rnd_keys)
        full_deciphered_message += binary_to_text(deciphered_binary_block)
        
    clean_text = unpad(full_deciphered_message)
    return clean_text

if __name__ == "__main__":
    my_key = "Secret99"
    my_message = input("Enter a message to encrypt: ")
    encrypted = encrypt_message(my_message, my_key)
    print(f"\nENCRYPTED: {encrypted}")
    decrypted = decrypt_message(encrypted, my_key)
    print(f"\nDECRYPTED: {decrypted}")