import tables as t

def string_to_bit_array(text):#Convert a string into a list of bits
    array = list()
    for char in text:
        binval = binvalue(char, 8)#Get the char value on one byte
        array.extend([int(x) for x in list(binval)]) #Add the bits to the final list
    binary_text = ''.join(y for y in [''.join([str(x) for x in _bytes]) for _bytes in nsplit(array,8)])
    return binary_text

def bit_array_to_string(array): #Recreate the string from the bit array
    res = ''.join([chr(int(y,2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in  nsplit(array,8)]])
    return res

def binvalue(val, bitsize): #Return the binary value as a string of the given size
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "binary value larger than the expected size"
    while len(binval) < bitsize:
        binval = "0"+binval #Add as many 0 as needed to get the wanted size
    return binval

def nsplit(s, n): # Split a list into sublists of size "n"
    return [s[k:k+n] for k in range(0, len(s), n)]

# Binary to hexadecimal conversion
def bin2hex(s):
    mp = {"0000" : '0',
          "0001" : '1',
          "0010" : '2',
          "0011" : '3',
          "0100" : '4',
          "0101" : '5',
          "0110" : '6',
          "0111" : '7',
          "1000" : '8',
          "1001" : '9',
          "1010" : 'A',
          "1011" : 'B',
          "1100" : 'C',
          "1101" : 'D',
          "1110" : 'E',
          "1111" : 'F' }
    hex = ""
    for i in range(0,len(s),4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i+1]
        ch = ch + s[i+2]
        ch = ch + s[i+3]
        hex = hex + mp[ch]
    return hex

# Binary to decimal conversion
def bin2dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2,i)
        binary = binary//10
        i += 1
    return decimal

# Decimal to binary conversion
def dec2bin(num):
    res = bin(num).replace("0b","")
    if(len(res)%4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4* (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res
# print(dec2bin(14))

# Permute function to rearrange the bits
def permute(k, arr, n):
    permutaion = ""
    for i in range(0, n):
        permutaion = permutaion + k[arr[i] - 1]
    return permutaion

# Shifting the bits towards left by n-th shifts
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1,len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

# Calculating XOR of two strings of binary number a and b
def xor(a,b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

def encrypt(pt, rkb, rk):
    pt = string_to_bit_array(pt)

    # Initial Permutation
    pt = permute(pt, t.initial_perm , 64)
    print(f"After inital permutation: {pt}")

    # Splitting
    left = pt[0:32]
    right = pt[32:64]
    for i in range(0, 16):
        #  Expansion E-box: Expanding the 32 bits data into 48 bits
        right_expanded = permute(right, t.exp_e, 48)

        # XOR RoundKey[i] and right_expanded
        xor_x = xor(right_expanded, rkb[i])

        # S-boxex: substituting the value from s-box table by calculating row and column
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = t.sbox[j][row][col]
            sbox_str = sbox_str + dec2bin(val)

        # Straight P-box: After substituting rearranging the bits
        sbox_str = permute(sbox_str, t.per, 32)

        # XOR left and sbox_str
        result = xor(left, sbox_str)
        left = result

        # Swapper
        if(i != 15):
            left, right = right, left
        print(f"Round {i + 1}:    L{i + 1}: {bin2hex(left)}    R{i + 1}:{bin2hex(right)}    K{i + 1}:{rk[i]}")

    # Combination
    combine = left + right

    # Final permutaion: final rearranging of bits to get cipher text
    cipher_text = permute(combine, t.final_perm, 64)
    return cipher_text

pt = input("Enter plaintext: ")
key = input("Enter key: ")

# Key generation
# --hex to binary
key = string_to_bit_array(key)

if len(key) < 64:
    raise "Key Should be 8 bytes long"
elif len(key) > 64:
    key = key[:64] # If key size is above 8bytes, cut to be 8bytes long

# Getting 56 bit key from 64 bit using the parity bits
key = permute(key, t.keyp, 56)

# Splitting
left = key[0:28]    # rkb for RoundKeys in binary
right = key[28:56]  # rk for RoundKeys in hexadecimal

rkb = []
rk  = []
for i in range(0, 16):
    # Shifting the bits by nth shifts by checking from shift table
    left = shift_left(left, t.shift_table[i])
    right = shift_left(right, t.shift_table[i])

    # Combination of left and right string
    combine_str = left + right

    # Compression of key from 56 to 48 bits
    round_key = permute(combine_str, t.key_comp, 48)

    rkb.append(round_key)
    rk.append(bin2hex(round_key))

print("ENCRYPTION")
cipher_text = bit_array_to_string(encrypt(pt, rkb, rk))
print(f"Cipher Text in binary: {string_to_bit_array(cipher_text)}")
print(f"Cipher Text: {cipher_text}")

print("DECRYPTION")
rkb_rev = rkb[::-1]
rk_rev = rk[::-1]
text = bit_array_to_string(encrypt(cipher_text, rkb_rev, rk_rev))
print(f"Plain Text in binary: {string_to_bit_array(text)}")
print(f"Plan Text: {text}")
