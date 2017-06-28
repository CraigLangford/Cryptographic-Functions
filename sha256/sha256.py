

# Initial hash values, H(0), which are the first 32 bits of the fractional
# parts of the square roots of the first 8 prime numbers
H = ["""
     6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
     """.split()]

K = """
    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
    27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
    a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
    19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
    748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
    """.split()


def sha256(data_string):
    """Performs the SHA-256 algorithm on the incoming string. This is performed
       by conberting the string to a binary string via unicode positions on
       which the permutations are performed. The result is then converted to a
       hexidecimal string and returned from the function

    args:
        data_string (str): Incoming string to be converted to SHA-256 hash

    output args:
        sha_256_hash (str): The resulting hash from the data_string in
                            hexidecimal format
    """
    binary_string = _str_to_bin(data_string)
    preprocessed_string = _preprocessing(binary_string)
    M = [preprocessed_string[32 * i:32 * (i + 1)] for i in range(16)]

    W = M
    for t in range(16, 63):
        W.append(_add(_sigma_1(W[t-2]), W[t-7], _sigma_0(W[t-15]), W[t-16]))

    a, b, c, d, e, f, g, h = (_hex_to_bin(val) for val in H[0])

    #  print('\n')

    for t in range(63):
        T_1 = _add(h, _Epsilon_1(e), _Ch(e, f, g), _hex_to_bin(K[t]), W[t])
        T_2 = _add(_Epsilon_0(a), _Maj(a, b, c))

        h, g, f, e, d, c, b, a = g, f, e, _add(d, T_1), c, b, a, _add(T_1, T_2)

        #  print(t, [_bin_to_hex(val) for val in [a, b, c, d, e, f, g, h]])

    H.append([
        _bin_to_hex(_add(a, _hex_to_bin(H[0][0]))),
        _bin_to_hex(_add(b, _hex_to_bin(H[0][1]))),
        _bin_to_hex(_add(c, _hex_to_bin(H[0][2]))),
        _bin_to_hex(_add(d, _hex_to_bin(H[0][3]))),
        _bin_to_hex(_add(e, _hex_to_bin(H[0][4]))),
        _bin_to_hex(_add(f, _hex_to_bin(H[0][5]))),
        _bin_to_hex(_add(g, _hex_to_bin(H[0][6]))),
        _bin_to_hex(_add(h, _hex_to_bin(H[0][7]))),
    ])
    return H[1]


def _preprocessing(binary_data):
    """Prepares the binary data for the SHA-256 processing

    Preprocessing is performed by achieving the following 3 properties
    1. A 1 is appended to the binary data
    2. A 64 bit representation of the length of the binary data is
       appended to the data
    3. 1 and 2 are separated by 0s until a total binary_data length of
       a multiple of 512 bits is achieved

    args:
        binary_data (str): Incoming binary string to be preprocessed

    return args:
        preprocessed_data (str): Data ready for SHA-256 processing
    """
    data_length = '{0:064b}'.format(len(binary_data))
    padding = '0' * (512 - (len(binary_data) + 1 + 64) % 512)
    return binary_data + '1' + padding + data_length


# Conversion functions
def _str_to_bin(data_string):
    """Returns the binary representation of a string
    using unicode representation of the str values

    args:
        data_string (str): Incoming string to be hashed

    return args:
        binary_data (str): Binary representation of the
                           string
    """
    unicode_points = [ord(char) for char in data_string]
    binary_values = ['{0:08b}'.format(point) for point in unicode_points]
    binary_data = ''.join(binary_values)
    return binary_data


def _hex_to_bin(hex_string):
    """Returns the binary representation of a hexidecimal string"""
    binary_values = ['{0:04b}'.format(int(point, 16)) for point in hex_string]
    return ''.join(binary_values)


def _bin_to_hex(bin_string):
    """Returns the hexidecimal representation of a binary string"""
    bin_vals = [bin_string[pos * 4:(pos + 1) * 4]
                for pos in range(int(len(bin_string) / 4))]
    hex_values = [hex(int(val, 2))[2:] for val in bin_vals]
    return ''.join(hex_values)


# Manipulation functions
def _add(*binary_strings):
    """Takes any number of binary strings and adds them together to find a
       final sum
    """
    remainder = 0
    added_str = ''
    for vals in list(zip(*binary_strings))[::-1]:
        total = sum(int(val) for val in vals) + remainder
        new_bit = total % 2
        remainder = int((total - new_bit) / 2)
        added_str = str(new_bit) + added_str
    return added_str


def _XOR(*args):
    """Takes any number of strings and outputs their exclusive or result

    eg. 1 ⊕ 1 = 0
        1 ⊕ 0 = 1
        0 ⊕ 1 = 1
        0 ⊕ 0 = 0
    """
    return ''.join('1' if vals.count('1') % 2 == 1 else '0'
                   for vals in zip(*args))


def _ROTR(x, n):
    """The rotate right (circular right shift) operation

    x is a w-bit word and n is an integer with 0 ≤ n < w,

    ROTR_n(x) = (x >> n) ∨ (x << w - n)

    args:
        x (str): String being rotated
        n (int): Number of positions string is being rotated

    return args:
        rotated_str (str): Rotated string
    """
    if n > len(x):
        error_msg = "A string of length {} cannot be rotated {} positions"
        raise ValueError(error_msg.format(len(x), n))
    return x[-n:] + x[:-n]


def _SHR(x, n):
    """The right shift operation

     x is a w-bit word and n is an integer with 0 ≤ n < w

    SHR_n(x)=x >> n
    """
    if n > len(x):
        error_msg = "A string of length {} cannot be shifted {} positions"
        raise ValueError(error_msg.format(len(x), n))
    return '0' * n + x[:-n]


def _Ch(x, y, z):
    """Choose function: x chooses if value comes from y or z

    Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)
    """
    return ''.join(_y if _x == '0' else _z for _x, _y, _z in zip(x, y, z))


def _Maj(x, y, z):
    """ Majority function: False when majority are False

    Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
    """
    return ''.join('1' if bits.count('1') >= 2 else '0'
                   for bits in zip(x, y, z))


def _Epsilon_0(x):
    """First rotational mixing function

    ∑_256_0(x) = ROTR_2(x) ⊕ ROTR_13(x) ⊕ ROTR_22(x)
    """
    return _XOR(_ROTR(x, 2), _ROTR(x, 13), _ROTR(x, 22))


def _Epsilon_1(x):
    """Second rotational mixing function

    ∑_256_1(x) = ROTR_6(x) ⊕ ROTR_11(x) ⊕ ROTR_25(x)
    """
    return _XOR(_ROTR(x, 6), _ROTR(x, 11), _ROTR(x, 25))


def _sigma_0(x):
    """First rotational + shifting mixing function

    σ_256_0(x) = ROTR_7(x) ⊕ ROTR_18(x) ⊕ SHR_3(x)
    """
    return _XOR(_ROTR(x, 7), _ROTR(x, 18), _SHR(x, 3))


def _sigma_1(x):
    """Second rotational + shifting mixing function

    σ_256_1(x) = ROTR_17(x) ⊕ ROTR_19(x) ⊕ SHR_10(x)
    """
    return _XOR(_ROTR(x, 17), _ROTR(x, 19), _SHR(x, 10))
