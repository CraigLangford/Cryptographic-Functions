

# Initial hash values, H(0), which are the first 32 bits of the fractional
# parts of the square roots of the first 8 prime numbers
H = [(
    '6a09e667',
    'bb67ae85',
    '3c6ef372',
    'a54ff53a',
    '510e527f',
    '9b05688c',
    '1f83d9ab',
    '5be0cd19',
)]


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
    W = []
    for t in range(63):
        if t <= 15:
            W.append(M[t])
        else:
            initial_result = _add_modulo(_sigma_1(W[t-2]), _sigma_0(W[t-15]))
            W.append(_add_modulo(initial_result, W[t-16]))
        a, b, c, d, e, f, g, h = (_hex_to_bin(val) for val in H[t])


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
def _add_modulo(x, y):
    """Takes two binary strings and adds them together returning the same
       length string
    """
    remainder = 0
    added_str = ''
    for _x, _y in zip(x[::-1], y[::-1]):
        total = int(_x) + int(_y) + remainder
        out_bit = total % 2
        remainder = int((total - out_bit) / 2)
        added_str = ''.join([str(out_bit), added_str])
    return added_str


def _XOR(x, y):
    """Takes two strings and returns their exclusive or values

    eg. 1 ⊕ 1 = 0
        1 ⊕ 0 = 1
        0 ⊕ 1 = 1
        0 ⊕ 0 = 0
    """
    return ''.join('1' if _x != _y else '0' for _x, _y in zip(x, y))


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
    initial_result = _XOR(_ROTR(x, 2), _ROTR(x, 13))
    return _XOR(initial_result, _ROTR(x, 22))


def _Epsilon_1(x):
    """Second rotational mixing function

    ∑_256_1(x) = ROTR_6(x) ⊕ ROTR_11(x) ⊕ ROTR_25(x)
    """
    initial_result = _XOR(_ROTR(x, 6), _ROTR(x, 11))
    return _XOR(initial_result, _ROTR(x, 25))


def _sigma_0(x):
    """First rotational + shifting mixing function

    σ_256_0(x) = ROTR_7(x) ⊕ ROTR_18(x) ⊕ SHR_3(x)
    """
    initial_result = _XOR(_ROTR(x, 7), _ROTR(x, 18))
    return _XOR(initial_result, _SHR(x, 3))


def _sigma_1(x):
    """Second rotational + shifting mixing function

    σ_256_1(x) = ROTR_17(x) ⊕ ROTR_19(x) ⊕ SHR_10(x)
    """
    initial_result = _XOR(_ROTR(x, 17), _ROTR(x, 19))
    return _XOR(initial_result, _SHR(x, 10))
