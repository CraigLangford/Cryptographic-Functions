

# Initial hash values, H(0), which are the first 32 bits of the fractional
# parts of the square roots of the first 8 prime numbers
H_0 = [
    '6a09e667',
    'bb67ae85',
    '3c6ef372',
    'a54ff53a',
    '510e527f',
    '9b05688c',
    '1f83d9ab',
    '5be0cd19',
]


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


# Manipulation functions
def _ROTR(x, n):
    """The rotate right (circular right shift) operation

    x is a w-bit word and n is an integer with 0 ≤ n < w,

    ROTR_n(x) = (x >> n) ∨ (x << w - n)
    """
    pass


def _SHR(x, n):
    """The right shift operation

     x is a w-bit word and n is an integer with 0 ≤ n < w

    SHR_n(x)=x >> n
    """
    pass


def _Ch(x, y, z):
    """Choose function: x chooses if value comes from y or z

    Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)
    """
    pass


def _Maj(x, y, z):
    """ Majority function: False when majority are False

    Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
    """
    pass


def _Epsilon_0(x):
    """First rotational mixing function

    ∑_256_0(x) = ROTR_2(x) ⊕ ROTR_13(x) ⊕ ROTR_22(x)
    """
    pass


def _Epsilon_1(x):
    """Second rotational mixing function

    ∑_256_1(x) = ROTR_6(x) ⊕ ROTR_11(x) ⊕ ROTR_25(x)
    """
    pass


def _sigma_0(x):
    """First rotational + shifting mixing function

    σ_256_0(x) = ROTR_7(x) ⊕ ROTR_18(x) ⊕ SHR_3(x)
    """
    pass


def _sigma_1(x):
    """Second rotational + shifting mixing function

    σ_256_1(x) = ROTR_17(x) ⊕ ROTR_19(x) ⊕ SHR_10(x)
    """
    pass
