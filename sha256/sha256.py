#!/usr/bin/env python

"""
sha256.py: Performs the SHA-256 algorithm on an incoming string by
converting the string to unicode points, converting the binary data to
have a length of a multiple of 512 bits and then processing data to
produce a hash digest.

This algorithm was based off of the link below from which the initial
values were taken:

http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
"""
from typing import List, Tuple

__author__ = "Craig Langford"
__credits__ = ["Craig Langford"]
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Craig Langford"
__email__ = "craigllangford@gmail.com"
__status__ = "Beta"


# Initial hash values, H(0), which are the first 32 bits of the
# fractional parts of the square roots of the first 8 prime numbers
H_HEX = """
        6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
        """
H = [[int(val, 16) for val in H_HEX.split()]]

K_HEX = """
        428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
        d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
        e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
        983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
        27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
        a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
        19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
        748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
        """
K = [int(val, 16) for val in K_HEX.split()]


def hex8(number):
    """Cuts number to 8 digit hex"""
    return number & 0xffffffff


def sha256(input_message: str, input_type: str) -> str:
    """Performs the SHA-256 algorithm on the incoming string.

    This is performed by converting the string to a binary string via
    unicode positions on which the permutations are performed. The
    result is then converted to a hexidecimal string and returned from
    the function

    args:
        input_message:
            Incoming string to be converted to SHA-256 digest
        input_type:
            Either 'string' or 'int'. If string the data is converted
            via unicode. Otherwise it is converted to an integer
            directly

    output args:
        sha_256_digest:
            The resulting hash from data string in hexidecimal format
    """
    if input_type == 'string':
        binary_data = str_to_bin(input_message)
    elif input_type == 'int':
        binary_data = int_to_bin(input_message)
    M = preprocess_data(binary_data)
    for i, M_i in enumerate(M):
        a, b, c, d, e, f, g, h = H[i]

        W = list(M_i)
        for t in range(64):
            if t >= 16:
                new_W = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16]
                W.append(hex8(new_W))
            T1 = hex8(h + Epsilon_1(e) + Ch(e, f, g) + K[t] + W[t])
            T2 = hex8(Epsilon_0(a) + Maj(a, b, c))
            a, b, c, d, e, f, g, h = hex8(T1 + T2), a, b, c, hex8(d + T1), e, f, g

        H.append([
            hex8(a + H[i][0]), hex8(b + H[i][1]), hex8(c + H[i][2]), hex8(d + H[i][3]),
            hex8(e + H[i][4]), hex8(f + H[i][5]), hex8(g + H[i][6]), hex8(h + H[i][7]),
        ])

    return ' '.join(['{:08x}'.format(val).upper() for val in H[-1]])


def str_to_bin(data_string):
    """Returns the binary representation of a string

    Uses unicode (or ASCII) representation of the string values

    args:
        data_string (str): Incoming string in unicode/ASCII format

    return args:
        binary_data (str): Binary representation of the string
    """
    unicode_points = [ord(char) for char in data_string]
    binary_values = ['{0:08b}'.format(point) for point in unicode_points]
    return ''.join(binary_values)


def int_to_bin(data_string: str) -> str:
    """Returns the binary representation of a integer string

    First, casts the string to int and calculates from there

    args:
        data_string: Incoming string composed of values from 1 to 9

    return args:
        binary_data: Binary representation of the integer
    """
    return bin(int(data_string))[2:]


def preprocess_data(binary_data: str) -> List[Tuple[int]]:
    """Prepares the binary data for the SHA-256 processing

    Preprocessing is performed by achieving the following 3 properties
    1. The string is converted to binary data
    2. A 1 is appended to the binary data
    3. A 64 bit representation of the length of the binary data is
       appended to the data
    4. 1 and 2 are separated by 0s until a total binary_data length of
       a multiple of 512 bits is achieved
    5. Blocks of 512 bits are converted to 16 ints and returned as a
       list

    args:
        input_message (str): Incoming binary string to be preprocessed

    return args:
        preprocessed_data (list(tuples(int,),)):
            Data ready for SHA-256 processing
    """
    data_length = '{0:064b}'.format(len(binary_data))
    padding = '0' * (512 - (len(binary_data) + 1 + 64) % 512)
    binary_string = binary_data + '1' + padding + data_length
    processed_values = [int(binary_string[i:i + 32], 2)
                        for i in range(0, len(binary_string), 32)]
    return [tuple(processed_values[i:i + 16])
            for i in range(0, len(processed_values), 16)]


def ROTR(x, n):
    """The rotate right (circular right shift) operation

    x is a w-bit word (32 bits in sha256) and n is an integer with
    0 ≤ n < w,

    ROTR_n(x) = (x >> n) ∨ (x << w - n)
    """
    return hex8((x >> n) | (x << (32 - n)))


def SHR(x, n):
    """The right shift operation

    x is a w-bit word and n is an integer with 0 ≤ n < w

    SHR_n(x) = x >> n
    """
    return x >> n


def Ch(x, y, z):
    """Choose function

    x chooses if value comes from y or z 1 means the bit comes from y
    and 0 means the bit comes from z

    Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)
    """
    return (x & y) ^ ((x ^ 0xffffffff) & z)


def Maj(x, y, z):
    """ Majority function: False when majority are False

    Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
    """
    return (x & y) ^ (x & z) ^ (y & z)


def Epsilon_0(x):
    """First rotational mixing function

    ∑_256_0(x) = ROTR_2(x) ⊕ ROTR_13(x) ⊕ ROTR_22(x)
    """
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)


def Epsilon_1(x):
    """Second rotational mixing function

    ∑_256_1(x) = ROTR_6(x) ⊕ ROTR_11(x) ⊕ ROTR_25(x)
    """
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)


def sigma_0(x):
    """First rotational + shifting mixing function

    σ_256_0(x) = ROTR_7(x) ⊕ ROTR_18(x) ⊕ SHR_3(x)
    """
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)


def sigma_1(x):
    """Second rotational + shifting mixing function

    σ_256_1(x) = ROTR_17(x) ⊕ ROTR_19(x) ⊕ SHR_10(x)
    """
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)


if __name__ == '__main__':
    input_types = {'1': 'string', '2': 'int'}
    input_types_list = [f'[{n}] {input_type}' for n, input_type in input_types.items()]
    print('Input types, please input number\n{}'.format('\n'.join(input_types_list)))
    input_type = None
    while input_type not in input_types.keys():
        input_type = input('Input type: ')
    input_str = input('Input {}: '.format(input_types[input_type]))
    sha256_digest = sha256(input_str, input_types[input_type])
    print("SHA-256 digest: {}".format(sha256_digest))
