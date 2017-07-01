import unittest

import sha256


"""
Examples are from
http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf
"""
NSA_EXAMPLE_1 = "abc"
NSA_EXAMPLE_1_PREPROCESSED = (
    "61626380 00000000 00000000 00000000 00000000 00000000 00000000 00000000 "
    "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000018"
)
NSA_EXAMPLE_1_H_0 = (
    "5D6AEBCD 6A09E667 BB67AE85 3C6EF372 FA2A4622 510E527F 9B05688C 1F83D9AB"
)
NSA_EXAMPLE_1_DIGEST = (
    "BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD"
)

NSA_EXAMPLE_2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
NSA_EXAMPLE_2_PREPROCESSED = (
    "61626364 62636465 63646566 64656667 65666768 66676869 6768696A 68696A6B "
    "696A6B6C 6A6B6C6D 6B6C6D6E 6C6D6E6F 6D6E6F70 6E6F7071 80000000 00000000 "
    "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 "
    "00000000 00000000 00000000 00000000 00000000 00000000 00000000 000001C0"
)
NSA_EXAMPLE_2_H_0 = (
    "5D6AEBB1 6A09E667 BB67AE85 3C6EF372 FA2A4606 510E527F 9B05688C 1F83D9AB"
)
NSA_EXAMPLE_2_DIGEST = (
    "248D6A61 D20638B8 E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1"
)


class Sha256TestCase(unittest.TestCase):
    """Tests the sha256.sha256() function based on results from the original
       NSA examples
    """


    def test_abc_is_processed_same_as_NSA_example(self):
        """Ensure abc produces the same output as from the NSA paper"""
        input_message = "abc"
        output_hash = sha256.sha256(input_message)


class ConversionTestCase(unittest.TestCase):
    """Tests the sha256 conversion functions function"""

    def test_str_to_bin_takes_str(self):
        """Ensure _str_to_bin takes a string to process"""
        sha256._str_to_bin('abc')

    def test_str_to_bin_returns_binary(self):
        """Ensure _str_to_bin returns binary representation"""
        binary_representation = sha256._str_to_bin('abc')
        count_1s = binary_representation.count('1')
        count_0s = binary_representation.count('0')
        self.assertEqual(len(binary_representation), count_1s + count_0s)

    def test_correct_binary_length_returned(self):
        """Ensure _str_to_bin returns correct length of binary values"""
        self.assertEqual(len(sha256._str_to_bin('abc')), 3 * 8)

    def test_any_unicode_handled(self):
        """Ensure _str_to_bin can handle any unicode value"""
        unicode_10084 = '❤'
        binary_representation = sha256._str_to_bin(unicode_10084)
        unicode_10084_binary = bin(10084)[2:]
        self.assertEqual(binary_representation, unicode_10084_binary)

    def test_hex_to_bin_takes_hex_string_and_converts_it_to_bin_string(self):
        """Ensure the sha256._hex_to_bin() function takes a hex and returns its
           coordinating binary format
        """
        hex_value = '4d2'
        expected_bin = '010011010010'
        self.assertEqual(sha256._hex_to_bin(hex_value), expected_bin)

    def test_bin_to_hex_takes_bin_string_and_converts_it_to_hex_string(self):
        """Ensure the sha256._bin_to_hex() function takes a bin and returns its
           coordinating hexidecimal format
        """
        bin_value = '010011010010'
        expected_hex = '4d2'
        self.assertEqual(sha256._bin_to_hex(bin_value), expected_hex)


class PreprocessingTestCase(unittest.TestCase):
    """Tests the sha256._preprocessing() function"""

    def test_preprocessing_can_handle_less_than_512_bits(self):
        """Ensure preprocessing takes a unicode string and converts it to a
           list of tuples containing the desired ints
        """
        input_message = NSA_EXAMPLE_1
        expected_result = [
            tuple(int(val, 16) for val in NSA_EXAMPLE_1_PREPROCESSED.split())
        ]
        self.assertEqual(sha256._preprocessing(input_message), expected_result)

    def test_preprocessing_can_handle_more_than_512_bits(self):
        """Ensure preprocessing takes a unicode string and converts it to a
           list of tuples containing the desired ints
        """
        input_string = NSA_EXAMPLE_2
        expected_result = [
            tuple(int(val, 16)
                  for val in NSA_EXAMPLE_2_PREPROCESSED.split()[:16]),
            tuple(int(val, 16)
                  for val in NSA_EXAMPLE_2_PREPROCESSED.split()[16:]),
        ]
        self.assertEqual(sha256._preprocessing(input_string), expected_result)


class ManipulationFunctionsTestCase(unittest.TestCase):
    """Tests the sha256 manipulation function work correctly"""

    def test_add_returns_added_binary_strings(self):
        """Tests sha256._add() to ensure x + y module length is returned"""
        self.assertEqual(sha256._add('1', '1'), '0')
        self.assertEqual(sha256._add('11', '11'), '10')
        self.assertEqual(sha256._add('1111', '1100'), '1011')
        val_1 = bin(123456789)[2:]
        val_2 = bin(123456789)[2:]
        val_3 = bin(123456789)[2:]
        total = bin(3 * 123456789 % (2 ** 32))[2:]
        total = total[len(total) - len(val_1):]
        self.assertEqual(sha256._add(val_1, val_2, val_3), total)

    def test_XOR_returns_exclusive_or_of_two_strings(self):
        """Tests sha256._XOR() to ensure exclusive or is returned"""
        string_x = '1100'
        string_y = '1010'
        expected = '0110'
        self.assertEqual(sha256._XOR(string_x, string_y), expected)

    def test_ROTR_rotates_string_data_to_the_right_n_units(self):
        """Tests sha256._ROTR() to ensure data rotates to the right"""
        data = '123456789'
        data_rotated_twice = '891234567'
        self.assertEqual(sha256._ROTR(data, 2), data_rotated_twice)
        self.assertEqual(sha256._ROTR(data, len(data)), data)

        excess_rotation = len(data) + 2
        expected_msg = "A string of length {} cannot be rotated {} positions"
        expected_msg = expected_msg.format(len(data), excess_rotation)

    def test_SHR_shifts_string_data_to_the_right_n_units(self):
        """Tests sha256._SHR() to ensure data shifts to the right"""
        data = '123456789'
        data_shifted_twice = '001234567'

        self.assertEqual(sha256._SHR(data, 2), data_shifted_twice)
        self.assertEqual(sha256._SHR(data, len(data)), '0' * len(data))

        excess_rotation = len(data) + 2
        expected_msg = "A string of length {} cannot be shifted {} positions"
        expected_msg = expected_msg.format(len(data), excess_rotation)

    def test_Ch_returns_correct_string_permutation(self):
        """Tests sha256._Ch() to ensure string x chooses vals from y and z"""
        string_x = '101'
        string_y = '010'
        string_z = '101'

        self.assertEqual(
            sha256._Ch(string_x, string_y, string_z),
            string_z[0] + string_y[1] + string_z[2]
        )
        self.assertEqual(sha256._Ch('000', string_y, string_z), string_y)
        self.assertEqual(sha256._Ch('111', string_y, string_z), string_z)

    def test_Maj_returns_correct_string_permutation(self):
        """Tests sha256._Maj() the majority of bits between x, y and z are
           returned
        """
        majority_str = string_x = string_y = '101'
        string_z = '010'

        self.assertEqual(
            sha256._Maj(string_x, string_y, string_z),
            majority_str
        )

    def test_Epsilon_0_returns_returns_correct_values(self):
        """Testes sha256._Epsilon_0() to ensure single string is mixed"""
        string_x = '1' + '0' * 25
        mixed = sha256._Epsilon_0(string_x)
        self.assertEqual(mixed[0], '0')
        self.assertEqual(mixed[2], '1')
        self.assertEqual(mixed[13], '1')
        self.assertEqual(mixed[22], '1')
        self.assertEqual(mixed.count('0'), len(string_x) - 3)

    def test_Epsilon_1_returns_returns_correct_values(self):
        """Testes sha256._Epsilon_1() to ensure single string is mixed"""
        string_x = '1' + '0' * 25
        mixed = sha256._Epsilon_1(string_x)
        self.assertEqual(mixed[0], '0')
        self.assertEqual(mixed[6], '1')
        self.assertEqual(mixed[11], '1')
        self.assertEqual(mixed[25], '1')
        self.assertEqual(mixed.count('0'), len(string_x) - 3)

    def test_sigma_0_returns_returns_correct_values(self):
        """Testes sha256._sigma_0() to ensure single string is mixed"""
        string_x = '1' + '0' * 25 + '1'
        mixed = sha256._sigma_0(string_x)
        self.assertEqual(mixed[0], '0')
        self.assertEqual(mixed[2], '0')
        self.assertEqual(mixed[3], '1')
        self.assertEqual(mixed[6], '1')
        self.assertEqual(mixed[7], '1')
        self.assertEqual(mixed[17], '1')
        self.assertEqual(mixed[18], '1')
        self.assertEqual(mixed.count('0'), len(string_x) - (2 * 3 - 1))

    def test_sigma_1_returns_returns_correct_values(self):
        """Testes sha256._sigma_1() to ensure single string is mixed"""
        string_x = '1' + '0' * 25 + '1'
        mixed = sha256._sigma_1(string_x)
        self.assertEqual(mixed[0], '0')
        self.assertEqual(mixed[16], '1')
        self.assertEqual(mixed[17], '1')
        self.assertEqual(mixed[18], '1')
        self.assertEqual(mixed[19], '1')
        self.assertEqual(mixed[9], '0')
        self.assertEqual(mixed[10], '1')
        self.assertEqual(mixed.count('0'), len(string_x) - (2 * 3 - 1))


if __name__ == '__main__':
    unittest.main()
