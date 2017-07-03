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
NSA_EXAMPLE_2_DIGEST = (
    "248D6A61 D20638B8 E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1"
)


class Sha256TestCase(unittest.TestCase):
    """Tests the sha256.sha256() function based on results from the original
       NSA examples
    """

    def test_NSA_example_1_is_processed_correctly(self):
        """Ensure abc produces the same output as from the NSA paper"""
        input_message = NSA_EXAMPLE_1
        output_digest = sha256.sha256(input_message)
        self.assertEqual(output_digest, NSA_EXAMPLE_1_DIGEST)

    def test_NSA_example_0_is_processed_correctly(self):
        """Ensure abc produces the same output as from the NSA paper"""
        input_message = NSA_EXAMPLE_2
        output_digest = sha256.sha256(input_message)
        self.assertEqual(output_digest, NSA_EXAMPLE_2_DIGEST)


class ConversionTestCase(unittest.TestCase):
    """Tests the sha256 conversion functions function"""

    def test_str_to_bin_takes_str(self):
        """Ensure sha256.str_to_bin() takes a string to process"""
        sha256.str_to_bin('abc')

    def test_str_to_bin_returns_binary(self):
        """Ensure sha256.str_to_bin() returns binary representation"""
        binary_representation = sha256.str_to_bin('abc')
        count_1s = binary_representation.count('1')
        count_0s = binary_representation.count('0')
        self.assertEqual(len(binary_representation), count_1s + count_0s)

    def test_correct_binary_length_returned(self):
        """Ensure sha256.str_to_bin() returns correct length values"""
        self.assertEqual(len(sha256.str_to_bin('abc')), 3 * 8)

    def test_any_unicode_handled(self):
        """Ensure sha256.str_to_bin() can handle any unicode value"""
        unicode_10084 = '❤'
        binary_representation = sha256.str_to_bin(unicode_10084)
        unicode_10084_binary = bin(10084)[2:]
        self.assertEqual(binary_representation, unicode_10084_binary)


class PreprocessingTestCase(unittest.TestCase):
    """Tests the sha256.preprocess_data() function"""

    def test_preprocess_data_can_handle_less_than_512_bits(self):
        """Ensure preprocess_data takes a unicode string and converts it to a
           list of tuples containing the desired ints
        """
        input_message = NSA_EXAMPLE_1
        binary_data = sha256.str_to_bin(input_message)
        expected_result = [
            tuple(int(val, 16) for val in NSA_EXAMPLE_1_PREPROCESSED.split())
        ]
        self.assertEqual(
            sha256.preprocess_data(binary_data),
            expected_result
        )

    def test_preprocess_data_can_handle_more_than_512_bits(self):
        """Ensure preprocess_data takes a unicode string and converts it to a
           list of tuples containing the desired ints
        """
        input_message = NSA_EXAMPLE_2
        binary_data = sha256.str_to_bin(input_message)
        expected_result = [
            tuple(int(val, 16)
                  for val in NSA_EXAMPLE_2_PREPROCESSED.split()[:16]),
            tuple(int(val, 16)
                  for val in NSA_EXAMPLE_2_PREPROCESSED.split()[16:]),
        ]
        self.assertEqual(sha256.preprocess_data(binary_data), expected_result)


class ManipulationFunctionsTestCase(unittest.TestCase):
    """Tests the sha256 manipulation function work correctly"""

    def test_ROTR_rotates_int_data_to_the_right_n_units(self):
        """Tests sha256.ROTR() to ensure data rotates to the right"""
        data = 0b10000000000000000000000000000001
        data_rotated_twice = 0b01100000000000000000000000000000
        self.assertEqual(sha256.ROTR(data, 2), data_rotated_twice)

    def test_SHR_shifts_string_data_to_the_right_n_units(self):
        """Tests sha256.SHR() to ensure data shifts to the right"""
        data = 0b10000000000000000000000000000001
        data_shifted_twice = 0b00100000000000000000000000000000
        self.assertEqual(sha256.SHR(data, 2), data_shifted_twice)

    def test_Ch_returns_correct_string_permutation(self):
        """Tests sha256.Ch() to ensure string x chooses vals from y and z"""
        val_x = 0b11111111111111110000000000000000
        val_y = 0b11111111111111110000000000000000
        val_z = 0b00000000000000001111111111111111
        expected = 0b11111111111111111111111111111111
        self.assertEqual(sha256.Ch(val_x, val_y, val_z), expected)

        all_ones = 0b11111111111111111111111111111111
        self.assertEqual(sha256.Ch(all_ones, val_y, val_z), val_y)

        all_zeros = 0b00000000000000000000000000000000
        self.assertEqual(sha256.Ch(all_zeros, val_y, val_z), val_z)

    def test_Maj_returns_correct_string_permutation(self):
        """Tests sha256._Maj() the majority of bits between x, y and z are
           returned
        """
        majority_val = val_x = val_y = 0b101
        val_z = 0b010

        self.assertEqual(sha256.Maj(val_x, val_y, val_z), majority_val)

    def test_Epsilon_0_returns_returns_correct_values(self):
        """Testes sha256.Epsilon_0() to ensure single string is mixed"""
        string_x = 0b10000000000000000000000000000001
        expected = 0b01100000000011000000011000000000
        self.assertEqual(sha256.Epsilon_0(string_x), expected)

    def test_Epsilon_1_returns_returns_correct_values(self):
        """Testes sha256.Epsilon_1() to ensure single string is mixed"""
        string_x = 0b10000000000000000000000000000001
        expected = 0b00000110001100000000000011000000
        self.assertEqual(sha256.Epsilon_1(string_x), expected)

    def test_sigma_0_returns_returns_correct_values(self):
        """Testes sha256._sigma_0() to ensure single string is mixed"""
        string_x = 0b10000000000000000000000000000001
        expected = 0b00010011000000000110000000000000
        self.assertEqual(sha256.sigma_0(string_x), expected)

    def test_sigma_1_returns_returns_correct_values(self):
        """Testes sha256._sigma_1() to ensure single string is mixed"""
        string_x = 0b10000000000000000000000000000001
        expected = 0b00000000001000001111000000000000
        self.assertEqual(sha256.sigma_1(string_x), expected)


if __name__ == '__main__':
    unittest.main()
