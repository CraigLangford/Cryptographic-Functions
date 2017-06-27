import unittest

import sha256


class StrToBinTestCase(unittest.TestCase):
    """Tests the sha256._str_to_bin() function"""

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


class PreprocessingTestCase(unittest.TestCase):
    """Tests the sha256._preprocessing() function"""

    binary_data = '1010101010101010'

    def test_preprocessing_appends_a_1_to_binary_data(self):
        """Ensure a 1 is appended to the incoming data"""
        processed_data = sha256._preprocessing(self.binary_data)
        appended_1 = processed_data[len(self.binary_data)]
        self.assertEqual(appended_1, '1')

    def test_preprocessing_appends_length_to_end_of_binary_data(self):
        """Ensure the length of the binary data is appended in final 64 bits"""
        processed_data = sha256._preprocessing(self.binary_data)
        appended_64_bits = processed_data[-64:]
        self.assertEqual(int(appended_64_bits, 2), len(self.binary_data))

    def test_preprocessing_includes_correct_padding(self):
        """Ensure total length of binary data is 512 bits with 0s as padding"""
        processed_data = sha256._preprocessing(self.binary_data)
        self.assertEqual(len(processed_data) % 512, 0)
        padding_data = processed_data[len(self.binary_data) + 1:-64]
        number_of_0s = padding_data.count('0')
        self.assertEqual(len(padding_data), number_of_0s)


class ManipulationFunctionsTestCase(unittest.TestCase):
    """Tests the sha256 manipulation function work correctly"""

    def test_ROTR_rotates_string_data_to_the_right_n_units(self):
        """Tests sha256._ROTR() to ensure data rotates to the right"""
        data = '123456789'
        data_rotated_twice = '891234567'
        self.assertEqual(sha256._ROTR(data, 2), data_rotated_twice)
        self.assertEqual(sha256._ROTR(data, len(data)), data)

        excess_rotation = len(data) + 2
        expected_msg = "A string of length {} cannot be rotated {} positions"
        expected_msg = expected_msg.format(len(data), excess_rotation)
        with self.assertRaisesRegexp(ValueError, expected_msg):
            sha256._ROTR(data, excess_rotation)

    def test_SHR_shifts_string_data_to_the_right_n_units(self):
        """Tests sha256._SHR() to ensure data shifts to the right"""
        data = '123456789'
        data_shifted_twice = '001234567'

        self.assertEqual(sha256._SHR(data, 2), data_shifted_twice)
        self.assertEqual(sha256._SHR(data, len(data)), '0' * len(data))

        excess_rotation = len(data) + 2
        expected_msg = "A string of length {} cannot be shifted {} positions"
        expected_msg = expected_msg.format(len(data), excess_rotation)
        with self.assertRaisesRegexp(ValueError, expected_msg):
            sha256._SHR(data, excess_rotation)


if __name__ == '__main__':
    unittest.main()
