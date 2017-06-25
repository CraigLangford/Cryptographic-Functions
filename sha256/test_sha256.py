import unittest

from sha256 import _preprocessing, _str_to_bin


class StrToBinTestCase(unittest.TestCase):
    """Tests the sha256._str_to_bin() function"""

    def test_str_to_bin_takes_str(self):
        """Ensure _str_to_bin takes a string to process"""
        _str_to_bin('abc')

    def test_str_to_bin_returns_binary(self):
        """Ensure _str_to_bin returns binary representation"""
        binary_representation = _str_to_bin('abc')
        count_1s = binary_representation.count('1')
        count_0s = binary_representation.count('0')
        self.assertEqual(len(binary_representation), count_1s + count_0s)

    def test_correct_binary_length_returned(self):
        """Ensure _str_to_bin returns correct length of binary values"""
        self.assertEqual(len(_str_to_bin('abc')), 3 * 8)

    def test_any_unicode_handled(self):
        """Ensure _str_to_bin can handle any unicode value"""
        unicode_10084 = '❤'
        binary_representation = _str_to_bin(unicode_10084)
        unicode_10084_binary = bin(10084)[2:]
        self.assertEqual(binary_representation, unicode_10084_binary)


class PreprocessingTestCase(unittest.TestCase):
    """Tests the sha256._preprocessing() function"""

    binary_data = '1010101010101010'

    def test_preprocessing_appends_a_1_to_binary_data(self):
        """Ensure a 1 is appended to the incoming data"""
        processed_data = _preprocessing(self.binary_data)
        appended_1 = processed_data[len(self.binary_data)]
        self.assertEqual(appended_1, '1')

    def test_preprocessing_appends_length_to_end_of_binary_data(self):
        """Ensure the length of the binary data is appended in final 64 bits"""
        processed_data = _preprocessing(self.binary_data)
        appended_64_bits = processed_data[-64:]
        self.assertEqual(int(appended_64_bits, 2), len(self.binary_data))

    def test_preprocessing_includes_correct_padding(self):
        """Ensure total length of binary data is 512 bits with 0s as padding"""
        processed_data = _preprocessing(self.binary_data)
        self.assertEqual(len(processed_data) % 512, 0)
        padding_data = processed_data[len(self.binary_data) + 1:-64]
        number_of_0s = padding_data.count('0')
        self.assertEqual(len(padding_data), number_of_0s)

if __name__ == '__main__':
    unittest.main()
