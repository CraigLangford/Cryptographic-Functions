

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
