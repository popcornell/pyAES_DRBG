import re


def parse_test_vectors(keylen, df_used):
    """Parse the test vector file to obtain test vectors in a suitable format
    """

    if df_used == True:

        pass  # TODO with Derivation function

    else:  # no derivation function

        ver_pattern = r'(?P<version>AES-%d no df)'.format(keylen)

        rx_dict = {
            'version': re.compile(ver_pattern),
            'entropy': re.compile(r'EntropyInput = (?P<entropy>.*)\n'),
            'entropy_rs': re.compile(r'EntropyInputReseed = (?P<entropy_rs>.*)\n'),
            'key': re.compile(r'\s*Key\s*=\s*(?P<key>.*)\n'),
            'v': re.compile(r'\s*V\s*=\s*(?P<v>.*)\n'),
            'r_bits': re.compile(r'ReturnedBits = (?P<r_bits>.*)\n')
        }

        # init return lists

        entropy = []
        key_list = []
        v = []
        entropy_rs = []
        returned_bits = []

        lines_of_interest = 0

        with open('test_vectors/CTR_DRBG.txt', 'r') as vectors:  # open txt with dRBG test vectors

            line = vectors.readline()

            while line:  # parse line

                key, match = _parse_line(rx_dict, line)

                if key == "version":
                    # ok we have reached the portion of the file where AES-256 no df test vectors are defined

                    lines_of_interest = lines_of_interest + 1  # jump first occurence in header

                if lines_of_interest == 2:

                    # start gathering test_vectors

                    if key == "entropy":
                        temp = match.group("entropy")
                        entropy.append(bytes.fromhex(temp))

                    if key == "key":
                        temp = match.group("key")
                        key_list.append(bytes.fromhex(temp))

                    if key == "v":
                        temp = match.group("v")
                        v.append(bytes.fromhex(temp))

                    if key == "entropy_rs":
                        temp = match.group("entropy_rs")
                        entropy_rs.append(bytes.fromhex(temp))

                    if key == "r_bits":
                        temp = match.group("r_bits")
                        returned_bits.append(bytes.fromhex(temp))

                line = vectors.readline()

        return entropy, key_list, v, entropy_rs, returned_bits


def _parse_line(rx_dict, line):
    for key, rx in rx_dict.items():
        match = rx.search(line)
        if match:
            return key, match

    # if there are no matches
    return None, None
