import unittest
from test_vectors.parse_ctr_drbg import parse_test_vectors
from aes_drbg import AES_DRBG

class test_DRBG(unittest.TestCase):

    def test_DRBG_AES_128_no_df(self):

        print("\nTesting SP 800-90A, Rev 1 NIST AES-128 DRBG NO DERIVATION FUNCTION\n")

        entropy, key, v, entropy_rs, r_bits = parse_test_vectors(128, df_used=False)

        indx = 0

        for i in range(len(entropy)):
            drbg = AES_DRBG(256)

            # TEST INSTANTIATE

            drbg.instantiate(entropy[i])

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST RESEED

            drbg.reseed(entropy_rs[i])

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST GENERATE_1

            drbg.generate(64)

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST GENERATE_2

            returned_bits = drbg.generate(64)

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])
            self.assertEqual(returned_bits, r_bits[i])

            indx += 1

    def test_DRBG_AES_192_no_df(self):

        print("\nTesting SP 800-90A, Rev 1 NIST AES-192 DRBG NO DERIVATION FUNCTION\n")

        entropy, key, v, entropy_rs, r_bits = parse_test_vectors(128, df_used=False)

        indx = 0

        for i in range(len(entropy)):
            drbg = AES_DRBG(256)

            # TEST INSTANTIATE

            drbg.instantiate(entropy[i])

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST RESEED

            drbg.reseed(entropy_rs[i])

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST GENERATE_1

            drbg.generate(64)

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST GENERATE_2

            returned_bits = drbg.generate(64)

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])
            self.assertEqual(returned_bits, r_bits[i])

            indx += 1



    def test_DRBG_AES_256_no_df(self):

        print("\nTesting SP 800-90A, Rev 1 NIST AES-256 DRBG NO DERIVATION FUNCTION\n")

        entropy, key, v, entropy_rs, r_bits = parse_test_vectors(256, df_used=False)


        indx = 0

        for i in range(len(entropy)):

            drbg = AES_DRBG(256)

            # TEST INSTANTIATE

            drbg.instantiate(entropy[i])

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST RESEED

            drbg.reseed(entropy_rs[i])

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST GENERATE_1

            drbg.generate(64)

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])

            indx += 1

            # TEST GENERATE_2

            returned_bits = drbg.generate(64)

            self.assertEqual(drbg.key, key[indx])
            self.assertEqual(drbg.V, v[indx])
            self.assertEqual(returned_bits, r_bits[i])

            indx += 1







