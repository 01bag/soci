from encryption import paillier
import random
import time
import numpy as np
from util import invert, powmod, getprimeover, isqrt, extended_euclidean_algorithm
from encoding import EncodedNumber

class SecureComputing(object):
    DEFAULT_SIGMA = 118

    def __init__(self, cp, csp):
        self.cp = cp
        self.csp = csp

    def sdot_vector(self, evector1, evector2, sigm_len=None):

        if len(evector1) != len(evector2):
            raise Exception('error operation! the dot product requires two vector has the same size')
        else:
            if sigm_len is None:
                sigm_len = self.DEFAULT_SIGMA

            size = len(evector1)
            #enc_dot = self.smul(evector1[0], evector2[0])
            enc_dot = self.conv_smul(evector1[0], evector2[0])[0]
            for i in range(1, size):
                #enc_dot = enc_dot + self.smul(evector1[i], evector2[i], sigm_len)
                enc_dot = enc_dot + self.conv_smul(evector1[i], evector2[i], sigm_len)[0]

            return enc_dot

    def sdot(self, enc_qf, enc_gf, sigm_len=None):

        if sigm_len is None:
            sigm_len = self.DEFAULT_SIGMA

        size_probe = len(enc_qf)
        size_gallery = len(enc_gf)
        enc_q_g_dist = np.zeros((size_probe, size_gallery), dtype=paillier.EncryptedNumber)
        for i in range(size_probe):
            for j in range(size_gallery):
                enc_q_g_dist[i][j] = self.sdot_vector(enc_qf[i], enc_gf[j], sigm_len)

        q_g_dist = np.zeros((size_probe, size_gallery), dtype=float)
        for i in range(size_probe):
            for j in range(size_gallery):
                q_g_dist[i][j] = self.cp.final_decrypt(self.cp.partial_decrypt(enc_q_g_dist[i][j]),
                                                       self.csp.partial_decrypt(enc_q_g_dist[i][j]))
        return enc_q_g_dist, q_g_dist

    def batch_smul(self, elist, sigm_len=None):

        bit_len = 0

        if sigm_len is None:
            sigm_len = self.DEFAULT_SIGMA

        L = 2 ** (sigm_len + 2)

        # Step-1
        rlist = []
        r = self.get_random_with_sigmbits(sigm_len)
        rlist.append(r)
        er = self.cp.public_key.encrypt(r)
        eRes = elist[0] + er
        for i in range(1, len(elist)):
            r = self.get_random_with_sigmbits(sigm_len)
            rlist.append(r)
            er = self.cp.public_key.encrypt(r)
            etmp = elist[i] + er
            etmp = etmp * (L ** i)
            eRes = eRes + etmp

        eRes1 = self.cp.partial_decrypt(eRes)
        bit_len += eRes1.ciphertext.bit_length()

        # Step-2
        eRes2 = self.csp.partial_decrypt(eRes)
        res = self.csp.final_decrypt(eRes1, eRes2)
        delta = len(elist) // 2
        eXY = []
        for i in range(delta):
            etmp = res % (L ** (2*i+2)) // (L ** (2*i))
            X = etmp // L
            Y = etmp % L
            eXY.append(csp.public_key.encrypt(X * Y))

            bit_len += eXY[i].ciphertext(False).bit_length()

        # Step-3
        ciphertexts = []
        for i in range(len(eXY)):
            er1_mul_r2 = self.cp.public_key.encrypt(rlist[2*i] * rlist[2*i+1])
            er1_mul_r2.exponent = elist[2*i].exponent
            if elist[2*i].exponent > 0:
                ciphertexts.append((eXY[i] + (elist[2*i] * - rlist[2*i+1]) + (elist[2*i+1] * -rlist[2*i]) - er1_mul_r2)
                                   / (10 ** elist[2*i].exponent))
            else:
                # return ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2, sum_time
                ciphertexts.append((eXY[i] + (elist[2*i] * - rlist[2*i+1]) + (elist[2*i+1] * -rlist[2*i]) - er1_mul_r2))

        return ciphertexts
    def smul(self, ev1, ev2, sigm_len=None):

        if ev1.public_key != ev2.public_key:
            raise Exception('an error operation')
        elif ev1.exponent != ev2.exponent:
            raise Exception('ev1 (ev1.exponent=%i) should has the same exponent with ev2 (ev2.exponent=%i)'
                            % (ev1.exponent, ev2.exponent))
        else:
            if sigm_len is None:
                sigm_len = self.DEFAULT_SIGMA

            # L = 10 ** (sigm_len // 3)
            L = 2 ** (sigm_len + 2)

            # Step-1
            starTim = time.perf_counter()
            r1 = self.get_random_with_sigmbits(sigm_len)
            r2 = self.get_random_with_sigmbits(sigm_len)
            er1 = self.cp.public_key.encrypt(r1)
            er2 = self.cp.public_key.encrypt(r2)
            er1.exponent = er2.exponent = ev1.exponent

            ev1_add_r1 = ev1 + er1
            ev2_add_r2 = ev2 + er2
            X1 = self.cp.partial_decrypt(ev1_add_r1)
            Y1=  self.cp.partial_decrypt(ev2_add_r2)
            eRes = (ev1_add_r1 * L) + ev2_add_r2
            sum_time = time.perf_counter() - starTim

            # Step-2
            starTim = time.perf_counter()
            X2 = self.csp.partial_decrypt(ev1_add_r1)
            Y2=self.csp.partial_decrypt(ev2_add_r2)
            x_add_r1 = self.csp.final_decrypt(X1,X2)
            y_add_r2 = self.csp.final_decrypt(Y1,Y2)
            ex_add_r1_mul_y_add_r2 = self.csp.public_key.encrypt(x_add_r1 * y_add_r2)
            ex_add_r1_mul_y_add_r2.exponent = eRes.exponent
            sum_time += time.perf_counter() - starTim

            # Step-3
            er1_mul_r2 = self.cp.public_key.encrypt(r1 * r2)
            er1_mul_r2.exponent = ev1.exponent
            if ev1.exponent > 0:
                return (ex_add_r1_mul_y_add_r2 + ((ev1 * r2) + (ev2 * r1) +er1_mul_r2)*(self.cp.n-1)) / (10 ** ev1.exponent), sum_time

            else:
                return ex_add_r1_mul_y_add_r2 + ((ev1 * r2) + (ev2 * r1) +er1_mul_r2)*(self.cp.n-1), sum_time
    # def smul(self, ev1, ev2, sigm_len=None):
    #
    #     if ev1.public_key != ev2.public_key:
    #         raise Exception('an error operation')
    #     elif ev1.exponent != ev2.exponent:
    #         raise Exception('ev1 (ev1.exponent=%i) should has the same exponent with ev2 (ev2.exponent=%i)'
    #                         % (ev1.exponent, ev2.exponent))
    #     else:
    #         if sigm_len is None:
    #             sigm_len = self.DEFAULT_SIGMA
    #
    #         # L = 10 ** (sigm_len // 3)
    #         L = 2 ** (sigm_len + 2)
    #
    #         # Step-1
    #         starTim = time.perf_counter()
    #         r1 = self.get_random_with_sigmbits(sigm_len)
    #         r2 = self.get_random_with_sigmbits(sigm_len)
    #         er1 = self.cp.public_key.encrypt(r1)
    #         er2 = self.cp.public_key.encrypt(r2)
    #         er1.exponent = er2.exponent = ev1.exponent
    #
    #         ev1_add_r1 = ev1 + er1
    #         ev2_add_r2 = ev2 + er2
    #         eRes = (ev1_add_r1 * L) + ev2_add_r2
    #         eRes1 = self.cp.partial_decrypt(eRes)
    #         sum_time = time.perf_counter() - starTim
    #
    #         # Step-2
    #         starTim = time.perf_counter()
    #         eRes2 = self.csp.partial_decrypt(eRes)
    #         Res = self.csp.final_decrypt(eRes1, eRes2)
    #         x_add_r1 = Res // L
    #         y_add_r2 = Res % L
    #         ex_add_r1_mul_y_add_r2 = self.csp.public_key.encrypt(x_add_r1 * y_add_r2)
    #         ex_add_r1_mul_y_add_r2.exponent = eRes.exponent
    #         sum_time += time.perf_counter() - starTim
    #
    #         # Step-3
    #         er1_mul_r2 = self.cp.public_key.encrypt(r1 * r2)
    #         er1_mul_r2.exponent = ev1.exponent
    #         if ev1.exponent > 0:
    #             return (ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2) / (10 ** ev1.exponent), sum_time
    #             #return (ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2) / (2 ** ev1.exponent)
    #         else:
    #             #return ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2, sum_time
    #             return ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2, sum_time

    def conv_smul(self, ev1, ev2, sigm_len=None):

        bit_len = 0
        if ev1.public_key != ev2.public_key:
            raise Exception('an error operation')
        elif ev1.exponent != ev2.exponent:
            raise Exception('ev1 (ev1.exponent=%i) should has the same exponent with ev2 (ev2.exponent=%i)'
                            % (ev1.exponent, ev2.exponent))
        else:
            if sigm_len is None:
                sigm_len = self.DEFAULT_SIGMA

            startTim = time.perf_counter()
            # Step-1
            r1 = self.get_random_with_sigmbits(sigm_len)
            r2 = self.get_random_with_sigmbits(sigm_len)
            er1 = self.cp.public_key.encrypt(r1)
            er2 = self.cp.public_key.encrypt(r2)
            er1.exponent = er2.exponent = ev1.exponent

            X = ev1 + er1
            Y = ev2 + er2
            X1 = self.cp.partial_decrypt(X)
            Y1 = self.cp.partial_decrypt(Y)

            bit_len += X1.ciphertext.bit_length()
            bit_len += Y1.ciphertext.bit_length()
            sum_time = time.perf_counter() - startTim

            startTim = time.perf_counter()
            # Step-2
            X2 = self.csp.partial_decrypt(X)
            Y2 = self.csp.partial_decrypt(Y)
            x_add_r1 = self.csp.final_decrypt(X1, X2)
            y_add_r2 = self.csp.final_decrypt(Y1, Y2)
            ex_add_r1_mul_y_add_r2 = self.csp.public_key.encrypt(x_add_r1 * y_add_r2)
            ex_add_r1_mul_y_add_r2.exponent = X.exponent

            bit_len += ex_add_r1_mul_y_add_r2.ciphertext(False).bit_length()

            sum_time += time.perf_counter() - startTim

            startTim = time.perf_counter()
            # Step-3
            er1_mul_r2 = self.cp.public_key.encrypt(r1 * r2)
            er1_mul_r2.exponent = ev1.exponent
            if ev1.exponent > 0:
                res = (ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2) / (10 ** ev1.exponent)
                #res = (ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2) / (2 ** ev1.exponent)
                sum_time += time.perf_counter() - startTim
                return res, sum_time
                #return res
            else:
                res = ex_add_r1_mul_y_add_r2 + (ev1 * -r2) + (ev2 * -r1) - er1_mul_r2
                sum_time += time.perf_counter() - startTim
                return res, sum_time
                #return res
    def scmp(self, ev1, ev2,cp,csp,sigm_len=None,):
        if ev1.public_key != ev2.public_key:
            raise Exception('an error operation')
        elif ev1.exponent != ev2.exponent:
            raise Exception('ev1 (ev1.exponent=%i) should has the same exponent with ev2 (ev2.exponent=%i)'
                            % (ev1.exponent, ev2.exponent))
        else:
            if sigm_len is None:
                sigm_len = self.DEFAULT_SIGMA
            # Step-1
            sum_time=0
            startTim = time.perf_counter()
            pi = random.randint(0, 1)
            mid_n = cp.n // 2
            r1 = random.SystemRandom().randrange(1, 1 << sigm_len)
            r2 = random.SystemRandom().randrange(mid_n - r1 + 1, mid_n)
            if pi == 0:
                er1_add_r2 = cp.public_key.encrypt(r1 + r2)
                er1_mul_v1subv2 = (ev1 - ev2) * r1
                er1_add_r2.exponent = er1_mul_v1subv2.exponent
                eRes = er1_mul_v1subv2 + er1_add_r2
            else:
                er2 = cp.public_key.encrypt(r2)
                er1_mul_v2subv1 = (ev2 - ev1) * r1
                er2.exponent = er1_mul_v2subv1.exponent
                eRes = er1_mul_v2subv1 + er2
            eRes1 = cp.partial_decrypt(eRes)
            sum_time += time.perf_counter() - startTim

            startTim = time.perf_counter()
            # Step-2
            eRes2 = csp.partial_decrypt(eRes)
            Res = csp.final_decrypt(eRes1, eRes2)
            if Res < 0:
                u = 0
            else:
                u = 1
            eu = csp.public_key.encrypt(u)
            sum_time += time.perf_counter() - startTim

            startTim = time.perf_counter()
            # Step-3
            if pi == 0:
                return eu,sum_time
            else:
                return cp.public_key.encrypt(1) - eu,sum_time
    def get_random_with_sigmbits(self, sigm_len):
        """Return a cryptographically random number less than :attr:`n`"""
        return random.SystemRandom().randrange(1 << sigm_len - 1, 1 << sigm_len)
            

if __name__ == '__main__':
    public_key, private_key, partial_private_keys = paillier.generate_paillier_keypair(n_length=512)

    cp = paillier.ThresholdPaillier(public_key, partial_private_keys.sk1)
    csp = paillier.ThresholdPaillier(public_key, partial_private_keys.sk2)
    sc = SecureComputing(cp, csp)

    """qf = np.zeros((1,3), dtype=float)
    gf = np.zeros((5,3), dtype=float)
    enc_qf = np.zeros((1,3), dtype=paillier.EncryptedNumber)
    enc_gf = np.zeros((5,3), dtype=paillier.EncryptedNumber)
    for i in range(len(qf)):
        for j in range(len(qf[i])):
            qf[i][j] = i + j * 1.2
            enc_qf[i][j] = public_key.encrypt(qf[i][j])
    print(qf)
    for i in range(len(gf)):
        for j in range(len(gf[i])):
            gf[i][j] = i + j * 1.3
            enc_gf[i][j] = public_key.encrypt(gf[i][j])
    print(gf)

    enc_q_g_dist, q_g_dist1 = sc.sdot(enc_qf, enc_gf)
    for i in range(len(enc_q_g_dist)):
        for j in range(len(enc_q_g_dist[i])):
            print(private_key.decrypt(enc_q_g_dist[i][j]), q_g_dist1[i][j])"""

    # f_x = random.random()
    # f_y = random.random()
    # ev1 = public_key.encrypt(f_x)
    # ev2 = public_key.encrypt(f_y)
    # print(private_key.decrypt(sc.conv_smul(ev1, ev2)[0]) == f_x * f_y)
    # print(private_key.decrypt(sc.smul(ev1, ev2)[0]) == f_x * f_y)

    count_mul = count_cmp = 0
    conv_time = imp_time = 0
    for i in range(100):
        f_x = random.random()
        f_y = random.random()
        if i % 4 == 1:
            f_x = f_x * -1
        if i % 4 == 2:
            f_y = f_y * -1
        if i % 4 == 3:
            f_x = f_x * -1
            f_y = f_y * -1
        ev1 = public_key.encrypt(f_x)
        ev2 = public_key.encrypt(f_y)
        conv_time += sc.conv_smul(ev1, ev2)[0]
        imp_time += sc.smul(ev1, ev2)[0]
        if private_key.decrypt(sc.conv_smul(ev1, ev2)[0]) != f_x * f_y:
            count_mul += 1
        if private_key.decrypt(sc.scmp(public_key.encrypt(f_x), public_key.encrypt(f_y))) == 0:
            count_cmp += 1
    print(count_mul, count_cmp)
    print(conv_time / 100, imp_time / 100)


