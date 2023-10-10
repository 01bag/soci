import numpy as np

from encryption import paillier
import time
import secrets

import random


from secomp.secureprotol import SecureComputing
# for test

public_key, private_key, partial_private_keys = paillier.generate_paillier_keypair(n_length=1024)
cp = paillier.ThresholdPaillier(public_key, partial_private_keys.sk1)
csp = paillier.ThresholdPaillier(public_key, partial_private_keys.sk2)
sc = SecureComputing(cp, csp)
print("n= ",public_key.n)
def encrypt_test(a):
    print("set x =  ", a)
    starTim = time.perf_counter()
    c=public_key.encrypt(a)
    print("E(x) = ",c.ciphertext())
    t=time.perf_counter() - starTim
    print("compute encrypt function, its running time is ------ ",time.perf_counter() - starTim)
    print("x= ", private_key.decrypt(c))
    print('---------------------------')
    return t


def decrypt_test(a):
        print("set x =  ", a)
        c=public_key.encrypt(a)
        starTim = time.perf_counter()
        print("x= ", private_key.decrypt(c))
        t = time.perf_counter() - starTim
        print("compute decrypt function, its running time is ------ ", time.perf_counter() - starTim)
        print('---------------------------')
        return t

def _add_scalar_test(a,b):     #Returns decrypt(E(a + b)), given self=E(a) and b
    print("set x =  ",a,', y = ',b)
    a=public_key.encrypt(a)
    starTim = time.perf_counter()
    c=a._add_scalar(b)
    t = time.perf_counter() - starTim
    print("compute _add_scalar function, its running time is ------ ", time.perf_counter() - starTim)
    print("decrypt result of E(a)+b",private_key.decrypt(c))
    print('---------------------------')
    return t

def _add_encrypted_test(a,b):      #Returns decrypt(E(a + b)) given E(a) and E(b).
    print("set x =  ", a, ', y = ', b)
    a = public_key.encrypt(a)
    b = public_key.encrypt(b)
    starTim = time.perf_counter()
    c=a._add_encrypted(b)
    t = time.perf_counter() - starTim
    print("compute _add_encrypted function, its running time is ------ ", time.perf_counter() - starTim)
    print("x+y= ", private_key.decrypt(c))
    print('---------------------------')
    return t


def __mul__test(a,b):      #Returns decrypt(E(a)*b) given E(a) and b
    print("set x =  ", a, ', y = ', b)
    a = public_key.encrypt(a)
    starTim = time.perf_counter()
    c=a.__mul__(b)
    t = time.perf_counter() - starTim
    print("compute __mul__ function, its running time is ------ ", time.perf_counter() - starTim)
    print("x*y = ", private_key.decrypt(c))
    print('---------------------------')
    return t




def smul_test(f_x,f_y):
    #f_x =random.random()
    #f_y =random.random()
    print("set x =  ", f_x, ', y = ', f_y)
    ev1 = public_key.encrypt(f_x)
    ev2 = public_key.encrypt(f_y)
    c=sc.conv_smul(ev1, ev2)
    d=sc.smul(ev1, ev2)
    print("compute conv_smul function, its running time is ------ ", c[1])
    print("x*y = ",private_key.decrypt(c[0]))
    print("compute smul function, its running time is ------ ", d[1])
    print("x*y = ",private_key.decrypt(d[0]))
    print('---------------------------')
    return d[1]


def sdot_test():
    qf = np.zeros((1, 3), dtype=float)
    gf = np.zeros((5, 3), dtype=float)
    enc_qf = np.zeros((1, 3), dtype=paillier.EncryptedNumber)
    enc_gf = np.zeros((5, 3), dtype=paillier.EncryptedNumber)
    for i in range(len(qf)):
        for j in range(len(qf[i])):
            qf[i][j] = i + j * 1.2
            enc_qf[i][j] = public_key.encrypt(qf[i][j])
    print("qf: ",qf)
    for i in range(len(gf)):
        for j in range(len(gf[i])):
            gf[i][j] = i + j * 1.3
            enc_gf[i][j] = public_key.encrypt(gf[i][j])
    print("gf: ",gf)
    starTim = time.perf_counter()
    enc_q_g_dist, q_g_dist1 = sc.sdot(enc_qf, enc_gf)
    t = time.perf_counter() - starTim
    print("compute sdot function, its running time is ------ ", time.perf_counter() - starTim)

    for i in range(len(enc_q_g_dist)):
        for j in range(len(enc_q_g_dist[i])):
            print("enc_q_g_dist:  ",private_key.decrypt(enc_q_g_dist[i][j])," q_g_dist1: ", q_g_dist1[i][j])
    print('---------------------------')
    return t


def scmp_test(f_x,f_y):
    starTim = time.perf_counter()
    a=sc.scmp(public_key.encrypt(f_x), public_key.encrypt(f_y),cp,csp)
    print(private_key.decrypt(a[0]))
    t = time.perf_counter() - starTim
    print("compute scmp function, its running time is ------ ", time.perf_counter() - starTim)
    return a[1]
# sum=0.0
# print('c= ',random.getrandbits(256))
# for i in range(20):
#  sum+=__mul__test(5429496723,9949672)
# print(sum/20.0)

smul_test(12,12)

'''
encrypt_test(random.getrandbits(256))
decrypt_test(726173)
_add_encrypted_test(18413,2847)
__mul__test(123,222)
smul_test(99,789)

sdot_test()
scmp_test(99,789)
'''
