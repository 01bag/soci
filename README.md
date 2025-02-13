# <center>Secure Computation on Integers —— Python Project

# SOCI
The Secure Outsourced Computation on Integers (SOCI) scheme employs a twin-server architecture that is based on the Paillier cryptosystem. This framework enables secure outsourced computation involving encrypted integers, as opposed to being limited to natural numbers [1]. Notably, SOCI achieves significant improvements in computational efficiency compared to fully homomorphic encryption mechanisms. Within the SOCI framework, a comprehensive set of efficient secure computation protocols has been developed, encompassing secure multiplication ($\textsf{SMUL}$), secure comparison ($\textsf{SCMP}$), secure sign bit-acquisition ($\textsf{SSBA}$), and secure division ($\textsf{SDIV}$). These protocols have been designed to facilitate secure computations on both non-negative integers and negative integers, providing a versatile and robust solution for secure outsourced computation.


# Preliminary

The protocols within the SOCI framework are constructed upon the foundation of the Paillier cryptosystem with threshold decryption (PaillierTD). This variant of the conventional Paillier cryptosystem divides the private key into two partially private keys. Importantly, neither of these partially private keys alone possesses the capability to effectively decrypt a ciphertext that has been encrypted using the Paillier cryptosystem. The PaillierTD scheme comprises the following algorithms.

$\textbf{Key Generation} (\textsf{KeyGen})$: Let $p,q$ be two strong prime numbers (i.e., $p=2p'+1$ and $q=2q'+1$, where $p'$ and $q'$ are prime numbers) with $\kappa$ bits (e.g., $\kappa=512$). Compute $N=p\cdot q$, $\lambda=lcm(p-1,q-1)$ and $\mu=\lambda^{-1}\mod N$. Let the generator $g=N+1$, the public key $pk=(g,n)$ and the private key $sk=\lambda$.

The private key $\lambda$ is split into two parts denoted by $sk_1=\lambda_1$ and $sk_2=\lambda_2$, s.t., $\lambda_1+\lambda_2=0\mod\lambda$ and $\lambda_1+\lambda_2=1\mod N$. According to the Chinese remainder theorem, we can calculate $\sigma=\lambda_1+\lambda_2=\lambda\cdot\mu\mod(\lambda\cdot\mu)$ to make $\delta=0\mod\lambda$ and $\delta=1\mod N$ hold at the same time, where $\lambda_1$ can be a $\sigma$-bit random number and $\lambda_2=\lambda\cdot\mu+\eta\cdot\lambda N-\lambda_1$ ($\eta$ is a non-negative integer).

$\textbf{Encryption} (\textsf{Enc})$: Taken as input a message $m\in\mathbb{Z}_N$, this algorithm outputs $[ m]\leftarrow\textsf{Enc}(pk,m)=g^m\cdot r^N\mod N^2$, where $r$ is a random number in $\mathbb{Z}^*_N$ and $[ m]=[ m\mod N]$. 

$\textbf{Decryption} (\textsf{Dec})$: Taken as input a ciphertext $[ m]$ and $sk$, this algorithm outputs $m\leftarrow\textsf{Dec}(sk,[ m])=L([ m]^{\lambda}\mod N^2)\cdot\mu\mod N$, where $L(x)=\frac{x-1}{N}$.

$\textbf{Partial Decryption} (\textsf{PDec})$: Take as input a ciphertext $[ m]$ and a partially private key $sk_i$ ($i\in\{1,2\}$), and outputs $M_i\leftarrow\textsf{PDec}(sk_i,[ m])=[ m]^{\lambda_i}\mod N^2$.

For brevity, we will omot $\mod N^2$ for $\textsf{Enc}$ algorithm in the rest of the document.

PaillierTD has the additive homomorphism and scalar-multipilication homomorphism as follows.

- Additive homomorphism: $\textsf{Dec}(sk,[ m_1+m_2\mod N])=\textsf{Dec}(sk,[ m_1]\cdot[ m_2])$;

- Scalar-multiplication homomorphism: $\textsf{Dec}(sk,[ c\cdot m\mod N])=\textsf{Dec}(sk,[ m]^c)$ for $c\in\mathbb{Z}^*_N$. Particularly, when $c=N-1$, $\textsf{Dec}(sk,[ m]^c)=-m$ holds.


# System Architecture
![SOCI system architecture](./resource/SOCI_system_architecture.png)

The system architecture of SOCI, depicted in the figure above, comprises a data owner (DO) and two servers: a cloud platform (CP) and a computation service provider (CSP).

- DO: The DO is responsible for securely generating and distributing keys to both CP and CSP. To achieve this, the DO initiates the $\textsf{KeyGen}$ algorithm to create a public/private key pair, denoted as $(pk, sk)$, for the Paillier cryptosystem. Subsequently, the DO splits the private key $sk$ into two partially private keys, labeled as $(sk_1, sk_2)$. Following this, the DO distributes $(pk, sk_1)$ and $(pk, sk_2)$ to CP and CSP, respectively. To safeguard data privacy, the DO encrypts data using the public key $pk$ and then outsources the encrypted data to CP. Additionally, the DO outsources computation services, performed on the encrypted data, to both CP and CSP.
- CP: CP is responsible for storing and managing the encrypted data transmitted by the DO. It also generates intermediate results and final results while keeping them in an encrypted form. Furthermore, CP is capable of directly executing specific calculations over encrypted data, such as homomorphic addition and homomorphic scalar multiplication. CP collaborates with CSP to execute secure operations like $\textsf{SMUL}$, $\textsf{SCMP}$, $\textsf{SSBA}$, and $\textsf{SDIV}$ on encrypted data.
- CSP: CSP exclusively offers online computation services and does not retain any encrypted data. Specifically, CSP works in conjunction with CP to perform secure computations, such as multiplication, comparison, and division, on encrypted data.


# SOCI-Python API Description

The project in this version is written in Python.

## generate_paillier_keypair()

Taken as input a security parameter $\kappa$, this algorithm generates two strong prime numbers $p$, $q$ with $\kappa$ bits. Then, it compute $N = p\cdot q$, $\lambda=lcm(p-1,q-1)$, $\mu=\lambda^{-1}\mod N$ and $g= N+1$. It outputs the public key $pk=(g,N)$ and private key $sk=\lambda$. 

Taken as input the private key  $sk$ , it computes $sk_1$ and $sk_2$. The private key $sk=\lambda$ is split into two parts denoted by $sk_1 = \lambda_1$ and $sk_2 = \lambda_2$, s.t., $\lambda_1+\lambda_2=0\mod\lambda$ and $\lambda_1+\lambda_2=1\mod N$. 

- PaillierPublicKey(). This class outputs the public key public_key= $(g,N)$.


- PaillierPrivateKey(). This class outputs the private key private_key= $\lambda$.


- PartialPaillierPrivateKey(). This class outputs the partial private keys partial_private_keys= $(sk_1,sk_2)$.


## encrypt()
Taken as input a plaintext $m$,  this algorithm encrypts $m$ into ciphertext $c$ with public $pk$. In the computations of SOCI, the value of message m should be between $-N/2$ and $N/2$.


## decrypt()
Taken as input a ciphertext $c$,  this algorithm decrypts $c$ into plaintext $m$ with secret key $sk$. The input ciphertext $c$ should be between 0 and $N^2$ to guarantee correct decryption.


## partial_decrypt()
Given a ciphertext $c$, this algorithm partial decrypts $c$ into partially decrypted ciphertext $C_1$ with partial secret key $sk_1$, or partial decrypts $c$ into $C_2$ with $sk_2$.

- cp.partial_decrypt(): This algorithm is executed by cloud platform for partial decryption.

- csp.partial_decrypt(): This algorithm is executed by computation service provider for partial decryption.


## smul()
Given ciphertexts $ex$ and $ey$, this algorithm computes the multiplication homomorphism and outputs the result $ciphertext$. Suppose $ex=[ x]$ and $ey=[ y]$. Then, the result $ciphertext=[ x\cdot y]$. 


## _add_encrypted()
Given two ciphertext $c_1$ and $c_2$,  this algorithm computes the additive homomorphism and output the result $res$. Suppose $c_1=[ m_1]$ and $c_2=[ m_2]$. Then, the result $sum<sub>ciphertext</sub>=[ m_1+m_2]$. The input ciphertexts $c_1$ and $c_2$ should between 0 and $N^2$. 

## scmp()
Given ciphertexts $ex$ and $ey$, this algorithm computes the secure comparison result $res$. Suppose $ex=[ x]$ and $ey=[ y]$. Then, the result $ciphertext=[ 1]$ if x<y , and $ciphertext=[ 0]$ if $x\geq y$. 

## sdot_vector()

Given ciphertexts $ex$ and $ey$, this algorithm computes the dot production of vectors and outputs the result $ciphertext$. Suppose $ex=[ x]$ and $ey=[ y]$, where vectors $x=(x_1,\cdots,x_n)$, $y=(y_1,\cdots,y_n)$ and $[ x]=([ x_1],\cdots,[ x_n])$, $[ y]=([ y_1],\cdots,[ y_n])$. Then, the result $enc_{dot}=[ z]$, where $$z=\sum_{i=1}^n x_i\cdot y_i.$$ 

-------------------------------------------

# Build Dependencies

* OS: Windows 11
* numpy

# Build SOCI-Python
```sh
pip install -r requirements.txt 
```

## Run SOCI-Python
```sh
python3 algorithm_test.py
```
## Output:
    set x =   1238572
    E(x) =  3826160357666431518607150556354038784177936683067937390247450490466221182937130105714823719210263345731984551021854473948477649851606869129410293163209184
    compute encrypt function, its running time is ------  0.366200 ms
    x=  1238572
    ---------------------------
    set x =   726173
    compute decrypt function, its running time is ------  0.000300 ms
    x=  726173
    ---------------------------
    set x = 18413, y = 2847
    run _add_encrypted function, its running time is  ------  0.006900 ms
    x + y = 21260
    ---------------------------
    set x = 123, y = 222
    compute scl_mul function, its running time is  ------  0.017100 ms
    x*y = 27306
    ---------------------------
    Secure computation protocols
    set x = 99, y = 789
    compute SMUL function, its running time is  ------  4.175300 ms
    x*y = 78111
    ---------------------------
    set x = 99, y = 789
    compute SCMP function, its running time is  ------  3.285400 ms
    x<y 
    ---------------------------
    set qf=[[0.  1.2 2.4]] 
    set gf=[[0.  1.3 2.6]
            [1.  2.3 3.6]
            [2.  3.3 4.6]
            [3.  4.3 5.6]
            [4.  5.3 6.6]]
    compute sdot function, its running time is ------ 63.487300ms
    q_g_dist=[[ 7.8 11.4 15.  18.6 22.2]]
    ---------------------------
# Performance
We employed varying values of KEY_LEN_BIT to assess the performance of each function. The experiments were conducted on a laptop equipped with a 10th Gen Intel(R) Core(TM) i5-10210U CPU, consisting of 2 cores running at 2.70 GHz and 2 cores running at 2.69 GHz, with 16GB of RAM. The obtained experimental results are detailed below:
|**Length of key in bit**| **KEY_LEN_BIT**|**256**|**384**|**512**|**640**| **768** | **896** | **1024**|
| ------ | ------ | ------ | ------ |------ |------ |  ------ |------ |------ |
| 	PaillierTD Encryption		| 	encrypt	| 	0.31158	| 	0.890245	| 	1.69446	| 	2.727275	| 	4.531075	| 	6.54862	| 	10.222125	| 
| 	PaillierTD Decryption		| 	decrypt	| 	0.23807	| 	0.664915	| 	1.356725	| 	2.529825	| 	4.40573	| 	6.728625	| 	9.666675	| 
| 	Secure Addition		| 	add	| 	0.007285	| 	0.01436	| 	0.020015	| 	0.02415	| 	0.03977	| 	0.061285	| 	0.063205	| 
| 	Secure Scalar Multiplication		| 	scl_mul	| 	0.016645	| 	0.03404	| 	0.051585	| 	0.07038	| 	0.09575	| 	0.13957	| 	0.17699	| 
| 	Secure Multiplication	| 	SMUL	| 	2.375615 	| 	7.676255	| 	18.56232	| 	33.735535	| 	63.27857	| 	74.16896	| 	109.29592	| 
| 	Secure Comparison		| 	SCMP	| 	1.385825	| 	4.3059	| 	8.687665	| 	16.568485	| 	27.034525	| 	42.45019	| 	58.41245	| 
| 	Secure Dot Production		| 	SDOT	| 	46.267135	| 	146.16107	| 	292.701925	| 	580.94016	| 	946.897805	| 	1594.465575	| 	2083.95945	| 




The time unit is ms.


# Benchmark
In the Main.cpp source code file, you have the flexibility to modify the values of two important parameters: KEY_LEN_BIT and SIGMA_LEN_BIT.

(1) KEY_LEN_BIT governs the bit-length of the large prime used in the computation.

(2) SIGMA_LEN_BIT dictates the bit-length of the variable denoted as $sk_1$ in the program.

# Reference

1. Bowen Zhao, Jiaming Yuan, Ximeng Liu, Yongdong Wu, Hwee Hwa Pang, and Robert H. Deng. SOCI: A toolkit for secure outsourced computation on integers. IEEE Transactions on Information Forensics and Security, 2022, 17: 3637-3648.

