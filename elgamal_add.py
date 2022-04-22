# 修正Elgamal暗号
from Crypto.Util import number

# 鍵生成アルゴリズム
def elgamal_gen_key(bits):
    # 素数p
    while True:
        q = number.getPrime(bits-1)
        p = 2*q + 1
        if number.isPrime(p):
            break
    # 原始元g
    while True:
        g = number.getRandomRange(3, p)
        # 原始元判定
        if pow(g, 2, p) == 1:
            continue
        if pow(g, q, p) == 1:
            continue
        break
    # 秘密値x
    x = number.getRandomRange(0, p-2)
    # 公開値y
    y = pow(g, x, p)
    return (p, g, y), x

# 暗号化アルゴリズム
def elgamal_encrypt(m, pk):
    p, g, y = pk
    assert(0 <= m < p)
    r = number.getRandomRange(0, p-2)
    c1 = pow(g, r, p)
    c2 = (pow(g, m, p) * pow(y, r, p)) % p
    return (c1, c2)

# 復号アルゴリズム
def elgamal_decrypt(c, pk, sk):
    p, g, y = pk
    c1, c2 = c
    r = (c2 * pow(c1, p - 1 - sk, p)) % p
    return baby_step_giant_step(g, r, p)

#以下elgamal暗号と異なる部分

# Baby-step Giant-step法
# X^K ≡ Y (mod M) となるような K を求める
def baby_step_giant_step(X, Y, M):
    print('XYZ:',X,Y,M)

    D = {1: 0} # {g^i: i}
    m = int(M**0.5) + 1 # m = ⌈√M⌉ 
    print('m:',m)
    # Baby-step
    # m = ⌈√M⌉  とし、 x^0,x^1...x^(m-1)を求めるステップ 
    Z = 1
    for i in range(m):
        Z = (Z * X) % M
        D[Z] = i+1
    if Y in D:
        print('D[Y]:',D[Y])
        return D[Y]

    # Giant-step
    R = pow(Z, M-2, M) # R = X^{-m}
    for i in range(1, m+1):
        Y = (Y * R) % M
        if Y in D:
            return D[Y] + i*m
    return -1

pk, sk = elgamal_gen_key(bits=20)
p, _, _ = pk
print('pk:', pk)
print('sk:', sk)
print()

m1 = 3
c1 = elgamal_encrypt(m1, pk)
m2 = 7
c2 = elgamal_encrypt(m2, pk)
print('m1:', m1)
print('m2:', m2)
print('c1:', c1)
print('c2:', c2)

c = [ (a * b) % p for a, b in zip(c1, c2) ]
print('c1+c2:', tuple(c))

d = elgamal_decrypt(c, pk, sk)
print('d:', d)