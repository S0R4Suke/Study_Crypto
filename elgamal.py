# ElGamal暗号
# pip install pycryptodome
from Crypto.Util import number

# 鍵生成アルゴリズム
def elgamal_gen_key(bits):
    # 素数p
    while True:
        q = number.getPrime(bits-1) # ランダムなNビットの素数を返す
        p = 2*q + 1
        if number.isPrime(p): # pが素数である場合はTrueが返される
            break # 素数だったらbreak,そうではないならループを続ける
    # 原始元g
    while True:
        g = number.getRandomRange(3, p) # 3 ≦ x < p間でランダムな数xを返す
        # 原始元判定
        if pow(g, 2, p) == 1: # g^2 % p == 1だった時、whileの先頭に戻ってやり直す
            continue
        if pow(g, q, p) == 1: # g^q % p == 1だった時、whileの先頭に戻ってやり直す
            continue
        break
    # 秘密値x
    x = number.getRandomRange(0, p-2) # 0≦x≦p-2となる整数xをランダムに選ぶ
    # 公開値y
    y = pow(g, x, p) # g^x % p を計算
    return (p, g, y), x # 公開鍵と秘密鍵を返す

# 暗号化アルゴリズム
def elgamal_encrypt(m, pk):
    p, g, y = pk # 3つの公開鍵?をp,g,yとして格納
    assert(0 <= m < p) # 平文が0≦m<pを満たしていることをテスト
    r = number.getRandomRange(0, p-2) # 0≦r≦p-2となる整数rをランダムに選ぶ
    c1 = pow(g, r, p)           # c_1 = g^r mod p
    c2 = (m * pow(y, r, p)) % p # c_2 = m * y^r % p,平文mをy^rと掛け合わせ、平文をマスクする
    return (c1, c2)

# 復号アルゴリズム
def elgamal_decrypt(c, pk, sk):
    p, g, y = pk
    c1, c2 = c
    return (c2 * pow(c1, p - 1 - sk, p)) % p


# 情報準同型生を持つ計算パート
pk, sk = elgamal_gen_key(20)
p, _, _ = pk
print('pk:', pk) # 公開鍵
print('sk:', sk) # 秘密鍵
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
print('c1*c2:', tuple(c))

d = elgamal_decrypt(c, pk, sk)
print('d:', d)