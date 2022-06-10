# 拡張ElGamal暗号
import math
import random
import sympy as sym

# 素数判定
def Is_prime(num):
    if num == 1: return False
    elif num == 2: return True
    elif num % 2 == 0: return False
    for i in range(3, int(math.sqrt(num))+1, 2):
        if num % i == 0: return False
    return True

prime = []
for i in range(1, 1000):
    if Is_prime(i) == True: # 1-1000までの数字を素数かどうかを判定して、素数だったらtrueを返す。
        prime.append(i) # 配列の最後に要素を追加

count = len(prime)    
print('素数の数: ', count)
print(prime[0:5], "-----", prime[-6:-1])

# 鍵生成アルゴリズム

# phase1:GenGアルゴリズム
p_flag = False
while p_flag == False:
    q_candidate_index = random.randint(int(count/2), count-1) # 素数の数/2 から 素数の数-1まで
    q_candidate = prime[q_candidate_index] # 適当な素数
    p_candidate = 2*q_candidate + 1 # p = 2q + 1
    if Is_prime(p_candidate) == True: # 一応素数確認
        p = p_candidate
        q = q_candidate
        p_flag = True

print('chosen q, chosen p: ', q, p)

p_primitiveroot = []
for i in range(1, p): # 1からpまでの間で、
    if sym.is_primitive_root(i, p) == True: # sympy is_primarive_root 原始根だったら
        p_primitiveroot.append(i) # 配列p_primitiverootに追加

print('max p_primitiveroot = ', max(p_primitiveroot))
        
chosen_primitiveroot = random.choice(p_primitiveroot) # ランダムな原始根を取る
alpha = chosen_primitiveroot**2 % p # ランダムな原始根^2 mod p 
print('chosen chosen_primitiveroot = ', chosen_primitiveroot)
print('alpha = ', alpha)

g_cyclic_group = []
for i in range(q): # 0 から qまで
    g_cyclic_group.append(alpha **i %p) # a^i % p を追加

print('g_cyclic_group order: ', len(g_cyclic_group))

# gが循環群かどうかを確認している？
for i in range(1, 10):
    if alpha**i % p in g_cyclic_group: 
        print(alpha, '^', i, ' is in g_cyclic_group') # alpha ^ iがg_cyclic_groupにあるかを確認する
    else:
        print(alpha, '^', i, ' is NOT in g_cyclic_group')


# phase2:0 ≦ x ≦ 1〜q-1 となる整数xをランダムに取得
x = random.randint(0, q-1)

print('private key: x = ', x) # 秘密鍵

# phase3:y = g ^ x
y = alpha ** x % p
print('y = ', y)

# 平文を生成(平文はGの元)
m_index = random.randint(1, q-1)
m = g_cyclic_group[m_index]
print('message m = ', m)

# 暗号化アルゴリズム
r = random.randint(0, q-1)
print('r = ', r)

# c1 = g ^ r
c1 = alpha**r % p

# c2 = m * y ^ r
c2 = m * (y**r) % p

# 暗号文を出力
print('encrypted (c1 and c2): ', c1, c2)

# 復号アルゴリズム
inverse_c1 = 0
inverse_c1_flag = False

for i in range(0, q):
    # 1 == c1 * g^i
    if c1 * (alpha **i) % p == 1:
        # c1 ^ -1 = g^i
        inverse_c1 = alpha **i %p
        print('inverse_c1 = ', inverse_c1)
        inverse_c1_flag = True 

if inverse_c1_flag == False:
    print('could not find inverse_c1')

decrypted = c2 * (inverse_c1 **x) % p
print('dectypted message is ', decrypted)

if decrypted == m: print('decryption success!')
else: print('something is wrong!')


def elgamal_gen_key(bits):
    g = number.getRandomRange(0,q-1)