# 楕円ElGamal暗号
import math
import random

def Is_prime(num):
    if num == 1: return False
    elif num == 2: return True
    elif num % 2 == 0: return False
    for i in range(3, int(math.sqrt(num))+1, 2):
        if num % i == 0: return False
    return True

prime = []
for i in range(500, 550):
    if Is_prime(i) == True:
        prime.append(i)

p = random.choice(prime)
print('p = ', p)
ab_flag = False 
while ab_flag == False: 
    a = random.randint(1, p-1) # random.randint = ランダムな整数を生成
    b = random.randint(1, p-1)
    if 4*(a**3) + 27*(b**2) == 0: # 4*a^3+27*b^2 == 0
        ab_flag = False
    else: 
        ab_flag = True 

print('elliptic curve : y^2 = x^3 +', a ,'* x^2 + ', b, ' mod ', p)
def f(x):
    return (x**3 + a*x + b) % p

g = []
for i in range(0, p):
    for j in range(0, p):
        if j **2 %p == f(i): 
            g.append([i, j])

print('g order = ', len(g))
print('g = ', g)
Hasse_lower = p + 1 - 2 * math.sqrt(p)
Hasse_upper = p + 1 + 2 * math.sqrt(p)
print('Hasse lower = ', Hasse_lower)
print('Hasse upper = ', Hasse_upper)
if len(g) > Hasse_lower and len(g) < Hasse_upper: print("Within Hasse range")
else: print('Out of Hasse range')


def modular_inverse(a, p):
    inverse_a = 0
    for i in range(0, p):
        if a * i % p == 1:
            inverse_a = i
            return inverse_a


def find_lambda(x1, y1, x2, y2, p):
    if x1 == x2 and y1 == y2:
        if ( (3*(x1**2) + a) / (2*y1) ) %1 ==0:
            return ( (3*(x1**2) + a) / (2*y1) ) %p
        else: 
            return ( (3*(x1**2) + a) * modular_inverse(2*y1, p) ) %p
    else:
        if ( (y2-y1) / (x2-x1) ) %1 ==0:
            return ( (y2-y1) / (x2-x1) ) %p
        else: 
            return ( (y2-y1) * modular_inverse(x2-x1, p) ) %p        

def find_group_and_order(R, p):
    R_original = R
    Group = []
    Group.append(R)
    Order_flag = False 
    Order = 0
    
    while Order_flag == False:
        R_new = [0, 0]
        if R == [0, 0]:
            R_new = R_original
        elif (R[0] == R_original[0]) and ((R[1] + R_original[1]) %p == 0):
            R_new[0] = 0
            R_new[1] = 0
        else: 
            L = find_lambda(R[0], R[1], R_original[0], R_original[1], p)
            R_new[0] = (L**2 - R[0] - R_original[0]) %p
            R_new[1] = (L * (R[0]-R_new[0]) - R[1]) %p
        R = R_new
        Group.append(R)
        Order = Order +1
        if R == R_original: Order_flag = True
        else: Order_flag = False
    
    return Group, Order
    
P_original = random.choice(g)
P = P_original
print(P)
P_group = find_group_and_order(P, p)[0]
print('P_group = ', P_group)
P_order = find_group_and_order(P, p)[1]
print('P_order = ', P_order)
x = random.randint(1, p-1)
Y = P_group[(x-1) %P_order]
print('public keys :')
print('p = ', p)
print('P = ', P_original)
print('Y = ', Y)
print('secret key : ')
print('x = ', x)

M = random.choice(P_group)
print("M (message to encrypt) = ", M)
r = random.randint(1, p-1)
print('r = ', r)
c1 = P_group[(r-1) %P_order]
print('c1 = ', c1)
Y_group = find_group_and_order(Y, p)[0]
print('Y_group = ', Y_group)
Y_order = find_group_and_order(Y, p)[1]
print('Y_order = ', Y_order)
rY = Y_group[(r-1) %Y_order]
print(rY)
rY = Y_group[(r-1) %Y_order]
c2_x = ( M[0] + rY[0] ) %p
c2_y = ( M[1] + rY[1] ) %p
c2 = [c2_x, c2_y]
print('c2 = ', c2)
print('encrypted message is ', c1, c2)
c1_group = find_group_and_order(c1, p)[0]
print('c1_group = ', c1_group)
c1_order = find_group_and_order(c1, p)[1]
print('c1_order = ', c1_order)
xc1 = c1_group[(x-1) %c1_order]
print('xc1 = ', xc1)
M_decrypt_x = ( c2[0] - xc1[0] ) %p
M_decrypt_y = ( c2[1] - xc1[1] ) %p
M_decrypt = [M_decrypt_x, M_decrypt_y]
print('M_decrypt = ', M_decrypt)
if M_decrypt == M: print('decryption success!')
else: print('somthing is wrong')