#@title Elliptic curve for secp256k1
import random
class S256P:
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    def __init__(self, x, y):
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        self.x = self.x % self.p
        self.y = self.y % self.p
        if pow(self.y, 2, self.p) != (pow(self.x, 3, self.p) + 7) % self.p:
            #例外処理
            raise ValueError(
                'The x and y are not on curve.{:02x} {:02x}'.format(self.x, self.y))

    def __add__(self, other):
        if self.x == None:
            return other.__class__(other.x, other.y)
        if other.x == None:
            return self.__class__(self.x, self.y)
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None)
        if self.x != other.x:
            s = ((self.y - other.y)
                 * pow(self.x - other.x, self.p - 2, self.p)) % self.p
            x = (pow(s, 2, self.p) - self.x - other.x) % self.p
            y = (s * (self.x - x) - self.y) % self.p
            return self.__class__(x, y)
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None)
        if self == other:
            s = ((3 * pow(self.x, 2, self.p))
                 * pow(2 * self.y, self.p - 2, self.p)) % self.p
            x = (pow(s, 2, self.p) - 2 * self.x) % self.p
            y = (s * (self.x - x) - self.y) % self.p
            return self.__class__(x, y)

    def __rmul__(self, coefficient):
        if self.x is None:
            return self.__class__(None, None)
        coef = coefficient % self.n
        current = self.__class__(self.x, self.y)
        result = self.__class__(None, None)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result

    def compress(self):
        if self.y % 2 == 0:
            return b'\x02' + self.x.to_bytes(32, 'big')
        else:
            return b'\x03' + self.x.to_bytes(32, 'big')

    def uncompress(self):
        return b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')


def parse(compress):
    if len(compress) != 33:
        raise ValueError('illegal length: {}'.format(len(compress)))
    even = True
    if compress[0] == 3:
        even = False
    x = int.from_bytes(compress[1:33], 'big')
    y2 = (pow(x, 3, S256P.p) + 7) % S256P.p
    y = pow(y2, (S256P.p + 1) >> 2, S256P.p)
    if even:
        if y % 2 == 1:
            y = S256P.p - y
    else:
        if y % 2 == 0:
            y = S256P.p - y
    return S256P(x, y)


G = S256P(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
          0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
message = 'hello'  # @param {type:"string"}
m = int.from_bytes(message.encode('utf-8'), 'big') * 100
M = S256P(None, None)
for i in range(100):
    try:
        bs = b'\x02' + (m+i).to_bytes(32, 'big')
        M = parse(bs)
        break
    except ValueError as e:
        continue

x = random.randint(2, S256P.n)
P = x * G

print('P  =', P.compress().hex(), '# 公開鍵')

r = random.randint(2, S256P.n)
C1 = r * G
C2 = M + r * P
print('C1 =', C1.compress().hex(), '# 暗号１')
print('C2 =', C2.compress().hex(), '# 暗号２')

M = C2 + (- x) * C1


m = M.x // 100
print(m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8'))