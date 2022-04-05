from bitarray import bitarray
from bitarray import  util
from textwrap import wrap
from consts import Const
W = 64 
M = 1 << W
FF = M - 1



def RR(x, b):
    return ((x >> b) | (x << (W - b))) & FF


def Pad(W):

    mdi = len(W) % 64
    L = (len(W) << 3).to_bytes(8, 'big')
    npad = 55 - mdi if mdi < 56 else 119 - mdi
    return bytes(W, 'ascii') + b'\x80' + (b'\x00' * npad) + L


def Pad512(W):

    mdi = len(W) % 128
    L = (len(W) << 3).to_bytes(16, 'big')
    npad = 111 - mdi if mdi < 112 else 239 - mdi
    return bytes(W, 'ascii') + b'\x80' + (b'\x00' * npad) + L


def Sha256CF(Wt, Kt, A, B, C, D, E, F, G, H):

    Ch = (E & F) ^ (~E & G)
    Ma = (A & B) ^ (A & C) ^ (B & C)
    S0 = RR(A, 2) ^ RR(A, 13) ^ RR(A, 22)
    S1 = RR(E, 6) ^ RR(E, 11) ^ RR(E, 25)
    T1 = H + S1 + Ch + Wt + Kt
    return (T1 + S0 + Ma) & FF, A, B, C, (D + T1) & FF, E, F, G


def Sha512CF(Wt, Kt, A, B, C, D, E, F, G, H):

    Ch = (E & F) ^ (~E & G)
    Ma = (A & B) ^ (A & C) ^ (B & C)
    S0 = RR(A, 28) ^ RR(A, 34) ^ RR(A, 39)
    S1 = RR(E, 14) ^ RR(E, 18) ^ RR(E, 41)
    T1 = H + S1 + Ch + Wt + Kt
    return (T1 + S0 + Ma) & FF, A, B, C, (D + T1) & FF, E, F, G


def Sha256(M):

    M = Pad(M)
    DG = list(Const.H)
    for j in range(0, len(M), 64):
        S = M[j:j + 64]
        W = [0] * 64
        W[0:16] = [int.from_bytes(S[i:i + 4], 'big') for i in range(0, 64, 4)]

        for i in range(16, 64):
            s0 = RR(W[i - 15], 7) ^ RR(W[i - 15], 18) ^ (W[i - 15] >> 3)
            s1 = RR(W[i - 2], 17) ^ RR(W[i - 2], 19) ^ (W[i - 2] >> 10)
            W[i] = (W[i - 16] + s0 + W[i-7] + s1) & FF

        A, B, C, D, E, F, G, H = DG

        for i in range(64):
            A, B, C, D, E, F, G, H = Sha256CF(W[i], Const.K[i], A, B, C, D, E, F, G, H)
        DG = [(X + Y) & FF for X, Y in zip(DG, (A, B, C, D, E, F, G, H))]
    return b''.join(Di.to_bytes(4, 'big') for Di in DG)


def Sha224(M):

    M = Pad(M)
    DG = list(Const.H1)
    for j in range(0, len(M), 64):
        S = M[j:j + 64]
        W = [0] * 64
        W[0:16] = [int.from_bytes(S[i:i + 4], 'big') for i in range(0, 64, 4)]

        for i in range(16, 64):
            s0 = RR(W[i - 15], 7) ^ RR(W[i - 15], 18) ^ (W[i - 15] >> 3)
            s1 = RR(W[i - 2], 17) ^ RR(W[i - 2], 19) ^ (W[i - 2] >> 10)
            W[i] = (W[i - 16] + s0 + W[i-7] + s1) & FF

        A, B, C, D, E, F, G, H = DG

        for i in range(64):
            A, B, C, D, E, F, G, H = Sha256CF(W[i], Const.K[i], A, B, C, D, E, F, G, H)
        DG = [(X + Y) & FF for X, Y in zip(DG, (A, B, C, D, E, F, G, H))]
    return b''.join(Di.to_bytes(4, 'big') for Di in DG)


def Sha512(M):

    M = Pad512(M)
    DG = list(Const.H2)
    for j in range(0, len(M), 128):
        S = M[j:j + 128]
        W = [0] * 128
        W[0:16] = [int.from_bytes(S[i:i + 8], 'big') for i in range(0, 128, 8)]

        for i in range(16, 80):
            s0 = RR(W[i - 15], 1) ^ RR(W[i - 15], 8) ^ (W[i - 15] >> 7)
            s1 = RR(W[i - 2], 19) ^ RR(W[i - 2], 61) ^ (W[i - 2] >> 6)
            W[i] = (W[i - 16] + s0 + W[i-7] + s1) & FF

        A, B, C, D, E, F, G, H = DG

        for i in range(80):
            A, B, C, D, E, F, G, H = Sha512CF(W[i], Const.K1[i], A, B, C, D, E, F, G, H)
        DG = [(X + Y) & FF for X, Y in zip(DG, (A, B, C, D, E, F, G, H))]
    return b''.join(Di.to_bytes(8, 'big') for Di in DG)



if __name__ == "__main__":

    """hash = Sha224(u'The quick brown fox jumps over the lazy dog')
    hash = ''.join('{:02x}'.format(i) for i in hash)
    print(wrap(hash, 8))

    hash = Sha256(u'The quick brown fox jumps over the lazy dog')
    hash = ''.join('{:02x}'.format(i) for i in hash)
    print(wrap(hash, 8))"""

    hash = Sha512(u'The quick brown fox jumps over the lazy dog')
    hash = ''.join('{:02x}'.format(i) for i in hash)
    print(wrap(hash, 8))

