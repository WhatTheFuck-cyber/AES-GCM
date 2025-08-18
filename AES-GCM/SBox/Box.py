# ============================================================================================================================================================== #
#  ____                    ______                    ____         ___ ___            ___ ___                    ______                  ____ ____ ____ ____ ___  #
# |\ __\                  /__  __\                  /__ /|       ||_    _|          ||_    _|                  /\____/\                \\—— —— —— —— —— —— —— —\ #
# | \   \                /   /\   \                /   / |         ||  |              ||  |                   / /    \ \               ||___ ____      ____ ___| #
#  \ \   \              /   /||\   \              /   / /          ||  |              ||  |                  / /  /\  \ \                        ||   |          #
#   \ \   \            /   / /\ \   \            /   / /           ||  |              ||  |                 / /  /  \  \ \                       ||   |          #
#    \ \   \          /   / /  \ \   \          /   / /            ||  |___ ___ ___ __||  |                / /  /    \  \ \                      ||   |          #
#     \ \   \        /   / /    \ \   \        /   / /             ||  \—— —— —— —— ——\   |               / /  /      \  \ \                     ||   |          #
#      \ \   \      /   / /      \ \   \      /   / /              ||   ___ ___ ___ ___   |              / /  /___  ___\  \ \                    ||   |          #
#       \ \   \    /   / /        \ \   \    /   / /               ||  |              ||  |             / /  / \— —— —\ \  \ \                   ||   |          #
#        \ \   \  /   / /          \ \   \  /   / /                ||  |              ||  |            / /  /_ __ __ __ _\  \ \                  ||   |          #
#         \ \   \/   / /            \ \   \/   / /                 ||  |              ||  |           / /  /              \  \ \                 ||   |          #
#          \ \ ____ / /              \ \ ____ / /                  ||  |_             ||  |_         / /__/                \__\ \                || _ |          #
#           \/______\/                \/______\/                 || ____ |          || ____ |        \\__/                  \__//                ||___|          #
# ============================================================================================================================================================== #


# python Box.py


# ------------------------------------------- 本文件定义 AES 的 S 盒与逆 S 盒 ------------------------------------------- #
"""再投入使用之前，请确定是使用内存固定的 S 盒，还是使用临时计算的 S 盒函数。前者适合内存充足的设备，后者适合内存有限的设备。"""


# ----------------------------------------------- 标准 S 盒与标准逆 S 盒 ----------------------------------------------- #
_std_SBOX = bytes([
#   0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  # 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  # 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  # 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  # 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  # 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  # 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  # 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  # 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  # 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  # 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  # A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  # B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  # C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  # D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  # E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   # F
])

_std_INV_SBOX = bytes([
#   0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,  # 0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,  # 1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,  # 2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,  # 3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,  # 4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,  # 5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,  # 6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,  # 7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,  # 8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,  # 9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,  # A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,  # B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,  # C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,  # D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,  # E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d   # F
])


# ---------------------------------------------------- S Box look-up ----------------------------------------------------- #
def SBOX(data: bytearray) -> bytearray:
    '''S 盒正向变换，支持操作一个字节数组的变换'''
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = _std_SBOX[data[i]]
    return result

def INV_SBOX(data: bytearray) -> bytearray:
    '''S 盒逆向变换，支持操作一个字节数组的变换'''
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = _std_INV_SBOX[data[i]]
    return result


# -------------------------------------------------- S Box caculator 1 --------------------------------------------------- #
"""
_MOD = 0x11B

def _rot_l(x: int, k: int) -> int:
    '''循环左移 k 位'''
    return ((x << k) | (x >> (8 - k))) & 0xFF

def _poly_mul_on_GF(a: int, b: int, mod : int = _MOD) -> int:
    '''有限域上的多项式乘法并处理模约减'''
    M = mod.bit_length() - 1

    result = 0
    a &= 0xFF
    b &= 0xFF

    # 有限域上的多项式乘法
    for i in range(M):
        if (a & (1 << i)) != 0:  # a 的第 i 位为 1，则进行一次移位异或计算
            result ^= b << i

    # 模约简：将结果约简到 8 位以内（使用 GF(2^8) 上的模约减）
    for i in range(2 * M - 1, M - 1, -1):  # 从最高位开始处理（最多 15 位）
        if (result & (1 << i)) != 0:  # result 的第 i 位为 1，则进行一次模约简计算
            result ^= (mod << (i - M))
    
    return result & 0xFF

def _inverse(val : int, mod : int = _MOD) -> int:
    '''有限域逆元计算（扩展欧几里得算法）'''
    if val == 0:  # 0 的逆元定义为 0
        return 0
    
    # 初始化，这里的 0 指代循环中的 i-1；1 指代循环中的 i
    r0, r1 = mod, val
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    
    while r1 != 0:
        # 多项式除法：求商q和余数r，使得r_{i-1} = q*r_{i} + r_{i+1}（模2运算）
        q = 0
        degree_r0, degree_r1 = r0.bit_length() - 1, r1.bit_length() - 1
        
        while degree_r0 >= degree_r1:
            # GF(2^8) 上多项式除法的余数求法：高位对齐后作异或
            # GF(2^8) 上多项式除法的除数求法：高位对齐的左移数
            shift = degree_r0 - degree_r1
            q ^= (1 << shift)  # 用于 s 和 t 的更新
            r0 ^= (r1 << shift)
            
            if r0 == 0:  # 直接处理 GF(2^8) 上多项式除法计算完的余数是 0 的情况
                degree_r0 = -1
                break
            degree_r0 = r0.bit_length() - 1
        
        # 迭代更新：t 和 s 是滑动窗口式更新；r 是倒序更新。【这取决于 GF(2^8) 上多项式除法的算法】
        r0, r1 = r1, r0
        # 请注意，更新时的乘法是 GF(2^8) 上的多项式乘法，不是简单的异或、整数乘法、与、或等运算。
        s0, s1 = s1, s0 ^ _poly_mul_on_GF(q, s1)
        t0, t1 = t1, t0 ^ _poly_mul_on_GF(q, t1)

    # 算法中提到，当 r_{n-1} = 1 时（等价于 r_{n} = 0），t_{n-1} 是 b(x) 的逆元
    return t0 & 0xFF

def SBOX(data: bytearray) -> bytearray:
    '''S 盒正向变换，支持操作一个字节数组的变换'''
    result = bytearray(len(data))

    for i in range(len(data)):
        val = data[i]  # 取出字节（整数类型，可直接位运算）
        
        if val == 0:  # 特殊处理，输入为 0x00，直接获得输出 0x63
            result[i] = 0x63
            continue
        # 1. 有限域逆元计算（扩展欧几里得算法）
        t = _inverse(val)
        
        # 2. 仿射变换（位运算）
        b = t & 0xFF
        result[i] = (b ^ _rot_l(b, 1) ^ _rot_l(b, 2) ^ _rot_l(b, 3) ^ _rot_l(b, 4) ^ 0x63) & 0xFF
    
    return result

def INV_SBOX(data: bytearray) -> bytearray:
    '''S 逆向变换，支持操作一个字节数组的变换'''
    result = bytearray(len(data))

    for i in range(len(data)):
        c = data[i]  # 取出当前字节（整数类型）
        
        if c == 0x63:  # 特殊处理，输入为 0x63，直接获得输出 0x00
            result[i] = 0x00
            continue

        # 1. 逆仿射变换（优化版：循环移位+异或）
        b = (_rot_l(c, 1) ^ _rot_l(c, 3) ^ _rot_l(c, 6) ^ 0x05) & 0xFF
        
        # 2. 有限域逆元计算（与原逻辑一致）
        t = _inverse(b)
        result[i] = t & 0xFF

    return result
"""

# -------------------------------------------------- S Box caculator 2 --------------------------------------------------- #
"""
_MOD = 0x11B

def _rot_l(x: int, k: int) -> int:
    '''循环左移 k 位'''
    return ((x << k) | (x >> (8 - k))) & 0xFF

# 这是一个 AI 写的实现方式
def SBOX(data: bytearray) -> bytearray:
    '''S 盒正向变换，支持操作一个字节数组的变换'''
    result = bytearray(len(data))

    for i in range(len(data)):
        val = data[i]  # 取出字节（整数类型，可直接位运算）
        
        if val == 0:  # 特殊处理，输入为 0x00，直接获得输出 0x63
            result[i] = 0x63
            continue
        
        # 1. 有限域逆元计算（扩展欧几里得算法）
        u, v = val, _MOD
        t, s = 1, 0
        while u != 1:
            j = len(bin(u)) - len(bin(v))
            if j < 0:
                u, v = v, u
                t, s = s, t
                continue
            u ^= (v << j)
            t ^= (s << j)
            u &= 0xFF  # 确保在单字节范围内
        
        # 2. 仿射变换（位运算）
        b = t & 0xFF
        result[i] = (b ^ _rot_l(b, 1) ^ _rot_l(b, 2) ^ _rot_l(b, 3) ^ _rot_l(b, 4) ^ 0x63) & 0xFF
    
    return result

def INV_SBOX(data: bytearray) -> bytearray:
    '''S 逆向变换，支持操作一个字节数组的变换'''
    result = bytearray(len(data))

    for i in range(len(data)):
        c = data[i]  # 取出当前字节（整数类型）
        
        if c == 0x63:  # 特殊处理，输入为 0x63，直接获得输出 0x00
            result[i] = 0x00
            continue

        # 1. 逆仿射变换（优化版：循环移位+异或）
        b = (_rot_l(c, 1) ^ _rot_l(c, 3) ^ _rot_l(c, 6) ^ 0x05) & 0xFF
        
        # 2. 有限域逆元计算（与原逻辑一致）
        u, v = b, _MOD
        t, s = 1, 0
        while u != 1:
            j = u.bit_length() - v.bit_length()
            if j < 0:
                u, v = v, u
                t, s = s, t
                j = -j
            u ^= (v << j)
            t ^= (s << j)
            u &= 0xFF
        result[i] = t & 0xFF

    return result
""""""
# 这是一个使用 galois 库进行逆元计算的实现方式
import galois

_MOD = 0x11B

def _rot_l(x: int, k: int) -> int:
    '''循环左移 k 位'''
    return ((x << k) | (x >> (8 - k))) & 0xFF

def SBOX(data: bytearray) -> bytearray:
    '''S 盒正向变换，支持操作一个字节数组的变换'''
    GF = galois.GF(2**8, irreducible_poly = _MOD)
    result = bytearray(len(data))
    for i in range(len(data)):
        a = data[i]
        if a == 0:
            result[i] = 0x63
            continue
        b = int(GF(a) ** (-1))
        result[i] = (b ^ _rot_l(b, 1) ^ _rot_l(b, 2) ^ _rot_l(b, 3) ^ _rot_l(b, 4) ^ 0x63) & 0xFF
    return result


def INV_SBOX(data: bytearray) -> bytearray:
    '''S 逆向变换，支持操作一个字节数组的变换'''
    GF = galois.GF(2**8, irreducible_poly = _MOD)
    result = bytearray(len(data))
    for i in range(len(data)):
        c = data[i]
        if c == 0x63:
            result[i] = 0x00
            continue
        b = (_rot_l(c, 1) ^ _rot_l(c, 3) ^ _rot_l(c, 6) ^ 0x05) & 0xFF
        result[i] = int(GF(b) ** (-1))
    return result
"""


# ------------------------------------------------------- check ------------------------------------------------------- #
def _check_validity() -> None:
    '''检查自定义 S 盒和逆 S 盒与标准 S 盒的一致性'''
    # 测试所有可能的字节值（0x00 ~ 0xFF）
    all_bytes = bytearray(range(256))
    
    # 验证正向S盒
    test_sbox = all_bytes.copy()
    sbox_match = (SBOX(test_sbox) == _std_SBOX)
    
    # 验证逆向S盒
    test_inv_sbox = all_bytes.copy()
    inv_sbox_match = (INV_SBOX(test_inv_sbox) == _std_INV_SBOX)
    
    # 验证互逆性（S盒→逆S盒应返回原始值）
    mutual_check = True
    for val in range(256):
        # 正向变换后再逆向变换
        data = bytearray([val])
        data = SBOX(data)
        data = INV_SBOX(data)
        if data[0] != val:
            mutual_check = False
            break
    
    # 输出检查结果
    print(f"正向S盒与标准S盒匹配: {'✅' if sbox_match else '❌'}")
    print(f"逆S盒与标准逆S盒匹配: {'✅' if inv_sbox_match else '❌'}")
    print(f"S盒与逆S盒互逆性验证: {'✅' if mutual_check else '❌'}")
    
    # 若存在不匹配，输出具体差异位置（便于调试）
    if not sbox_match:
        for i in range(256):
            if test_sbox[i] != _std_SBOX[i]:
                print(f"正向S盒差异: 输入0x{i:02X} → 自定义0x{test_sbox[i]:02X}, 标准0x{_std_SBOX[i]:02X}")
                break  # 只显示第一个差异
    
    if not inv_sbox_match:
        for i in range(256):
            if test_inv_sbox[i] != _std_INV_SBOX[i]:
                print(f"逆S盒差异: 输入0x{i:02X} → 自定义0x{test_inv_sbox[i]:02X}, 标准0x{_std_INV_SBOX[i]:02X}")
                break  # 只显示第一个差异


# ------------------------------------------------------- main ------------------------------------------------------- #
if __name__ == '__main__':
    _check_validity()


# ============================================================================================================================================================== #
#  ____                    ______                    ____         ___ ___            ___ ___                    ______                  ____ ____ ____ ____ ___  #
# |\ __\                  /__  __\                  /__ /|       ||_    _|          ||_    _|                  /\____/\                \\—— —— —— —— —— —— —— —\ #
# | \   \                /   /\   \                /   / |         ||  |              ||  |                   / /    \ \               ||___ ____      ____ ___| #
#  \ \   \              /   /||\   \              /   / /          ||  |              ||  |                  / /  /\  \ \                        ||   |          #
#   \ \   \            /   / /\ \   \            /   / /           ||  |              ||  |                 / /  /  \  \ \                       ||   |          #
#    \ \   \          /   / /  \ \   \          /   / /            ||  |___ ___ ___ __||  |                / /  /    \  \ \                      ||   |          #
#     \ \   \        /   / /    \ \   \        /   / /             ||  \—— —— —— —— ——\   |               / /  /      \  \ \                     ||   |          #
#      \ \   \      /   / /      \ \   \      /   / /              ||   ___ ___ ___ ___   |              / /  /___  ___\  \ \                    ||   |          #
#       \ \   \    /   / /        \ \   \    /   / /               ||  |              ||  |             / /  / \— —— —\ \  \ \                   ||   |          #
#        \ \   \  /   / /          \ \   \  /   / /                ||  |              ||  |            / /  /_ __ __ __ _\  \ \                  ||   |          #
#         \ \   \/   / /            \ \   \/   / /                 ||  |              ||  |           / /  /              \  \ \                 ||   |          #
#          \ \ ____ / /              \ \ ____ / /                  ||  |_             ||  |_         / /__/                \__\ \                || _ |          #
#           \/______\/                \/______\/                 || ____ |          || ____ |        \\__/                  \__//                ||___|          #
# ============================================================================================================================================================== #