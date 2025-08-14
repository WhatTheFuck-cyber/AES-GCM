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


# python -m BlockOperation.Block


# ------------------------------------------- 本文件定义 AES 的 分块加密 ------------------------------------------- #
"""本文件给出了 AES 的正向加密和逆向解密的分块操作，当 AES 用于基于 CTR 模式的工作模式时，仅需要加密操作即可（CTR 只需要正向密码函数）"""


# --------------------------------------------------- 头部库导入 --------------------------------------------------- #
from SBox.Box import SBOX, INV_SBOX  # 输入：bytearray 类型的待置换字节； 输出：bytearray 类型的已置换字节
from KeyExpansion.KEF import KeyExpansion  # 输入：bytes 类型的密钥 + int 类型的密钥长度； 输出：list 类型的轮密钥列表，每个轮密钥是
from typing import List


# ------------------------------------------- GF(2^8)有限域上的多项式乘法 ------------------------------------------- #
_MOD = 0x11B
def _poly_mul_on_GF(a: int, b: int, mod : int = _MOD) -> int:
    '''GF(2^8) 有限域上的多项式乘法并处理模约减'''
    result = 0
    a &= 0xFF
    b &= 0xFF
    for i in range(8):
        if (a & (1 << i)) != 0:
            result ^= b << i
    for i in range(15, 7, -1):
        if (result & (1 << i)) != 0:
            result ^= (mod << (i - 8))
    return result & 0xFF


# ---------------------------------------------- 四个核心函数及其逆函数 ---------------------------------------------- #
def _AddRoundKey(state : List[bytearray], round_key : List[bytearray]) -> List[bytearray]:
    '''轮密钥加操作：将状态矩阵与轮密钥矩阵按字节异或'''
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def _SubBytes(state : List[bytearray]) -> List[bytearray]:
    '''字节替换操作：通过S盒对状态矩阵中的每个字节进行替换'''
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX(bytearray([state[i][j]]))[0]
    return state

def _ShiftRows(state : List[bytearray]) -> List[bytearray]:
    '''行移位操作：对状态矩阵的后三行执行循环左移'''
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state

def _MixColumns(state : List[bytearray]) -> List[bytearray]:
    '''列混淆操作：对状态矩阵的每一列执行 GF(2^8) 域上的线性变换'''
    for i in range(4):
        a0 = state[0][i]
        a1 = state[1][i]
        a2 = state[2][i]
        a3 = state[3][i]
        state[0][i] = _poly_mul_on_GF(0x02, a0) ^ _poly_mul_on_GF(0x03, a1) ^ a2 ^ a3
        state[1][i] = a0 ^ _poly_mul_on_GF(0x02, a1) ^ _poly_mul_on_GF(0x03, a2) ^ a3
        state[2][i] = a0 ^ a1 ^ _poly_mul_on_GF(0x02, a2) ^ _poly_mul_on_GF(0x03, a3)
        state[3][i] = _poly_mul_on_GF(0x03, a0) ^ a1 ^ a2 ^ _poly_mul_on_GF(0x02, a3)
    return state

def _InvAddRoundKey(state : List[bytearray], round_key : List[bytearray]) -> List[bytearray]:
    '''逆轮密钥加操作：将状态矩阵与轮密钥矩阵按字节异或'''
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def _InvSubBytes(state : List[bytearray]) -> List[bytearray]:
    '''逆字节替换操作：通过逆 S 盒对状态矩阵中的每个字节进行替换'''
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX(bytearray([state[i][j]]))[0]
    return state

def _InvShiftRows(state : List[bytearray]) -> List[bytearray]:
    '''逆行移位操作：对状态矩阵的后三行执行循环右移'''
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

def _InvMixColumns(state : List[bytearray]) -> List[bytearray]:
    '''逆列混淆操作：对状态矩阵的每一列执行 GF(2^8) 域上的线性变换'''
    for i in range(4):
        a0 = state[0][i]
        a1 = state[1][i]
        a2 = state[2][i]
        a3 = state[3][i]
        state[0][i] = _poly_mul_on_GF(0x0E, a0) ^ _poly_mul_on_GF(0x0B, a1) ^ _poly_mul_on_GF(0x0D, a2) ^ _poly_mul_on_GF(0x09, a3)
        state[1][i] = _poly_mul_on_GF(0x09, a0) ^ _poly_mul_on_GF(0x0E, a1) ^ _poly_mul_on_GF(0x0B, a2) ^ _poly_mul_on_GF(0x0D, a3)
        state[2][i] = _poly_mul_on_GF(0x0D, a0) ^ _poly_mul_on_GF(0x09, a1) ^ _poly_mul_on_GF(0x0E, a2) ^ _poly_mul_on_GF(0x0B, a3)
        state[3][i] = _poly_mul_on_GF(0x0B, a0) ^ _poly_mul_on_GF(0x0D, a1) ^ _poly_mul_on_GF(0x09, a2) ^ _poly_mul_on_GF(0x0E, a3)
    return state


# --------------------------------------------------- AES 块生成函数 --------------------------------------------------- #
def _BytesToState(bytes_data: bytes) -> List[bytearray]:
    '''将 16 字节的 bytes 数据转换为 AES 状态矩阵（4x4 bytearray）'''
    if len(bytes_data) != 16: raise ValueError("输入必须是 16 字节的 bytes 数据")
    state: List[bytearray] = [bytearray(4) for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = bytes_data[i]
    return state

def _StateToBytes(state: List[bytearray]) -> bytes:
    '''将 4x4 状态矩阵转换为 16 字节的 bytes 对'''
    if len(state) != 4: raise ValueError("输入必须是 4x4 状态矩阵")
    bytes_data = bytearray(16)
    for i in range(16):
        bytes_data[i] = state[i % 4][i // 4]
    return bytes(bytes_data)


# ------------------------------------------------ AES 块加密与解密函数 ------------------------------------------------ #
def AESEncryptBlock(plaintext_block : bytes, key_bytes : bytes, key_size_in_bits : int) -> bytes:
    '''AES 加密单个 128 位数据块'''
    if len(plaintext_block) != 16:
        raise ValueError("明文块必须为 16 字节")
    if len(key_bytes) != key_size_in_bits // 8:
        raise ValueError(f"{len(key_bytes) * 8} 位密钥必须为 {key_size_in_bits//8}字节")
    
    round_keys : List[List[bytearray]]  = KeyExpansion(key_bytes, key_size_in_bits)
    state : List[bytearray] = _BytesToState(plaintext_block)
    state : List[bytearray] = _AddRoundKey(state, round_keys[0])
    
    Nk = key_size_in_bits // 32
    if Nk == 4: Nr = 10
    elif Nk == 6: Nr = 12
    elif Nk == 8: Nr = 14
    else : raise ValueError("密钥长度无效")
    
    for round_num in range(1, Nr):
        state = _SubBytes(state)
        state = _ShiftRows(state)
        state = _MixColumns(state)
        state = _AddRoundKey(state, round_keys[round_num])
    
    state = _SubBytes(state)
    state = _ShiftRows(state)
    state = _AddRoundKey(state, round_keys[Nr])
    
    return _StateToBytes(state)

def AESDecryptBlock(ciphertext_block : bytes, key_bytes : bytes, key_size_in_bits : int) -> bytes:
    '''AES 解密单个 128 位数据块'''
    if len(ciphertext_block) != 16:
        raise ValueError("密文块必须为16字节")
    if len(key_bytes) != key_size_in_bits // 8:
        raise ValueError(f"{len(key_bytes) * 8}位密钥必须为{key_size_in_bits//8}字节")
    
    round_keys : List[List[bytearray]] = KeyExpansion(key_bytes, key_size_in_bits)
    state : List[bytearray] = _BytesToState(ciphertext_block)
    state : List[bytearray] = _AddRoundKey(state, round_keys[-1])
    
    Nk = key_size_in_bits // 32
    if Nk == 4: Nr = 10
    elif Nk == 6: Nr = 12
    elif Nk == 8: Nr = 14
    else : raise ValueError("密钥长度无效")
    
    for round_num in range(Nr-1, 0, -1):
        state = _InvShiftRows(state)
        state = _InvSubBytes(state)
        state = _InvAddRoundKey(state, round_keys[round_num])
        state = _InvMixColumns(state)
    
    state = _InvShiftRows(state)
    state = _InvSubBytes(state)
    state = _InvAddRoundKey(state, round_keys[0])
    
    return _StateToBytes(state)


# --------------------------------------------------- 测试块加密/解密 --------------------------------------------------- #
def _show_ciphertext_block(ciphertext_block : bytes) -> None:
    '''打印密文块'''
    for j in range(4):
        for i in range(4):
            print(f"{ciphertext_block[i*4+j]:02x}", end=" ")
        print()
    print()

def _check_validity(is_show : bool = False) -> None:
    '''测试块加密/解密函数的正确性'''
    plaintext_block = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    key_bytes = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    key_size_in_bits = 128

    ciphertext_block = AESEncryptBlock(plaintext_block, key_bytes, key_size_in_bits)
    if is_show: _show_ciphertext_block(ciphertext_block)
    _std_res = bytes([0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32])
    if ciphertext_block == _std_res: print("加密函数正确")
    else: print("加密函数错误")
    decrypted_block = AESDecryptBlock(ciphertext_block, key_bytes, key_size_in_bits)
    if decrypted_block == plaintext_block: print("解密函数正确")
    else: print("解密函数错误")


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