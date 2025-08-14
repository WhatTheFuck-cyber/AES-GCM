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


# python -m KeyExpansion.KEF


# ---------------------------------------------- 本文件定义密钥扩展函数 ---------------------------------------------- #


# --------------------------------------------------- 头部库导入 --------------------------------------------------- #
from SBox.Box import SBOX  # bytearray 类型的输入和输出
from typing import List


# ---------------------------------------------------- 全局变量 ---------------------------------------------------- #
_Rcon = bytes([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])


# ---------------------------------------------------- 密钥扩展 ---------------------------------------------------- #
"""
def KeyExpansion(key_bytes: bytes, key_size_in_bits : int) -> list:
    '''没有经过优化的密钥扩展函数，用于理解密钥扩展算法'''
    # Nk: 原始密钥的32位字数量（128 位密钥→ 4，192 → 6，256 → 8）
    Nk = key_size_in_bits // 32
    # Nr: 加密总轮数（128 位 → 10 轮，192 → 12，25 6→ 14）
    if Nk == 4: Nr = 10
    elif Nk == 6: Nr = 12
    elif Nk == 8: Nr = 14
    # Nb：固定为 4（AES状态矩阵列数）
    Nb = 4
    
    # w: 扩展密钥数组，每个元素是长度为 4 字节的"字"，总长度为Nb*(Nr+1)
    w = [[0]*4 for _ in range(Nb * (Nr + 1))]  # 创建一个二维列表，每个元素是一个"字"
    
    # 用原始密钥初始化w的前Nk个字（拆分密钥为4字节一组）
    for i in range(Nk):
        w[i] = list(key_bytes[4*i : 4*(i+1)])
    
    # 扩展生成剩余密钥"字"，顾名思义，逐个"字"生成
    for i in range(Nk, Nb * (Nr + 1)):
        temp = list(w[i-1])
        
        # 1. 当 i 是 Nk 的倍数时，执行 RotWord + SubWord + 轮常量异或
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]  # RotWord：循环左移 1 位
            temp = [SBOX(b) for b in temp]  # SubWord：每个字节经 S 盒替换
            temp[0] ^= Rcon[i // Nk]  # 第一个字节与轮常量异或
        
        # 2. 256 位密钥（Nk = 8）的额外处理：i % Nk == 4时执行 SubWord
        elif Nk == 8 and i % 8 == 4:
            temp = [SBOX(b) for b in temp]
        
        # 3. 新字 = 前Nk个字对应位置的字 异或 temp
        w[i] = [w[i-Nk][j] ^ temp[j] for j in range(4)]
    
    # 将扩展密钥转换为轮密钥矩阵（4x4矩阵，列优先填充）
    round_keys_matrices = [None] * (Nr + 1)
    for round_num in range(Nr + 1):
        round_key_matrix = [[0]*4 for _ in range(4)]  # 轮密钥矩阵形式
        for c in range(4):
            word_from_w = w[round_num * Nb + c]
            for r in range(4):
                round_key_matrix[r][c] = word_from_w[r]
        round_keys_matrices[round_num] = round_key_matrix
    
    return round_keys_matrices  # 返回所有轮的密钥矩阵
"""

def _check_key_and_size_validity(key_bytes : bytes, key_size_in_bits : int) -> None:
    '''检查密钥和密钥大小是否有效'''
    if len(key_bytes) != key_size_in_bits // 8:
        print(len(key_bytes))
        print(key_size_in_bits // 8)
        raise ValueError("输入的密钥长度与输入的密钥不匹配")

def KeyExpansion(key_bytes: bytes, key_size_in_bits : int) -> List[List[bytearray]]:
    '''经过优化的密钥扩展函数，用于实际使用'''

    _check_key_and_size_validity(key_bytes, key_size_in_bits)

    # Nk: 原始密钥的32位字数量（128 位密钥→ 4，192 → 6，256 → 8）
    Nk = key_size_in_bits // 32
    # Nr: 加密总轮数（128 位 → 10 轮，192 → 12，25 6→ 14）
    if Nk == 4: Nr = 10
    elif Nk == 6: Nr = 12
    elif Nk == 8: Nr = 14
    else : raise ValueError("Invalid key size, key size must be 128, 192, or 256 bits")
    # Nb：固定为 4（AES状态矩阵列数）
    Nb = 4
    
    # w: 扩展密钥数组，每个元素是长度为 4 字节的"字"，总长度为Nb*(Nr+1)
    w = [bytearray(4) for _ in range(Nb * (Nr + 1))]  # 创建一个二维列表，每个元素是一个"字"
    
    # 用原始密钥初始化w的前Nk个字（拆分密钥为4字节一组）
    for i in range(Nk):
        w[i][:] = key_bytes[4*i : 4*(i+1)] 
    
    # 扩展生成剩余密钥"字"，顾名思义，逐个"字"生成
    for i in range(Nk, Nb * (Nr + 1)):
        temp = bytearray(w[i-1]) 
        
        # 1. 当 i 是 Nk 的倍数时，执行 RotWord + SubWord + 轮常量异或
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]  # RotWord：循环左移 1 位
            temp = bytearray([SBOX(bytearray([b]))[0] for b in temp])  # SubWord：每个字节经 S 盒替换
            temp[0] ^= _Rcon[i // Nk]  # 第一个字节与轮常量异或
        
        # 2. 256 位密钥（Nk = 8）的额外处理：i % Nk == 4时执行 SubWord
        elif Nk == 8 and i % 8 == 4:
            temp = bytearray([SBOX(bytearray([b]))[0] for b in temp])
        
        # 3. 新字 = 前Nk个字对应位置的字 异或 temp
        w[i] = bytearray([w[i-Nk][j] ^ temp[j] for j in range(4)])
    
    # 将扩展密钥转换为轮密钥矩阵（4x4矩阵，列优先填充）
    round_keys_matrices = [None] * (Nr + 1)
    for round_num in range(Nr + 1):
        round_key_matrix = [bytearray(4) for _ in range(4)]   # 轮密钥矩阵形式
        for c in range(4):
            word_from_w = w[round_num * Nb + c]
            for r in range(4):
                round_key_matrix[r][c] = word_from_w[r]
        round_keys_matrices[round_num] = round_key_matrix
    
    return round_keys_matrices  # 返回所有轮的密钥矩阵


# -------------------------------------------------- 密钥扩展验证 -------------------------------------------------- #
def _show_round_keys(round_keys_matrices: list) -> None:
    '''以十六进制格式打印轮密钥矩阵'''
    for round_num, round_matrix in enumerate(round_keys_matrices):
        print(f"===== 第 {round_num} 轮密钥 =====")
        for row in round_matrix:
            # 将每行的每个字节转换为两位十六进制（大写），用空格分隔
            hex_row = " ".join([f"{byte:02X}" for byte in row])
            print(hex_row)
        print()  # 轮之间空一行


def _check_validity(is_show : bool = False) -> None:
    '''验证自定义密钥扩展函数的正确性，只检查扩展密钥列表中的最后一个元素'''
    print("======== 128 bits ========")
    key1 = bytes([0x2b, 0x7e, 0x15, 0x16, 
                  0x28, 0xae, 0xd2, 0xa6, 
                  0xab, 0xf7, 0x15, 0x88, 
                  0x09, 0xcf, 0x4f, 0x3c])
    round_keys1 = KeyExpansion(key1, 128)
    if is_show: _show_round_keys(round_keys1)
    if bytes([0xb6, 0x63, 0x0c, 0xa6]) == bytes([round_keys1[10][r][3] for r in range(4)]): print("验证通过")

    print("======== 192 bits ========")
    key2 = bytes([0x8e, 0x73, 0xb0, 0xf7, 
                  0xda, 0x0e, 0x64, 0x52, 
                  0xc8, 0x10, 0xf3, 0x2b, 
                  0x80, 0x90, 0x79, 0xe5, 
                  0x62, 0xf8, 0xea, 0xd2, 
                  0x52, 0x2c, 0x6b, 0x7b])
    round_keys2 = KeyExpansion(key2, 192)
    if is_show: _show_round_keys(round_keys2)
    if bytes([0x01, 0x00, 0x22, 0x02]) == bytes([round_keys2[12][r][3] for r in range(4)]): print("验证通过")

    print("======== 256 bits ========")
    key3 = bytes([0x60, 0x3d, 0xeb, 0x10, 
                  0x15, 0xca, 0x71, 0xbe, 
                  0x2b, 0x73, 0xae, 0xf0, 
                  0x85, 0x7d, 0x77, 0x81, 
                  0x1f, 0x35, 0x2c, 0x07, 
                  0x3b, 0x61, 0x08, 0xd7, 
                  0x2d, 0x98, 0x10, 0xa3, 
                  0x09, 0x14, 0xdf, 0xf4])
    round_keys3 = KeyExpansion(key3, 256)
    if is_show: _show_round_keys(round_keys3)
    if bytes([0x70, 0x6c, 0x63, 0x1e]) == bytes([round_keys3[14][r][3] for r in range(4)]): print("验证通过")


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