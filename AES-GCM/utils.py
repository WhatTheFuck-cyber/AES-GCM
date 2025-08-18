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


# python utils.py


# ------------------------------------- 本文件定义了一些 GCM 的扩展函数，仅作算法演示 ------------------------------------- #


# -------------------------------------------------- 确定性 IV 生成算法 -------------------------------------------------- #
_CTR : int = 0  # 全局起始的 CTR，用于构造短 IV

def short_IV_construct(expected_length : int, fixed_field : bytes, construct_mode : str = 'CTR', reg_len : int = 0, init_state : int = 0, poly : int = 0) -> bytes:
    '''长度低于 96 bits 的 IV 需要使用确定性构造方法。
    输入：
       expected_length : 需要的 IV 长度 （单位：bits）
       fixed_field : 固定字段
       construct_mode : 构造模式，目前支持 CTR 和 LFSR 模式
    输出：
       构造好的 IV
    注意：
       需要确保正在通信得设备之间的固定字段完全不一样
    '''
    assert expected_length > 0('IV 长度非法')
    if expected_length < 64:
        raise ValueError('IV 得长度必须大于等于 64 bits')
    elif expected_length > 96:
        raise ValueError('长度超过了 96 bits 的 IV 不需要使用此方法')
    
    if expected_length % 8 != 0:
        raise ValueError('IV 长度必须是 8 的倍数')
    
    len_of_field = (expected_length // 8) - len(fixed_field)

    if construct_mode == 'CTR':
        global _CTR
        bytes_CTR = (_CTR).to_bytes(len_of_field, byteorder='big')
        _CTR += 1
        return fixed_field + bytes_CTR
    elif construct_mode == 'LFSR':
        if reg_len == 0 or init_state == 0 or poly == 0: raise ValueError('LFSR 模式需要指定寄存器长度、初始状态和反馈多项式')
        lfsr = LFSR(reg_len = reg_len, init_state = init_state, poly = poly)
        bytes_sequence = lfsr.generate_sequence(gen_len = len_of_field)
        return fixed_field + bytes_sequence
    else: raise ValueError('不支持的构造模式')

# 以下是辅助函数
class LFSR:
    '''线性反馈移位寄存器 LFSR 算法实现。如需继续生成序列，无需重新初始化。
       LFSR 是一种通过移位和线性反馈生成伪随机序列的电路 / 算法
       其核心优势是能在有限长度下生成周期足够长且无重复的序列
    '''
    def __init__(self, reg_len : int, init_state : int, poly : int):
        '''初始化 LFSR 寄存器
        输入：
           reg_len : 寄存器长度
           init_state : 初始状态值
           poly : 反馈多项式（系数二进制码，如 3 位寄存器的 x³+x+1 对应 0b1011，
                那么每次从 state 中取 bits 的索引与 poly 位为 1 的位置一样）'''
        if init_state == 0: raise ValueError('初始状态值不能为 0')
        if reg_len < 2: raise ValueError('寄存器长度必须大于等于 2')
        if (poly >> reg_len) & 1 != 1: raise ValueError('寄存器长度与反馈多项式不匹配，反馈多项式的最高次幂必须等于寄存器长度')
        if init_state.bit_length() > reg_len: raise ValueError('初始状态值长度超过寄存器长度')

        self._state = init_state
        self.init_state = init_state  # 保留，仅记录初始状态值，方便检查
        self.len = reg_len
        self.poly = poly
    
    def _get_bits(self) -> list:
        '''根据 poly 获取抽出的位，返回 0-base 索引格式'''
        bits = []
        for i in range(self.len):
            if (self.poly >> i) & 1 == 1:
                bits.append(i)
        return bits

    def _shift_bit(self) -> int:
        '''移位操作，输出 1 bit'''
        list_bits = self._get_bits()
        feedback = 0
        for item in list_bits:
            feedback ^= (self._state >> item) & 1
        last_bit = self._state & 1
        self._state = (self._state >> 1) | (feedback << (self.len - 1))
        return last_bit
    
    def generate_sequence(self, gen_len : int) -> bytes:
        '''生成指定长度的序列，返回 bytes 格式'''
        if gen_len < 1:
            print('警告：序列长度必须大于 0')
            return b''
        elif gen_len % 8 != 0:
            print('警告：序列长度必须是 8 的倍数')
            return b''
        sequence = 0
        for _ in range(gen_len):
            sequence = (sequence << 1) | self._shift_bit()
        return sequence.to_bytes(gen_len // 8, byteorder='big')
    

# ----------------------------------------------- 超过 64 GB 的加密 / 解密算法 ----------------------------------------------- #
def aes_gcm_large_encrypt_authenticate(key : bytes, iv_base : Union[bytes, List[bytes]], 
                          plaintext : bytes, add : bytes, 
                          block_size : int = 64, strategy : str = 'base') -> bytes:
    '''超过 64 GB 的数据需要分块处理，每次处理 block_size GB 的数据，剩余不足 block_size GB 的数据单独处理'''
    if len(plaintext) < 64 * 1024 * 1024 * 1024:
        print('数据量小于 64 GB，无需使用此方法，主动退出函数')
        return None
    
    if strategy != 'base' or strategy != 'random':
        raise ValueError('不支持的 IV 策略')
    
    plaintext = _partitioning(plaintext, block_size)
    plaintext_block_num = len(plaintext)
    if plaintext_block_num > 2 ** 32:
        raise ValueError('数据块数量超过 2^32，无法使用此方法')
    
    IV = []
    if strategy == 'base':
        for block_num in range(1, plaintext_block_num + 1):
            IV.append(iv_base + block_num.to_bytes(4, byteorder='big'))
    elif strategy == 'random':
        if (isinstance(iv_base, list) and all(isinstance(item, bytes) for item in iv_base)) == False:
            raise ValueError('IV 基础值必须是字节列表（List[bytes]）')
        if plaintext_block_num > len(iv_base):
            raise ValueError(f'IV 个数不足，理论上需要 {plaintext_block_num} 个 IV，但只有 {len(iv_base)} 个')
        for block_num in range(1, plaintext_block_num + 1):
            IV.append(iv_base[block_num - 1] + block_num.to_bytes(4, byteorder='big'))

    ciphertext = []
    tag = []
    for i in range(plaintext_block_num):
        c, t = _aes_gcm_encrypt(key, IV[i], plaintext[i], b'')  # 不认证 add，最后再认证
        ciphertext.append(c)
        tag.append(t)
    
    Ciphertext = b''.join(ciphertext)
    Tag_ = b''.join(tag)

    Tag = _Hash(add, Tag_, _get_Hash_key(key))
    return Ciphertext + Tag

# 以下是辅助函数
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import List, Union, Tuple
import math

def _poly_mul(x: int, y: int, R: int = (0xE1 << 120)) -> int:
    '''本函数是 NIST GCM 文档中特别定义的乘法函数，不是 GF 上的乘法'''
    z = 0
    x &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 确保128位
    y &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 确保128位

    for i in range(128):
        bit = (x >> (127 - i)) & 1  
        if bit:
            z ^= y
        
        if y & 1:  
            y = (y >> 1) ^ R
        else:       
            y >>= 1
    return z & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

def _aes_gcm_encrypt(key : bytes, iv : bytes, plaintext : bytes, aad : bytes) -> Tuple[bytes, bytes]:
    '''这里直接使用了标准库的 AES-GCM，仅作算法演示。可以直接将 GCM 类集成到本函数里'''
    # 初始化AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 处理附加数据（AAD）
    encryptor.authenticate_additional_data(aad)
    
    # 加密并生成标签
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return ciphertext, tag

def _zero_padding(text : bytes, block_size : int = 16) -> bytes:
    '''用 0x00 填充尾部，使其长度为 block_size 的整数倍'''
    Len = len(text)
    last_block_size = Len % block_size

    if last_block_size != 0:
        return text + bytes(block_size - last_block_size)
    else:
        return text

def _get_Hash_key(key : bytes) -> bytes:
    '''获取哈希密钥'''
    empty_block = b'\x00' * 16 
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(empty_block) + encryptor.finalize()

def _Hash(add : bytes, tag : bytes, _H : bytes) -> bytes:
    '''哈希函数，将多个标签合并成一个。注意，本哈希函数是可自行选择的，这里选择的是 NIST GCM 文档中的 GHASH 函数。
    注意：对于 GHASH 函数的输入，是将 add 进行 0 填充后再拼接 tag ，最后拼接 add 的长度（128 bits）和 tag 的长度（128 bits） [长度均指代比特数]
    '''
    add_len = len(add) * 8
    add = _zero_padding(add)
    tag_len = len(tag) * 8
    data = add + tag + add_len.to_bytes(16, byteorder='big') + tag_len.to_bytes(16, byteorder='big')
    data_list = [data[i:i+16] for i in range(0, len(data), 16)]

    hash_block = 0
    for element in data_list:
        # 异或运算
        hash_block = (element ^ hash_block) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        # 乘法运算：
        hash_block = _poly_mul(hash_block, int.from_bytes(_H, byteorder='big', signed=False))

    return bytes(hash_block)

def _partitioning(text : bytes, block_size : int) -> List[bytes]:
    '''将数据分块，每块大小为 block_size GB'''
    block_size = block_size * 1024 * 1024 * 1024
    res = []
    block_num = math.ceil(len(text) / block_size)
    for i in range(block_num - 1):
        res.append(text[i * block_size : (i + 1) * block_size])
    res.append(text[(block_num - 1) * block_size : ])
    return res


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