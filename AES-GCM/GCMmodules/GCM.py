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


# python -m GCMmodules.GCM


# ------------------------------------------- 本文件定义 GCM 工作模式 ------------------------------------------- #
"""请注意，GCM 模式无需进行填充（可以进行填充，本文件不进行填充扩展）。加密的输入应当小于 64 GB，否则需要扩展 IV 的数量（本文件不进行 IV 扩展）。"""


# ------------------------------------------------- 头部库导入 ------------------------------------------------- #
import math
from typing import Callable, List, Tuple

class GCM:
    '''GCM 工作模式，类存有 key、IV、H、J0，其中 key 是强私有的，其余三个是弱私有的
       支持可变长度的 IV，支持任意长度的明文，支持任意长度的密文'''
    # ============================================================ 初始函数 ============================================================ #
    def __init__(self, key : bytes, IV : bytes, 
                 encrypt_block : Callable[[bytes, bytes, int], bytes]):  # GCM 是一个基于 CTR 的模式，只需要加密块即可，无需解密块
        '''初始化一个 GCM 对象'''
        len_key = len(key)
        if len_key not in [16, 24, 32]:
            raise ValueError('Invalid Key: key length must be 16, 24, or 32 bytes')

        self.__key = key  # 双下划线强私有：密钥
        self.__key_len_bits = len_key * 8  # 双下划线强私有：密钥长度（位）
        self._IV = IV  # 单下划线弱私有：初始向量
        self._IV_len_bits = len(IV) * 8  # 单下划线弱私有：初始向量长度（位）

        self.encrypt_block = encrypt_block  # 公共接口：块加密函数

        self._H = encrypt_block(bytes(16), self.__key, self.__key_len_bits)  # 单下划线弱私有：哈希密钥
        self._J0 = self._generate_J0()  # 单下划线弱私有：初始计数器

    # ============================================================ 辅助函数 ============================================================ #
    def _generate_J0(self) -> bytes:  
        '''生成 J0
        情况一：
            当 IV 的长度为 12 字节时，直接在 IV 后拼接 bytes.fromhex('00000001')
        情况二：
            当 IV 的长度不为 12 字节时，先将 IV 填充到 16 字节的整数倍，
            然后拼接 bytes.fromhex('0000000000000000')，
            最后再拼接 IV 的长度（IV 的字节数量，64 位）
        '''
        if len(self._IV) == 12:
            return self._IV + b'\x00\x00\x00\x01'
        else:
            IV_len = self._IV_len_bits.to_bytes(length=8, byteorder='big', signed=False)
            data = self._slicing(text = self._zero_padding(self._IV) + b'\x00\x00\x00\x00\x00\x00\x00\x00' + IV_len,
                                 group_size = 16, is_padding0 = False)
            return bytes(self._hash_block(data))

    def _hash_block(self, data : List[bytearray]) -> bytearray:
        ''' GCM 模式的哈希运算'''
        # 这个函数的计算效率其实很低，如需优化，建议将 data 转成 List[bytes] 类型
        # 之后再循环中就可以直接使用异或运算，而不是使用循环进行异或运算
        # 相应的，hash_block 应当初始化成一个整数，顺便也能直接转成 bytes 类型作为返回值
        hash_block = bytearray(16)
        for element in data:
            # 异或运算
            for i in range(16):
                hash_block[i] ^= element[i]
            # 乘法运算：
            hash_block_int = self._poly_mul(int.from_bytes(hash_block, byteorder='big', signed=False), 
                                            int.from_bytes(self._H, byteorder='big', signed=False))
            hash_block = bytearray(hash_block_int.to_bytes(length=16, byteorder='big', signed=False))
        return hash_block
    
    # ============================================================ 主体函数 ============================================================ #
    def _CTR_process(self, text : bytes) -> bytes:
        '''通用CTR模式处理函数，用于加密和解密的共同逻辑'''

        if len(text) == 0:
            print("Warning : text is empty, return empty bytes")
            return b''

        CTR_int = int.from_bytes(self._generate_J0(), byteorder='big', signed=False)

        text_blocks = self._slicing(text = text, group_size = 16, is_padding0 = False)
        res = [bytearray(16) for _ in range(len(text_blocks) - 1)]
        res.append(bytearray(len(text_blocks[-1])))

        for i, block in enumerate(text_blocks):
            # CTR 模式下的计数器自增是低 32 位的循环加法，高96位保持不变
            CTR_int = (((CTR_int & 0xFFFFFFFF) + 1) & 0xFFFFFFFF | ((CTR_int >> 32) << 32)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            # 请重点注意，CTR 模式下的密钥流生成在加密和解密时是相同的，也就是说，完全不需要解密算法！
            # 在 NIST GCM 文档中提到的 CTR 模式只需要 “正向的” 就是想表达这层意思！
            key_stream = self.encrypt_block( 
                    CTR_int.to_bytes(length=16, byteorder='big', signed=False),
                    self.__key,
                    self.__key_len_bits
                )
            for j in range(len(block)):
                res[i][j] = text_blocks[i][j] ^ key_stream[j]

        return b''.join(res)
    
    def _tag_generate(self, add : bytes, ciphertext : bytes = b'') -> bytes:
        '''生成认证码'''
        hash_val = b''
        enc_val = self.encrypt_block(self._generate_J0(), self.__key, self.__key_len_bits)

        add_len = (len(add) * 8).to_bytes(length=8, byteorder='big', signed=False)

        # GMAC 模式
        if ciphertext == b'':
            data = self._slicing(text = self._zero_padding(add) + add_len, group_size = 16, is_padding0 = True)
            hash_val = bytes(self._hash_block(data))
        # CTR 模式
        else:
            ciphertext_len = (len(ciphertext) * 8).to_bytes(length=8, byteorder='big', signed=False)
            ciphertext_padding = self._zero_padding(ciphertext)
            add_padding = self._zero_padding(add)

            joint_text_data = add_padding + ciphertext_padding
            joint_len_data = add_len + ciphertext_len
            data = self._slicing(joint_text_data + joint_len_data, 16, is_padding0 = False)
            hash_val = bytes(self._hash_block(data))
        
        return bytes([x ^ y for x, y in zip(hash_val, enc_val)])

    def _tag_verify(self, tag : bytes, add : bytes, ciphertext : bytes = b'', is_show = False) -> bool:
        '''验证认证码，常数时间比较，防止时序攻击'''
        generated_tag = self._tag_generate(add, ciphertext)
        if len(tag) != len(generated_tag):
            return False
        
        result = 0
        for a, b in zip(tag, generated_tag):
            result |= a ^ b
        if is_show: 
            print("比较标签（hex）:", generated_tag.hex())
            print("比较标签（bts）:", generated_tag, "|")
            print(f"比较结果 : {hex(result)}")
        return result == 0

    # ============================================================ 静态函数 ============================================================ #
    @staticmethod
    def _zero_padding(text : bytes, block_size : int = 16) -> bytes:
        '''用 0x00 填充尾部，使其长度为 block_size 的整数倍'''
        Len = len(text)
        last_block_size = Len % block_size

        if last_block_size != 0:
            return text + bytes(block_size - last_block_size)
        else:
            return text

    @staticmethod
    def _slicing(text : bytes, group_size : int = 16, is_padding0 : bool = False) -> List[bytearray]:
        '''将 text 数据按照 group_size 个 bytes 为一组进行切片，并决定是否使用 0x00 字节进行填充。
           返回一个 List[bytearray] 类型的对象，便于后续操作。'''
        Len = len(text)

        # 空对象特殊处理，提高代码的兼容性
        if Len == 0:
            print("Warning: The length of text is 0, so the result is an empty list.")
            return []
        
        times = math.ceil(Len / group_size)  # 计算切片次数
        res = [bytearray(group_size) for _ in range(times - 1)]  # 预分配空间

        for i in range(times - 1):
            res[i] = bytearray(text[i * group_size : (i + 1) * group_size])

        # 处理最后一个块
        last_block = bytearray(text[(times - 1) * group_size:])
        last_block_size = len(last_block)

        # 最后一个切片可能不满 16 字节，可能需要填充 0x00 字节
        if is_padding0 and last_block_size != group_size:
            last_block += bytearray(group_size - last_block_size)

        res.append(last_block)
        return res
    
    @staticmethod
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

    # ============================================================ 对外接口 ============================================================ #
    def Encrypt_Authenticate(self, add : bytes, plaintext : bytes = b'') -> Tuple[bytes, bytes] :
        '''加密并生成认证标签
        参数:
            add: 附加认证数据
            plaintext: 明文数据
        返回:
            密文和认证标签的元组
        '''
        if len(plaintext) > 2 ** 36:
            raise ValueError("The length of plaintext is too long. It must be less than 2 ** 36.")
        
        ciphertext = b'' if plaintext == b'' else self._CTR_process(plaintext)
        tag = self._tag_generate(add, ciphertext)
        return ciphertext, tag
    
    def Decrypt_Verify(self, tag : bytes, add : bytes, ciphertext : bytes = b'') -> Tuple[bytes, bool]:
        '''解密并验证认证标签
        参数:
            tag: 待验证的认证标签
            add: 附加认证数据
            ciphertext: 密文数据
        返回:
            明文和验证结果的元组
        '''
        if len(ciphertext) > 2 ** 36:
            raise ValueError("The length of ciphertext is too long. It must be less than 2 ** 36.")
        
        is_valid = self._tag_verify(tag, add, ciphertext)
        if is_valid:
            plaintext = b'' if ciphertext == b'' else self._CTR_process(ciphertext)
        else:
            print("Warning: The authentication tag is invalid. The decryption result is undefined.")
            plaintext = b''
        return plaintext, is_valid
    

# ----------------------------------------------------- 测试 ----------------------------------------------------- #
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from BlockOperation.Block import AESEncryptBlock
import random
import os

def _std_aes_gcm_encrypt(key : bytes, iv : bytes, plaintext : bytes, aad : bytes) -> Tuple[str, str]:
    '''标准库实现 AES-GCM 加密'''
    # 初始化AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 处理附加数据（AAD）
    encryptor.authenticate_additional_data(aad)
    
    # 加密并生成标签
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return ciphertext, tag

def _check_vadility(times : int = 1, is_show : bool = False) -> None:
    '''测试 GCM 的正确性'''
    invalid_tag_times = 0
    invalid_ciphertext_times = 0
    valid_times = 0
    GMAC_valid_times = 0
    GMAC_invalid_times = 0
    for _ in range(times):
        print("==================== IV 为96 bits 的测试 ====================")
        print("========== ADD 为空的测试 ==========")
        for bytes_size in [16, 24, 32]:
            key = os.urandom(bytes_size)
            iv = os.urandom(12)
            add = b''
            plaintext = os.urandom(random.randint(10000, 100000))

            ciphertext_std, tag_std = _std_aes_gcm_encrypt(key, iv, plaintext, add)

            gcm = GCM(key, iv, encrypt_block=AESEncryptBlock)
            ciphertext_self, tag_self = gcm.Encrypt_Authenticate(add, plaintext)

            if is_show:
                print(f"当前测试密钥长度为 {bytes_size * 8} bits.")
                print("key: ", key.hex())
                print("iv: ", iv.hex())
                print("plaintext: ", plaintext.hex())
                print("ciphertext_std : ", ciphertext_std.hex())
                print("ciphertext_self: ", ciphertext_self.hex())
                print("tag_std : ", tag_std.hex())
                print("tag_self: ", tag_self.hex())

            if ciphertext_std == ciphertext_self :
                if tag_std == tag_self:
                    print("测试通过")
                    valid_times += 1
                else:
                    print("测试失败，认证标签不同")
                    invalid_tag_times += 1
            else:
                print("测试失败，密文不同，认证标签未定义")
                invalid_ciphertext_times += 1
            print()
        print()
        print("========== ADD 不为空的测试 ==========")
        for bytes_size in [16, 24, 32]:
            key = os.urandom(bytes_size)
            iv = os.urandom(12)
            add = os.urandom(random.randint(1000, 10000))
            plaintext = os.urandom(random.randint(10000, 100000))

            ciphertext_std, tag_std = _std_aes_gcm_encrypt(key, iv, plaintext, add)

            gcm = GCM(key, iv, encrypt_block=AESEncryptBlock)
            ciphertext_self, tag_self = gcm.Encrypt_Authenticate(add, plaintext)

            if is_show:
                print(f"当前测试密钥长度为 {bytes_size * 8} bits.")
                print("key: ", key.hex())
                print("iv: ", iv.hex())
                print("plaintext: ", plaintext.hex())
                print("add: ", add.hex())
                print("ciphertext_std: ", ciphertext_std.hex())
                print("ciphertext_self: ", ciphertext_self.hex())
                print("tag_std: ", tag_std.hex())
                print("tag_self: ", tag_self.hex())

            if ciphertext_std == ciphertext_self :
                if tag_std == tag_self:
                    print("测试通过")
                    valid_times += 1
                else:
                    print("测试失败，认证标签不同")
                    invalid_tag_times += 1
            else:
                print("测试失败，密文不同，认证标签未定义")
                invalid_ciphertext_times += 1
            print()
        print()
        print("==================== IV 不为96 bits 的测试 ====================")
        print("========== CTR 模式 ==========")
        for bytes_size in [16, 24, 32]:
            key = os.urandom(bytes_size)
            iv = os.urandom(random.randint(8, 128))
            add = os.urandom(random.randint(1000, 10000))
            plaintext = os.urandom(random.randint(10000, 100000))

            ciphertext_std, tag_std = _std_aes_gcm_encrypt(key, iv, plaintext, add)

            gcm = GCM(key, iv, encrypt_block=AESEncryptBlock)
            ciphertext_self, tag_self = gcm.Encrypt_Authenticate(add, plaintext)

            if is_show:
                print(f"当前测试密钥长度为 {bytes_size * 8} bits.")
                print("key: ", key.hex())
                print("iv: ", iv.hex())
                print("plaintext: ", plaintext.hex())
                print("add: ", add.hex())
                print("ciphertext_std: ", ciphertext_std.hex())
                print("ciphertext_self: ", ciphertext_self.hex())
                print("tag_std: ", tag_std.hex())
                print("tag_self: ", tag_self.hex())

            if ciphertext_std == ciphertext_self :
                if tag_std == tag_self:
                    print("测试通过")
                    valid_times += 1
                else:
                    print("测试失败，认证标签不同")
                    invalid_tag_times += 1
            else:
                print("测试失败，密文不同，认证标签未定义")
                invalid_ciphertext_times += 1
            print()
        print("========== GMAC 模式 ==========")
        for bytes_size in [16, 24, 32]:
            key = os.urandom(bytes_size)
            iv = os.urandom(random.randint(8, 128))
            add = os.urandom(random.randint(1000, 10000))
            plaintext = b''

            ciphertext_std, tag_std = _std_aes_gcm_encrypt(key, iv, plaintext, add)

            gcm = GCM(key, iv, encrypt_block=AESEncryptBlock)
            ciphertext_self, tag_self = gcm.Encrypt_Authenticate(add, plaintext)

            if is_show:
                print(f"当前测试密钥长度为 {bytes_size * 8} bits.")
                print("key: ", key.hex())
                print("iv: ", iv.hex())
                print("add: ", add.hex())
                print("tag_std: ", tag_std.hex())
                print("tag_self: ", tag_self.hex())

            if tag_std == tag_self:
                print("测试通过")
                GMAC_valid_times += 1
            else:
                print("测试失败，认证标签不同")
                GMAC_invalid_times += 1
            print()
        print()

    print("========== 测试结果 ==========")
    print("CTR 模式 :", valid_times, "次成功，", invalid_tag_times, "次认证标签错误，", invalid_ciphertext_times, "次密文错误")
    print("GMAC 模式 :", GMAC_valid_times, "次成功", GMAC_invalid_times, "次认证标签错误")


# ----------------------------------------------------- main ----------------------------------------------------- #
if __name__ == '__main__':
    _check_vadility(times = 100, is_show=False)                               


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