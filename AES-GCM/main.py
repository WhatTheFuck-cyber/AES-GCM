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


# python main.py


# ------------------------------------- 本文件展示如何使用标准库与自定义库进行 AES-GCM 加 / 解密 ------------------------------------- #


from BlockOperation.Block import AESEncryptBlock
from GCMmodules.GCM import GCM

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

def aes_gcm_encrypt(key_hex, iv_hex, plaintext_hex, aad_hex):
    # 转换十六进制字符串为字节
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    plaintext = binascii.unhexlify(plaintext_hex) if plaintext_hex else b""
    aad = binascii.unhexlify(aad_hex) if aad_hex else b""
    
    # 初始化AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 处理附加数据（AAD）
    encryptor.authenticate_additional_data(aad)
    
    # 加密并生成标签
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    # 转换为十六进制字符串
    return binascii.hexlify(ciphertext).decode(), binascii.hexlify(tag).decode()

if __name__ == "__main__":
    print("------------------------------ CTR 使用示例 ------------------------------")
    key_hex1 = "2b7e151628aed2a6abf7158809cf4f302b7e151628aed2a6abf7158809cf4f30"  # 密钥随意 [128, 192, 256] 长度
    iv_hex1 = "111111111111111111111111000000000000000000000000"     
    plaintext_hex1 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"  # 明文随意长度
    aad_hex1 = ""  # 附加数据随意长度
    
    ciphertext_hex1, tag_hex1 = aes_gcm_encrypt(key_hex1, iv_hex1, plaintext_hex1, aad_hex1)
    print("===== 标准库测试 =====")
    print("密文（hex）:", ciphertext_hex1)
    print("标准标签（hex）:", tag_hex1)
    
    gcm1 = GCM(key = bytes.fromhex(key_hex1), IV = bytes.fromhex(iv_hex1), encrypt_block = AESEncryptBlock)
    print("===== 自定义测试 =====")
    c1, t1 = gcm1.Encrypt_Authenticate(add = bytes.fromhex(aad_hex1), plaintext = bytes.fromhex(plaintext_hex1))
    print("密文（hex）:", c1.hex())
    print("生成标签（hex）:", t1.hex())
    p1, v1 = gcm1.Decrypt_Verify(tag = t1, add = bytes.fromhex(aad_hex1), ciphertext = c1)
    print("数据完整性校验 :", v1)
    print("原始的明文（hex）:", plaintext_hex1)
    print("解密的明文 :", p1.hex())

    print()

    print("------------------------------ GMAC 使用示例 ------------------------------")
    key_hex2 = "2ace14e628ae65a6abf7888809cf4fdc2b7e151628aed786abf71fe8becf4f30"  # 密钥随意 [128, 192, 256] 长度
    iv_hex2 = "111111111111111111111111000000000000000000000000"
    plaintext_hex2 = ""
    aad_hex2 = "0000000000000000055354353000000085000000000000000000000000000496816500000000000045600000000000000000"  # 附加数据随意长度

    ciphertext_hex2, tag_hex2 = aes_gcm_encrypt(key_hex2, iv_hex2, plaintext_hex2, aad_hex2)
    print("===== 标准库测试 =====")
    print("标准标签（hex）:", tag_hex2)

    gcm2 = GCM(key = bytes.fromhex(key_hex2), IV = bytes.fromhex(iv_hex2), encrypt_block = AESEncryptBlock)
    print("===== 自定义测试 =====")
    c2, t2 = gcm2.Encrypt_Authenticate(add = bytes.fromhex(aad_hex2), plaintext = bytes.fromhex(plaintext_hex2))
    print("生成标签（hex）:", t2.hex())
    p2, v2 = gcm2.Decrypt_Verify(tag = t2, add = bytes.fromhex(aad_hex2), ciphertext = c2)
    print("数据完整性校验 :", v2)


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