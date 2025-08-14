# 1 特别说明

- **<span style='color:blue'>GCM 模式是一种基于计数器（CTR）的工作模式，其只需要加密函数即可</span>**

- **原因很简单，CTR 模式的工作流程是使用加密算法生成密钥流，然后将密钥流与明文作异或操作，最后得到密文。所以说要保证解密时采用相同的密钥流，那么解密时依旧需要使用加密算法进行密钥流生成**

- GCM 模式同时提供加密和认证功能，通过将 CTR 模式的加密与 GHASH 函数的认证结合，可同时保证数据的机密性和完整性

- 本实现支持可变长度的 IV（限定长度范围为8 - 128 字节）、任意长度的明文和密文(不能超过 64 GB)，密钥长度严格限制为 16/24/32 字节（对应 AES-128/192/256）


# 2 \(J_{0}\)的计算方式

\(J_0\) 是 GCM 模式中计数器的初始值，其计算方式根据 IV 长度分为两种情况，具体实现见 `_generate_J0` 方法：

1. **当 IV 长度为 12 字节时**（推荐长度，NIST 标准推荐）：  
   直接在 IV 后拼接 4 字节的 `0x00000001`，即：  
   \(J_0 = IV \mathbin{\|} 0x00000001\)  
   代码实现：`return self._IV + b'\x00\x00\x00\x01'`

2. **当 IV 长度不为 12 字节时**：  
   需通过 GHASH 函数计算，步骤如下：  
   - 对 IV 进行零填充（`_zero_padding`），使其长度为 16 字节的整数倍  
   - 拼接 8 字节的零（`b'\x00\x00\x00\x00\x00\x00\x00\x00'`）  
   - 拼接 IV 的长度（64 位 big-endian 表示，`IV_len_bits.to_bytes(8, 'big')`）  
   - 对上述拼接结果按 16 字节分组（`_slicing`），通过 GHASH 函数（`_hash_block`）计算得到 \(J_0\)  


# 3 \(GHASH\)函数的实现

GHASH 是 GCM 模式的核心认证函数，用于计算基于伽罗瓦域（GF(2???)）的哈希值，实现见 `_hash_block` 方法，核心逻辑如下：

1. **哈希密钥 \(H\) 的生成**：  
   \(H\) 是通过加密全零块得到的固定值，即 \(H = \text{encrypt\_block}(0^{128}, key)\)，代码中通过 `self._H = encrypt_block(bytes(16), self.__key, self.__key_len_bits)` 初始化。

2. **迭代计算过程**：  
   - 初始哈希块为 16 字节的零（`bytearray(16)`）  
   - 对输入的每个 16 字节分组（`data` 中的元素），执行：  
     a. 与当前哈希块进行异或操作（`hash_block[i] ^= element[i]`）  
     b. 异或结果与 \(H\) 进行多项式乘法（`_poly_mul`），更新哈希块  
   - 最终得到的哈希块即为 GHASH 结果

3. **多项式乘法（`_poly_mul`）**：  
   遵循 NIST GCM 规范的特殊乘法规则，在 GF(2???) 域中进行，使用不可约多项式 \(R = 0xE1 || 0^{120}\) 进行模运算，确保结果为 128 位值。


# 4 CTR模式的实现

CTR 模式是 GCM 中的加密/解密核心，实现见 `_CTR_process` 方法，逻辑如下：

1. **计数器生成**：  
   以 \(J_0\) 为初始计数器，每次处理一个块时，计数器低 32 位加 1（`CTR_int = (((CTR_int & 0xFFFFFFFF) + 1) & 0xFFFFFFFF | ((CTR_int >> 32) << 32)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`），保证计数器唯一性。

2. **密钥流生成**：  
   对每个计数器值（16 字节）使用加密函数（`encrypt_block`）生成密钥流（`key_stream`）。

3. **加解密过程**：  
   - 将明文/密文按 16 字节分组（`_slicing`）  
   - 每个分组与对应密钥流进行异或操作（`res[i][j] = text_blocks[i][j] ^ key_stream[j]`）  
   - 拼接所有分组结果，得到密文/明文  

   注：CTR 模式中加密与解密逻辑完全一致，仅需使用加密函数生成密钥流，无需解密函数。


# 5 GMAC模式的实现

GMAC 是 GCM 模式在明文为空时的特殊情况（仅提供认证功能），实现见 `_tag_generate` 方法中 `ciphertext == b''` 的分支，逻辑如下：

1. **输入处理**：  
   - 对附加认证数据（AAD）进行零填充（`_zero_padding(add)`），使其长度为 16 字节的整数倍  
   - 拼接 AAD 的长度（64 位 big-endian 表示，`add_len = (len(add) * 8).to_bytes(8, 'big')`）  
   - 拼接 8 字节的零（`b'\x00\x00\x00\x00\x00\x00\x00\x00'`）

2. **GHASH 计算**：  
   对上述拼接结果按 16 字节分组（`_slicing`），通过 `_hash_block` 计算哈希值（`hash_val`）。

3. **标签生成**：  
   将哈希值与加密后的 \(J_0\)（`enc_val = encrypt_block(self._generate_J0(), ...)`）进行异或，得到最终认证标签：`bytes([x ^ y for x, y in zip(hash_val, enc_val)])`。


# 6 加密认证与认证解密过程

## 6.1 加密认证（`Encrypt_Authenticate`）  
流程：  
1. 若明文非空，使用 CTR 模式加密明文得到密文（`self._CTR_process(plaintext)`）；若明文为空，密文也为空  
2. 结合附加认证数据（AAD）和密文，通过 `_tag_generate` 生成认证标签  
3. 返回（密文，标签）元组  

核心逻辑：`ciphertext = b'' if plaintext == b'' else self._CTR_process(plaintext); tag = self._tag_generate(add, ciphertext)`


## 6.2 认证解密（`Decrypt_Verify`）  
流程：  
1. 调用 `_tag_verify` 验证输入标签的有效性：  
   - 生成与加密端相同的标签（`generated_tag = self._tag_generate(add, ciphertext)`）  
   - 使用常数时间比较（`result |= a ^ b`）防止时序攻击，确保验证安全性  
2. 若标签有效，使用 CTR 模式解密密文得到明文（`self._CTR_process(ciphertext)`）；若无效，返回空明文和验证失败标志  
3. 返回（明文，验证结果）元组  

核心逻辑：`is_valid = self._tag_verify(tag, add, ciphertext); plaintext = self._CTR_process(ciphertext) if is_valid else b''`