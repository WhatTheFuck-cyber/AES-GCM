**<span style='color:blue'>本文件简单介绍一些 python 基础语法知识</span>**

# 1 字节类型

在Python中，`bytes`和`bytearray`都是用于处理二进制数据的类型，前者不可变，后者可变，用法类似但适用场景不同。


### 一、`bytes`：不可变字节序列
`bytes`一旦创建就不能修改，适合存储固定的二进制数据（如常量、密钥、预定义的S盒等）。

#### 1. 创建`bytes`
```python
# 1. 直接用字节值列表创建（元素必须是0~255的整数）
b1 = bytes([0x63, 0x7c, 0x77, 0x7b])  # 结果：b'\x63|w{'
print(b1)  # 输出：b'\x63|w{'

# 2. 用字符串+编码创建（需指定编码，如ASCII、UTF-8）
b2 = "abc".encode('utf-8')  # 结果：b'abc'（每个字符对应ASCII值）

# 3. 用十六进制字符串创建（需配合binascii模块）
import binascii
b3 = binascii.unhexlify("637c777b")  # 结果：b'\x63|w{'（与b1等价）

# 4. 创建指定长度的空字节（默认填充0x00）
b4 = bytes(4)  # 结果：b'\x00\x00\x00\x00'
```

#### 2. 访问和切片（类似列表，但不能修改）
```python
b = bytes([0x63, 0x7c, 0x77, 0x7b])

# 访问单个字节（返回整数）
print(b[0])  # 输出：99（0x63的十进制）
print(hex(b[1]))  # 输出：0x7c

# 切片（返回新的bytes）
print(b[1:3])  # 输出：b'|w'（对应0x7c、0x77）
```

#### 3. 常用操作
```python
b = b'\x63|w{'

# 长度
print(len(b))  # 输出：4

# 拼接（返回新的bytes）
b_new = b + bytes([0xf2])  # 结果：b'\x63|w{\xf2'

# 转换为列表（便于查看所有字节值）
print(list(b))  # 输出：[99, 124, 119, 123]（对应0x63,0x7c,0x77,0x7b）
```


### 二、`bytearray`：可变字节序列
`bytearray`可以修改其中的元素，适合存储需要动态更新的二进制数据（如加密过程中的状态矩阵、中间结果等）。

#### 1. 创建`bytearray`
```python
# 1. 用字节值列表创建
ba1 = bytearray([0x63, 0x7c, 0x77, 0x7b])  # 结果：bytearray(b'\x63|w{')

# 2. 用bytes转换
b = bytes([0x63, 0x7c])
ba2 = bytearray(b)  # 结果：bytearray(b'\x63|')

# 3. 创建指定长度的空字节（默认填充0x00）
ba3 = bytearray(4)  # 结果：bytearray(b'\x00\x00\x00\x00')
```

#### 2. 访问、修改和切片（支持原地修改）
```python
ba = bytearray([0x63, 0x7c, 0x77, 0x7b])

# 访问单个字节
print(ba[0])  # 输出：99

# 修改单个字节（直接赋值，必须是0~255的整数）
ba[1] = 0x7d  # 0x7c → 0x7d
print(ba)  # 输出：bytearray(b'\x63}w{')

# 切片修改（替换一段字节）
ba[2:4] = [0x7f, 0x80]  # 替换后：bytearray(b'\x63}\x7f\x80')

# 切片访问（返回bytes）
print(ba[1:3])  # 输出：b'}\x7f'
```

#### 3. 常用操作
```python
ba = bytearray([0x63, 0x7c, 0x77])

# 长度
print(len(ba))  # 输出：3

# 追加字节
ba.append(0x7b)  # 结果：bytearray(b'\x63|w{')

# 插入字节
ba.insert(1, 0x00)  # 在索引1处插入0x00，结果：bytearray(b'\x63\x00|w{')

# 删除字节
del ba[1]  # 删除索引1的0x00，结果：bytearray(b'\x63|w{')

# 转换为bytes（不可变）
b = bytes(ba)  # 结果：b'\x63|w{'
```


### 三、适用场景总结
| 类型         | 不可变/可变 | 适合场景                     | 核心优势                     |
|--------------|-------------|------------------------------|------------------------------|
| `bytes`      | 不可变      | 存储固定二进制数据（如S盒、密钥） | 安全（防止意外修改）、空间紧凑 |
| `bytearray`  | 可变        | 动态处理二进制数据（如加密中间态） | 支持原地修改，操作灵活        |


### 四、注意事项
在操作`bytes`和`bytearray`时，要注意使用`[i]`进行取数（将字节取出为整数）后才能参与运算操作


# 2 十六进制字节
在Python中，要以十六进制形式查看`bytes`或`bytearray`的内容，可以通过以下几种方法实现，每种方法适用于不同场景：


### 一、基础方法：`hex()` 函数（最常用）
`bytes`和`bytearray`都内置了`hex()`方法，直接返回一个十六进制字符串（小写），每个字节对应两位十六进制数。

```python
# 定义一个字节序列
b = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2])
ba = bytearray([0x00, 0xab, 0xcd, 0xef])

# 转换为十六进制字符串
print(b.hex())    # 输出：'637c777bf2'
print(ba.hex())   # 输出：'00abcdef'
```

- 如需大写字母，可结合`upper()`：
  ```python
  print(b.hex().upper())  # 输出：'637C777BF2'
  ```


### 二、格式化输出：`format()` 或 f-string
对单个字节（整数），可用`format()`或f-string指定十六进制格式（`02x`表示两位小写，`02X`表示两位大写）。

#### 1. 遍历字节序列并格式化
```python
b = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2])

# 方法1：用f-string遍历
hex_str = ' '.join(f'{x:02x}' for x in b)
print(hex_str)  # 输出：'63 7c 77 7b f2'（带空格分隔，更易读）

# 方法2：大写格式
hex_str_upper = ' '.join(f'{x:02X}' for x in b)
print(hex_str_upper)  # 输出：'63 7C 77 7B F2'
```

#### 2. 按固定宽度分组（如AES中的16字节分组）
适合查看加密数据（如128位AES的块数据）：
```python
# 16字节的示例数据（AES块大小）
aes_block = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])

# 每4字节一组，每组内用空格分隔，组间用换行分隔
hex_lines = []
for i in range(0, len(aes_block), 4):
    group = aes_block[i:i+4]
    hex_group = ' '.join(f'{x:02x}' for x in group)
    hex_lines.append(hex_group)

print('\n'.join(hex_lines))
# 输出：
# 32 43 f6 a8
# 88 5a 30 8d
# 31 31 98 a2
# e0 37 07 34
```


### 三、使用`binascii`模块（更灵活）
`binascii`模块提供了更多十六进制转换工具，例如`hexlify()`（类似`hex()`，但返回`bytes`类型）。

```python
import binascii

b = bytes([0x63, 0x7c, 0x77, 0x7b])

# 转换为十六进制bytes（需解码为字符串）
hex_bytes = binascii.hexlify(b)
print(hex_bytes)        # 输出：b'637c777b'
print(hex_bytes.decode())  # 输出：'637c777b'（转为字符串）
```

**<span style='color:blue'>请注意，bytes类型类似C++中的</span>**
```Cpp
const type* pointer
```
**<span style='color:blue'>仅能够访问，不能够修改。</span>**

**<span style='color:blue'>请注意，bytearray类型类似C++中的引用传参</span>**

# 3 bin 和 bit_length
`bin()` 和 `bit_length()` 是Python中用于处理二进制和位数的内置函数。

### 一、`bin()`：将整数转换为二进制字符串
`bin()`函数将整数转换为以`'0b'`开头的二进制字符串。

```python
# 示例
num = 10
binary_str = bin(num)
print(binary_str)  # 输出：'0b1010'
```

### 二、`bit_length()`：计算二进制表示的位数
`bit_length()`函数返回整数在二进制表示中需要的位数（不包括前缀`'0b'`）。

```python
# 示例
num = 10
bit_length = num.bit_length()
print(bit_length)  # 输出：4
```

### 三、区别
- `bin()`：将整数转换为二进制字符串，包含前缀`'0b'`。
- `bit_length()`：返回整数在二进制表示中的位数，不包含前缀`'0b'`。

### 四、示例
```python
# 示例
num = 10
binary_str = bin(num)
bit_length = num.bit_length()

print(binary_str)  # 输出：'0b1010'
print(bit_length)  # 输出：4
print(len()(binary_str) - 2)  # 输出：4（去掉前缀'0b'后的长度）
```

# 4 range
`range()`函数用于生成一个指定范围的整数序列，常用于循环、切片等场景。

### 一、基本用法
`range(start, stop, step)`：
- `start`：序列的起始值（默认为0）。
- `stop`：序列的结束值（不包括在内）。
- `step`：序列的步长（默认为1）。

### 二、示例
```python
# 生成从0到9的整数序列
for i in range(10):
    print(i)  # 输出：0 1 2 3 4 5 6 7 8 9

# 生成从1到10的整数序列（步长为2）
for i in range(1, 11, 2):
    print(i)  # 输出：1 3 5 7 9

# 生成从10到0的整数序列（步长为-1）
for i in range(10, -1, -1):
    print(i)  # 输出：10 9 8 7 6 5 4 3 2 1 0
```