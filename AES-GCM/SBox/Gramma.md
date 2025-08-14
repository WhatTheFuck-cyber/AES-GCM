**<span style='color:blue'>���ļ��򵥽���һЩ python �����﷨֪ʶ</span>**

# 1 �ֽ�����

��Python�У�`bytes`��`bytearray`�������ڴ�����������ݵ����ͣ�ǰ�߲��ɱ䣬���߿ɱ䣬�÷����Ƶ����ó�����ͬ��


### һ��`bytes`�����ɱ��ֽ�����
`bytes`һ�������Ͳ����޸ģ��ʺϴ洢�̶��Ķ��������ݣ��糣������Կ��Ԥ�����S�еȣ���

#### 1. ����`bytes`
```python
# 1. ֱ�����ֽ�ֵ�б�����Ԫ�ر�����0~255��������
b1 = bytes([0x63, 0x7c, 0x77, 0x7b])  # �����b'\x63|w{'
print(b1)  # �����b'\x63|w{'

# 2. ���ַ���+���봴������ָ�����룬��ASCII��UTF-8��
b2 = "abc".encode('utf-8')  # �����b'abc'��ÿ���ַ���ӦASCIIֵ��

# 3. ��ʮ�������ַ��������������binasciiģ�飩
import binascii
b3 = binascii.unhexlify("637c777b")  # �����b'\x63|w{'����b1�ȼۣ�

# 4. ����ָ�����ȵĿ��ֽڣ�Ĭ�����0x00��
b4 = bytes(4)  # �����b'\x00\x00\x00\x00'
```

#### 2. ���ʺ���Ƭ�������б��������޸ģ�
```python
b = bytes([0x63, 0x7c, 0x77, 0x7b])

# ���ʵ����ֽڣ�����������
print(b[0])  # �����99��0x63��ʮ���ƣ�
print(hex(b[1]))  # �����0x7c

# ��Ƭ�������µ�bytes��
print(b[1:3])  # �����b'|w'����Ӧ0x7c��0x77��
```

#### 3. ���ò���
```python
b = b'\x63|w{'

# ����
print(len(b))  # �����4

# ƴ�ӣ������µ�bytes��
b_new = b + bytes([0xf2])  # �����b'\x63|w{\xf2'

# ת��Ϊ�б����ڲ鿴�����ֽ�ֵ��
print(list(b))  # �����[99, 124, 119, 123]����Ӧ0x63,0x7c,0x77,0x7b��
```


### ����`bytearray`���ɱ��ֽ�����
`bytearray`�����޸����е�Ԫ�أ��ʺϴ洢��Ҫ��̬���µĶ��������ݣ�����ܹ����е�״̬�����м����ȣ���

#### 1. ����`bytearray`
```python
# 1. ���ֽ�ֵ�б���
ba1 = bytearray([0x63, 0x7c, 0x77, 0x7b])  # �����bytearray(b'\x63|w{')

# 2. ��bytesת��
b = bytes([0x63, 0x7c])
ba2 = bytearray(b)  # �����bytearray(b'\x63|')

# 3. ����ָ�����ȵĿ��ֽڣ�Ĭ�����0x00��
ba3 = bytearray(4)  # �����bytearray(b'\x00\x00\x00\x00')
```

#### 2. ���ʡ��޸ĺ���Ƭ��֧��ԭ���޸ģ�
```python
ba = bytearray([0x63, 0x7c, 0x77, 0x7b])

# ���ʵ����ֽ�
print(ba[0])  # �����99

# �޸ĵ����ֽڣ�ֱ�Ӹ�ֵ��������0~255��������
ba[1] = 0x7d  # 0x7c �� 0x7d
print(ba)  # �����bytearray(b'\x63}w{')

# ��Ƭ�޸ģ��滻һ���ֽڣ�
ba[2:4] = [0x7f, 0x80]  # �滻��bytearray(b'\x63}\x7f\x80')

# ��Ƭ���ʣ�����bytes��
print(ba[1:3])  # �����b'}\x7f'
```

#### 3. ���ò���
```python
ba = bytearray([0x63, 0x7c, 0x77])

# ����
print(len(ba))  # �����3

# ׷���ֽ�
ba.append(0x7b)  # �����bytearray(b'\x63|w{')

# �����ֽ�
ba.insert(1, 0x00)  # ������1������0x00�������bytearray(b'\x63\x00|w{')

# ɾ���ֽ�
del ba[1]  # ɾ������1��0x00�������bytearray(b'\x63|w{')

# ת��Ϊbytes�����ɱ䣩
b = bytes(ba)  # �����b'\x63|w{'
```


### �������ó����ܽ�
| ����         | ���ɱ�/�ɱ� | �ʺϳ���                     | ��������                     |
|--------------|-------------|------------------------------|------------------------------|
| `bytes`      | ���ɱ�      | �洢�̶����������ݣ���S�С���Կ�� | ��ȫ����ֹ�����޸ģ����ռ���� |
| `bytearray`  | �ɱ�        | ��̬������������ݣ�������м�̬�� | ֧��ԭ���޸ģ��������        |


### �ġ�ע������
�ڲ���`bytes`��`bytearray`ʱ��Ҫע��ʹ��`[i]`����ȡ�������ֽ�ȡ��Ϊ����������ܲ����������


# 2 ʮ�������ֽ�
��Python�У�Ҫ��ʮ��������ʽ�鿴`bytes`��`bytearray`�����ݣ�����ͨ�����¼��ַ���ʵ�֣�ÿ�ַ��������ڲ�ͬ������


### һ������������`hex()` ��������ã�
`bytes`��`bytearray`��������`hex()`������ֱ�ӷ���һ��ʮ�������ַ�����Сд����ÿ���ֽڶ�Ӧ��λʮ����������

```python
# ����һ���ֽ�����
b = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2])
ba = bytearray([0x00, 0xab, 0xcd, 0xef])

# ת��Ϊʮ�������ַ���
print(b.hex())    # �����'637c777bf2'
print(ba.hex())   # �����'00abcdef'
```

- �����д��ĸ���ɽ��`upper()`��
  ```python
  print(b.hex().upper())  # �����'637C777BF2'
  ```


### ������ʽ�������`format()` �� f-string
�Ե����ֽڣ�������������`format()`��f-stringָ��ʮ�����Ƹ�ʽ��`02x`��ʾ��λСд��`02X`��ʾ��λ��д����

#### 1. �����ֽ����в���ʽ��
```python
b = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2])

# ����1����f-string����
hex_str = ' '.join(f'{x:02x}' for x in b)
print(hex_str)  # �����'63 7c 77 7b f2'�����ո�ָ������׶���

# ����2����д��ʽ
hex_str_upper = ' '.join(f'{x:02X}' for x in b)
print(hex_str_upper)  # �����'63 7C 77 7B F2'
```

#### 2. ���̶���ȷ��飨��AES�е�16�ֽڷ��飩
�ʺϲ鿴�������ݣ���128λAES�Ŀ����ݣ���
```python
# 16�ֽڵ�ʾ�����ݣ�AES���С��
aes_block = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])

# ÿ4�ֽ�һ�飬ÿ�����ÿո�ָ�������û��зָ�
hex_lines = []
for i in range(0, len(aes_block), 4):
    group = aes_block[i:i+4]
    hex_group = ' '.join(f'{x:02x}' for x in group)
    hex_lines.append(hex_group)

print('\n'.join(hex_lines))
# �����
# 32 43 f6 a8
# 88 5a 30 8d
# 31 31 98 a2
# e0 37 07 34
```


### ����ʹ��`binascii`ģ�飨����
`binascii`ģ���ṩ�˸���ʮ������ת�����ߣ�����`hexlify()`������`hex()`��������`bytes`���ͣ���

```python
import binascii

b = bytes([0x63, 0x7c, 0x77, 0x7b])

# ת��Ϊʮ������bytes�������Ϊ�ַ�����
hex_bytes = binascii.hexlify(b)
print(hex_bytes)        # �����b'637c777b'
print(hex_bytes.decode())  # �����'637c777b'��תΪ�ַ�����
```

**<span style='color:blue'>��ע�⣬bytes��������C++�е�</span>**
```Cpp
const type* pointer
```
**<span style='color:blue'>���ܹ����ʣ����ܹ��޸ġ�</span>**

**<span style='color:blue'>��ע�⣬bytearray��������C++�е����ô���</span>**

# 3 bin �� bit_length
`bin()` �� `bit_length()` ��Python�����ڴ�������ƺ�λ�������ú�����

### һ��`bin()`��������ת��Ϊ�������ַ���
`bin()`����������ת��Ϊ��`'0b'`��ͷ�Ķ������ַ�����

```python
# ʾ��
num = 10
binary_str = bin(num)
print(binary_str)  # �����'0b1010'
```

### ����`bit_length()`����������Ʊ�ʾ��λ��
`bit_length()`�������������ڶ����Ʊ�ʾ����Ҫ��λ����������ǰ׺`'0b'`����

```python
# ʾ��
num = 10
bit_length = num.bit_length()
print(bit_length)  # �����4
```

### ��������
- `bin()`��������ת��Ϊ�������ַ���������ǰ׺`'0b'`��
- `bit_length()`�����������ڶ����Ʊ�ʾ�е�λ����������ǰ׺`'0b'`��

### �ġ�ʾ��
```python
# ʾ��
num = 10
binary_str = bin(num)
bit_length = num.bit_length()

print(binary_str)  # �����'0b1010'
print(bit_length)  # �����4
print(len()(binary_str) - 2)  # �����4��ȥ��ǰ׺'0b'��ĳ��ȣ�
```

# 4 range
`range()`������������һ��ָ����Χ���������У�������ѭ������Ƭ�ȳ�����

### һ�������÷�
`range(start, stop, step)`��
- `start`�����е���ʼֵ��Ĭ��Ϊ0����
- `stop`�����еĽ���ֵ�����������ڣ���
- `step`�����еĲ�����Ĭ��Ϊ1����

### ����ʾ��
```python
# ���ɴ�0��9����������
for i in range(10):
    print(i)  # �����0 1 2 3 4 5 6 7 8 9

# ���ɴ�1��10���������У�����Ϊ2��
for i in range(1, 11, 2):
    print(i)  # �����1 3 5 7 9

# ���ɴ�10��0���������У�����Ϊ-1��
for i in range(10, -1, -1):
    print(i)  # �����10 9 8 7 6 5 4 3 2 1 0
```