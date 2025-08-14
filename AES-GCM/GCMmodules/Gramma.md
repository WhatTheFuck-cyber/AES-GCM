### 再次强调 bytes 和 bytearray
- bytes 和 bytearray 都是字节的序列，可以使用索引进行读取，类似数组。
- bytes 的数据是不能修改的，而 bytearray 的数据是可以修改的。
- bytes 和 bytearray 使用索引取出的元素是整数，而不是字符串或者字节。
- bytearray 的修改只需要索引到相应的位置并赋上整数值即可（注意范围 0 - 255）。