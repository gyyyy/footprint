# 带你学加密之WinACE中的CRC-32

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-cryptology-blue.svg)
![Tag](https://img.shields.io/badge/tag-crc32-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-0000000000-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-0%25-brightgreen.svg)

<sub>* 几天前，WinRAR曝出一个存在了19年的安全漏洞，实验室的[@浮萍](http://fuping.site/)大佬在第一时间进行了复现分析，其中用一个非常巧妙的方法获取了修改后的CRC值，通过常规CRC-32算法 *（zip和gzip通用）* 计算后得到的值与它并不一致，这让我感到十分好奇。遗憾的是，在随后圈里刮起的分析预警风里，也没能发现一篇满足我好奇心的。算了，还是自己动手吧。</sub>

## CRC基础

CRC，Cyclic Redundancy Check *（循环冗余校验）* ，是一个根据网络数据包或文件等数据生成固定长度校验码的散列算法，通常用于网络传输、解压缩等过程中的数据正确性校验。

常见的CRC算法有CRC-8、CRC-12、CRC-16和CRC-32，及各种衍生版本，它们主要的不同在于校验码长度和几个决定运算结果的参数上。

### 计算过程

CRC的计算和校验过程还包括一些参数，以及几种不同的算法。

不过简单的说，就是通过生成多项式 *（见下面生成多项式章节）* 对原始数据进行模2除，所得余数即CRC校验码。校验方拿到原始数据和CRC校验码后，将CRC校验码补入原始数据之后组成待校验数据 *（该过程也可在发送数据之前完成）* ，再利用相同的生成多项式对待校验数据模2除，判断所得余数是否为0，是则表示与原始数据一致。

其中，模2除与算术除的区别是，它使用异或运算代替减运算降低了运算处理的复杂度。

举个简单的例子，假设原始数据为`1010001101`，生成多项式为`110101`，CRC校验码长度即生成多项式的最高次幂，这里为5。

将原始数据左移5位后，它的模2除过程如下：

```plain
              1101010110
110101 / 101000110100000
         110101
          111011
          110101
            111010
            110101
              111110
              110101
                101100
                110101
                 110010
                 110101
                    1110
```

余数为`1110`，长度不足5高位补0，得到该原始数据的CRC校验码为`01110`。

### 生成多项式

通过上面的示例我们可以清楚的知道，CRC校验有一个关键因素就是待校验方与校验方必须约定好相同的生成多项式。

这个生成多项式说白了，其实就是告诉校验方需要校验的位置 *（因为是循环校验，所以非绝对位置）* ，校验位越多，出错的几率就越小。

我们以CRC-32为例，它常用的生成多项式为：

```math
g(x)=x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x^1+1
```

即表示它需要循环校验第1、2、4、5、7、8、10、11、12、16、22、23、26和32位置上的数据，对应代码为`100000100110000010001110110110111`共33位。按照CRC规范，最高位和最低位必须为`1`，简写省略最高位，因此16进制记作`0x04C11DB7`。

该多项式的最高次幂为32，故CRC校验码长度也为32。

在计算机中，常见的字节存储机制有Big-Endian和Little-Endian两种，俗称大端和小端。在IEEE 802.3标准中，TCP/IP的各层协议以及png、zip和gzip等格式的数据都以大端为主，即低位字节在前，也就是一个前后颠倒的顺序，如`0x1234`的大端表示为`34 12`。

既然原始数据顺序出现了颠倒，那么可以在计算CRC校验码之前将原始数据的顺序给倒回来，也可以直接将生成多项式做一次颠倒，去掉最高位后得到`0xEDB88320`，这也是Go中`crc32.IEEE`的值。

## ACE CRC-32

有了以上基础，我们可以使用浮萍提供的`liehu.ace`来尝试计算一下ACE文件中Volume Header的CRC校验码的值：

```go
f, _ := os.Open("liehu.ace")
a := make([]byte, 4)
f.Read(a)
b := make([]byte, binary.LittleEndian.Uint16(a[2:]))
f.Read(b)
f.Close()
sum := crc32.ChecksumIEEE(b)
```

值得注意的是，在程序中，若按顺序将字节装入数组中，高低位反而会因为索引顺序被反转回小端，因此使用`binary.LittleEndian`进行计算Header长度。

得到的`sum`值为`0xC71086BE`，与在文件中读取到的`0x7941`不一致。

通过查阅相关文档，发现了下面这段话：

> Each header contains a 16 bit checksum over the header bytes. Each archive member has a 32 bit checksum over the decompressed bytes. ACE uses a bitwise inverted version of standard CRC-32 with polynomial 0x04C11DB7 as the 32 bit checksum, and a truncated version of that for the 16 bit checksum.

原来Header中的16位校验码是从原32位校验码中截取的，于是对代码进行简单的修改：

```go
sum := uint16(crc32.ChecksumIEEE(b)&0xFFFF)
```

虽然结果`0x86BE`还是不对，不过现在已经可以拿到16位校验码了。

再仔细看上面的描述，其中提到ACE是在标准的CRC-32算法基础上，对结果做了按位取反操作，我们再改改：

```go
sum := uint16((^crc32.ChecksumIEEE(b))&0xFFFF)
```

其中，Go的`^`位运算符在一元运算中表示取反操作，与C的`~`相同。

最后，成功得到我们需要的`0x7941`。

## 参考

1. [Acefile API](https://apidoc.roe.ch/acefile/latest/)