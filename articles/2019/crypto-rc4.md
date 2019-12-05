# 带你学加密之RC4

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-cryptology-blue.svg)
![Tag](https://img.shields.io/badge/tag-rc4-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1575491938-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 偶然间看到一个JavaScript脚本中使用了RC4加密，闲来无事就看了下它的算法，挺简单的，带大家快速过一遍。</sub>

## RC4基础

RC4，Rivest Cipher 4，是一种密钥长度可变的流加密算法，属于对称加密的分支。

它被应用在WEP、WPA和早期的SSL/TLS中，可见其在网络通信发展历史中的地位是非常重要的。

本文直接以我看到的JavaScript脚本中的实现为例，经过对比，它与Golang官方crypto包中的逻辑基本一致。

### 初始化

在RC4中，存在一个长度为256的字节数组，用户传递的密钥参与将它生成状态向量。

最开始，我们先初始化一个步长为1的升序数组`S`：

```js
var S = [];
for (var i = 0; i < 256; i++) {
    S[i] = i;
}
```

接着，使用密钥将`S`打乱，其实就是不断的『随机』交换：

```js
var j = 0;
for (i = 0; i < 256; i++) {
    j = (j + S[i] + key.charCodeAt(i % key.length)) % 256;
    tmp = S[i];
    S[i] = S[j];
    S[j] = tmp;
}
```

其中，密钥是在其自身长度范围内循环遍历取值，并且`j`也需要保证小于256。

为了照顾代码基础较弱的同学，我们再来简单描述一下整个打乱过程。不过为了节约时间，我们将状态向量长度缩短至4位举例：

- 变量定义
    ```plain
    key = "abc"
    S = [0, 1, 2, 3]
    j = 0
    ```
- 第1轮循环
    ```plain
    i = 0
    j = (j + S[i] + key[i%key_len]) % 4 = (0 + 0 + 97) % 4 = 1
    S[i], S[j] = S[j], S[i] -> S = [1, 0, 2, 3]
    ```
- 第2轮循环
    ```plain
    i = 1
    j = (1 + 0 + 98) % 4 = 3
    S[i], S[j] = S[j], S[i] -> S = [1, 3, 2, 0]
    ```
- 第3轮循环
    ```plain
    i = 2
    j = (3 + 2 + 99) % 4 = 0
    S[i], S[j] = S[j], S[i] -> S = [2, 3, 1, 0]
    ```
- 第4轮循环
    ```plain
    i = 3
    j = (0 + 0 + 97) % 4 = 1
    S[i], S[j] = S[j], S[i] -> S = [2, 0, 1, 3]
    ```
- 最终结果
    ```plain
    S = [2, 0, 1, 3]
    ```

这样，我们就得到了『随机化』的状态向量。

### 伪随机子密码生成与加解密

接下来的工作就更简单了，在逐字节遍历待加解密数据时，将上述状态向量通过伪随机子密码生成算法生成一串密钥流，并取其中一个字节进行异或运算，达到类似『一次一密』的效果：

```js
var dst_data = '';
i = 0;
j = 0;
for (var k = 0; k < data.length; k++) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    tmp = S[i];
    S[i] = S[j];
    S[j] = tmp;
    c = data.charCodeAt(k) ^ S[(S[i]+S[j])%256];
    dst_data += String.fromCharCode(c);
}
```

还是来举个实际例子再耐心的描述一下运算过程：

- 变量定义
    ```plain
    data = "gyyyy"
    S = [2, 0, 1, 3]
    i = 0
    j = 0
    ```
- 第1轮循环
    ```plain
    k = 0
    i = 1
    j = (j + S[i]) % 4 = (0 + 0) % 4 = 0
    S[i], S[j] = S[j], S[i] -> S = [0, 2, 1, 3]
    c = data[k] ^ S[(S[i]+S[j])%4] = 103 ^ 1 = 102
    ```
- 第2轮循环
    ```plain
    k = 1
    i = 2
    j = (0 + 1) % 4 = 1
    S[i], S[j] = S[j], S[i] -> S = [0, 1, 2, 3]
    c = 121 ^ 3 = 122
    ```
- 第3轮循环
    ```plain
    k = 2
    i = 3
    j = (1 + 3) % 4 = 0
    S[i], S[j] = S[j], S[i] -> S = [3, 1, 2, 0]
    c = 121 ^ 0 = 121
    ```
- 第4轮循环
    ```plain
    k = 3
    i = 0
    j = (0 + 3) % 4 = 3
    S[i], S[j] = S[j], S[i] -> S = [0, 1, 2, 3]
    c = 121 ^ 3 = 122
    ```
- 第5轮循环
    ```plain
    k = 4
    i = 1
    j = (3 + 1) % 4 = 0
    S[i], S[j] = S[j], S[i] -> S = [1, 0, 2, 3]
    c = 121 ^ 0 = 121
    ```
- 最终结果
    ```plain
    dst_data = [102, 122, 121, 122, 121] = "fzyzy"
    ```

由于加解密的密钥相同，状态向量`S`无论是在打乱或生成子密码时，顺序结果都会保持一致，且数据加密前后字节长度不变。

因此可知，使用了异或运算处理的RC4算法的加解密是互逆的。

## 特殊密文

因为RC4是对字节流进行处理，所以我们看到的密文很多时候都经过了Base64编码，而RC4其算法本身的特征又过于明显，所以输入数据这一块经常会被动手脚，这种现象在黑灰产的利用中尤为常见。

还是以我看到的这个JavaScript脚本为例，它的密文形式都是正常的Base64，但如果直接解码后用RC4解密，会发现根本解不出来。

所以我们再花点时间来看看它的输入数据是如何被处理的，同时也可以为今后遇到类似情况积累一些经验。

经过分析，我找到了一个代码片段。原始代码是经过混淆的，我们暂时跳过还原过程，开门见山：

```js
var tmp = '';
data = atob(data);
for (var i = 0, len = data.length; i < len; i++) {
    tmp += '%' + ('00' + data.charCodeAt(i).toString(16))['slice'](-2);
}
data = decodeURIComponent(tmp);
```

答案已经很明显了，它在经过Base64解码后，会依次遍历每个字节，通过`toString()`将其转成16进制，并在前补充`00`后`slice()`取后两位，前置`%`转换成URL编码形式被`decodeURIComponent()`解码。

而`decodeURIComponent()`在对ASCII码 *（`0x00`-`0x7F`）* 以外的字符都是以双字节进行处理，如`%C2%80`会被解码成`0x80`，因此造成最终待解密的密文与原始Base64不一定相对应。

## 参考

1. [RC4](https://en.wikipedia.org/wiki/RC4)