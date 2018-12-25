# 正向代理之Shadowsocks源代码浅析，Go语言实战

![Category](https://img.shields.io/badge/category-security_develop-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-go-blue.svg)
![Tag](https://img.shields.io/badge/tag-proxy-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1538058606-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 在研究尝试正向代理方案时，遇到了性能上的瓶颈，刚好Shadowsocks官方有开源两个Go版源代码，于是利用业余时间分别对它们的主流程进行了简单分析，Shadowsocks加密传输的原理大家都懂，看看它是怎么实现的。至于ShadowsocksR甚至ShadowsocksX嘛，有兴趣的自己去看啦。</sub>

## shadowsocks-go

### 服务端

#### 用法

```sh
# 1. 配置config.json
# 2. 启动服务
shadowsocks-server
```

#### 启动

首先使用Go官方的`json`包解析配置文件config.json，并设置超时时间：

```go
config = &Config{}
if err = json.Unmarshal(data, config); err != nil {
    return nil, err
}
readTimeout = time.Duration(config.Timeout) * time.Second
```

利用Go的反射机制根据启动命令提供的参数值更新配置信息。

接下来进行一系列有效性检查：

1. 校验加密算法有效性，如果未设置加密算法，则默认使用『aes-256-cfb』
1. 校验密码有效性，并与端口配对缓存

遍历端口密码对，在本地各端口上建立TCP和UDP监听，以当前端口为索引缓存对应的密码和监听器，等待接收建立连接 *（UDP处理流程有些区别，下文都以TCP为例）* ：

```go
ln, err := net.Listen("tcp", ":"+port)
if err != nil {
    // ...
}
passwdManager.add(port, password, ln)
```

#### 建立连接

接收到新的连接后，通过配置的加密算法和密码初始化密码器：

```go
cipher, err = ss.NewCipher(config.Method, password)
```

密码器会根据密码和加密算法对应的密钥长度生成最终密钥：

```go
const md5Len = 16

cnt := (keyLen-1)/md5Len + 1
m := make([]byte, cnt*md5Len)
copy(m, md5sum([]byte(password)))

d := make([]byte, md5Len+len(password))
start := 0
for i := 1; i < cnt; i++ {
    start += md5Len
    copy(d, m[start-md5Len:start])
    copy(d[md5Len:], password)
    copy(m[start:], md5sum(d))
}
return m[:keyLen]
```

简单解释一下密钥的生成算法：

1. 根据加密算法的默认密钥长度计算块数 *（块长度为16）* ，并确定`m`的长度
1. 对密码进行MD5加密得到16字节的密文，将其值拷贝至`m`中 *（拷贝长度为两者中较小值）*
1. 分配16+密码长度的计算暂存区`d`
1. 循环块数次数，依次将`m`的当前块区值和密码拷贝至`d`中，对当前`d`值进行MD5加密，再追加拷贝至`m`中
1. 以加密算法的默认密钥长度截取`m`值作为最终密钥

封装加密连接对象，新开线程处理该连接：

```go
go handleConnection(ss.NewConn(conn, cipher.Copy()), port)
```

#### 处理连接

创建长度为请求最大长度269的缓冲区 *（计算公式为`1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)`）* ，分段读取请求信息，解析获得远程主机地址，并建立连接：

```go
remote, err := net.Dial("tcp", host)
```

建立双向通信管道：

```go
go func() {
    ss.PipeThenClose(conn, remote, func(Traffic int) {
        passwdManager.addTraffic(port, Traffic)
    })
}()

ss.PipeThenClose(remote, conn, func(Traffic int) {
    passwdManager.addTraffic(port, Traffic)
})
```

#### 通信

从缓冲区空闲列表获取或创建一个新的长度为4108的缓冲区 *（计算公式为`2(data.len) + 10(hmacsha1) + 4096(data)`）* 。

- 请求时

    循环从源主机连接读取请求数据，并解密：

    ```go
    n, err = c.Conn.Read(cipherData)
    if n > 0 {
        c.decrypt(b[0:n], cipherData[0:n])
    }
    ```

    向目的主机连接写入数据：

    ```go
    dst.Write(buf[0:n])
    ```

- 响应时

    相反的，循环从源主机连接读取请求数据，加密后向目的主机连接写入。

连接断开后，将当前用完废弃的缓冲区放入缓冲区空闲列表中供下一次重复使用 *（性能优化，见《Effective Go》的Concurrency章节）* ：

```go
defer leakyBuf.Put(buf)
```

至此，服务端主流程结束。

### 客户端

#### 用法

```sh
# 1. 配置config.json
# 2. 启动服务
shadowsocks-client
# 3. 设置浏览器代理：SOCKS5 127.0.0.1:local_port
```

#### 启动

首先重组Shadowsocks服务器URI，并更新进配置信息中。Shadowsocks服务器URI模式支持以下两种：

1. ss://base64(method:password)@host:port
1. ss://base64(method:password@host:port)

解析配置文件config.json，更新配置信息。

解析服务器配置，初始化密码器。

在本地端口上建立TCP监听，等待接收建立SOCKS5连接。

#### 建立连接

接收到新的连接后，直接新开线程处理该连接。

#### 处理连接

与连接请求主机进行SOCKS5握手，具体细节就不多说了。

按SOCKS5规范读取请求信息，解析获得远程主机原始地址，向连接请求主机确认连接建立成功：

```go
conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
```

与Shadowsocks服务器建立连接：

```go
conn, err := net.Dial("tcp", server)
```

封装加密连接对象，向Shadowsocks服务器连接写入远程主机原始地址。

建立双向通信管道：

```go
go ss.PipeThenClose(conn, remote, nil)
ss.PipeThenClose(remote, conn, nil)
```

#### 通信

与服务端通信过程基本一致。

## go-shadowsocks2

### 服务端

#### 用法

```sh
# 1. 启动服务
shadowsocks2 -s 'ss://AEAD_CHACHA20_POLY1305:your-password@:8488' -verbose
```

#### 启动

设置密钥 *（可生成，指定密钥位数，随机生成填充）* 。

解析Shadowsocks服务器URI，根据配置的加密方式 *（默认使用『AEAD_CHACHA20_POLY1305』）* 、密钥和密码初始化密码器，若密钥为空，则以密码为种子使用KDF算法生成密钥：

```go
var b, prev []byte
h := md5.New()
for len(b) < keyLen {
    h.Write(prev)
    h.Write([]byte(password))
    b = h.Sum(b)
    prev = b[len(b)-h.Size():]
    h.Reset()
}
return b[:keyLen]
```

简单解释一下密钥的生成算法：

1. 在密钥长度小于预期值时，将前一区块值和密码一起，循环计算MD5值，得到的16字节密文成新块追加在密钥尾部

由此可见，两个版本的密钥生成算法虽然在写法上稍有不同，但结果都保持一致，这也是必须的。

同时开启TCP和UDP两条连接处理通道，等待接收建立连接 *（下文仍以TCP为例）* 。

#### 建立连接

接收到新的连接后，直接新开线程处理该连接。

#### 处理连接

封装加密连接对象，与第一版不同的是，它直接重写了`net.Conn`的读写方法，以读取数据为例：

1. 首次连接时，初始化读取器
    - 读取盐
        ```go
        salt := make([]byte, c.SaltSize())
        if _, err := io.ReadFull(c.Conn, salt); err != nil {
            return err
        }
        ```
    - 根据密钥、盐和自定义信息生成密钥扩展，将其传给加密算法对应的对象，初始化解密器
        ```go
        subkey := make([]byte, a.KeySize())
        hkdfSHA1(a.psk, salt, []byte("ss-subkey"), subkey)
        return a.makeAEAD(subkey)
        ```
1. 通过读取器读取数据，并解密成明文

分段读取请求信息，解析获得远程主机地址，并建立连接。

建立通信中继：

```go
relay(c, rc)
```

#### 通信

建立双向通信管道，通过`io.Copy`拷贝数据。

### 客户端

#### 用法

```sh
# 1. 启动服务
shadowsocks2 -c 'ss://AEAD_CHACHA20_POLY1305:your-password@server_address:8488' -verbose -socks :1080 -u -udptun :8053=8.8.8.8:53,:8054=8.8.4.4:53 -tcptun :8053=8.8.8.8:53,:8054=8.8.4.4:53
# 2. 设置浏览器代理
```

#### 启动

解析客户端URI，初始化密码器。

启动时若设置了`-tcptun`或`-udptun`参数，则将Shadowsocks服务器地址转换成原始地址，建立TCP/UDP隧道。

在本地端口上建立TCP监听，等待接收建立SOCKS5连接。

#### 建立连接

接收到新的连接后，直接新开线程处理该连接。

#### 处理连接

与连接请求主机完成SOCKS5握手后，再与Shadowsocks服务器建立连接。

封装加密连接对象，向Shadowsocks服务器连接写入远程主机原始地址。

建立通信中继。

#### 通信

与服务端通信过程基本一致。

## 总结

为什么第二版被官方冠以『Next-generation』的称号呢？

通过上面对源代码的分析可以知道它的特点如下：

1. 通过使用接口、组合和回调函数等设计，使源代码结构更清晰合理，便于阅读理解
1. 减少外部依赖，只包含经过验证的现代密码学加密算法
1. 加速SOCKS5协议的解析，不判断处理多余字段，并增加了UDP ASSOCIATE请求类型的解析响应
1. 支持TCP隧道 *（如用于iperf3网络带宽测试）* 和UDP隧道 *（如用于DNS数据包中继）*
1. 支持Linux Netfilter重定向

## 参考

1. [Shadowsocks Go](https://github.com/shadowsocks/shadowsocks-go/)
1. [Shadowsocks Go 2nd](https://github.com/shadowsocks/go-shadowsocks2/)