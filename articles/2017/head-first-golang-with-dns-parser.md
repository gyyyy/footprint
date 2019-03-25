# DNS解析器，深入浅出Go语言

![Category](https://img.shields.io/badge/category-security_develop-blue.svg)
![Research](https://img.shields.io/badge/research-cyber_security-blue.svg)
![Language](https://img.shields.io/badge/lang-go-blue.svg)
![Tag](https://img.shields.io/badge/tag-dns-green.svg)
![Tag](https://img.shields.io/badge/tag-protocol-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1513831469-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 由于文章完成时间比较凑巧，首先，祝各位大佬圣诞快乐，元旦快乐，新年快乐！最近在写一个涉及DNS查询的小脚本时遇到个需求，需要指定DNS服务器获得域名的解析结果。由于近两年一直用Go作为主语言，借由这个场景，也刚好给小伙伴们普及一下Google爸爸创造的这门神奇的语言。GitHub上已经有很多大牛编写的完整成熟的DNS相关类库，大家感兴趣的可以去看看。</sub>

## DNS协议

作为一个古老的互联网协议 *（本文参考的1987年发布的RFC 1034和1035）* ，DNS协议的设计还是比较简单的。

RFC中对DNS消息结构的定义如下：

```plain
+---------------------+
|        Header       |
+---------------------+
|       Question      | the question for the name server
+---------------------+
|        Answer       | RRs answering the question
+---------------------+
|      Authority      | RRs pointing toward an authority
+---------------------+
|      Additional     | RRs holding additional information
+---------------------+
```

一般情况下，一个标准的DNS查询数据包包含Header和Question两部分，而一个标准的DNS应答数据包也会包含Header和Question，并根据Header中的部分标识和查询类型附带上Answer、Authority和Additional中的一个或多个部分。

是的，你没有看错，应答包中也包含了Question。你可以想象你在纸上写了一个问题传给DNS服务器，DNS服务器在纸上填好答案又把纸还给了你。

### Header

我们先来看看协议里的灵魂，Header：

```plain
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

这，额，还是简单的说明下吧：

1. ID

    消息的标识，并不要求唯一，一般由DNS协议实现层生成和管理 *（Win下的nslookup命令是从`0x0001`开始递增，自己实现的话随便写个死的也行，如`0x1024`）* ，应答包不会修改，所以如果需要区分处理多客户端的调用，还是有用的

1. FLAG
    - QR

        区分当前数据包是查询还是应答的标识，想问问设计者大大这设定是不是有点太任性了 :)

    - Opcode

        查询包标识，应答包不会修改

        - `0`为标准的正向查询
        - `1`为反向查询
        - `2`为请求服务器状态
        - 剩余为预留
    - AA

        应答包中的标识，表示是否权威服务器应答

    - TC

        消息是否过长被截断的标识

    - RD

        递归查询的标识，应答包不会修改

    - RA

        服务器是否支持递归查询的标识

    - Z

        预留

    - RCODE

        应答包标识

        - `0`为正常
        - `1`为格式错误
        - `2`为服务器故障
        - `3`为域名错误
        - `4`为不支持
        - `5`为拒绝
        - 剩余为预留
1. QDCOUNT

    Question部分中的问题个数

1. ANCOUNT

    Answer部分中的问题个数

1. NSCOUNT

    Authority部分中的域名服务器个数

1. ARCOUNT

    Additional部分中的附加记录个数

知道Header长什么样之后，我们需要用Go定义一个 **结构体** *（可以当作Java中的类）* 来表示它。

先等等，Go被形容为一门长得像C/C++用得像Python的四不像语言，它也有 **包** 的概念，下面是Java同学的福利：

```go
package dns // 放在每个go文件的第一行，只有一个单纯的名字
            // !!!不需要以分号结尾，不需要java.lang形式（由文件路径定位，和Python类似）!!!
```

对于结构体的定义，相信玩C/C++的小伙伴们一定会眼熟：

```go
type Header struct {
    ID      uint16 // !!!不需要以分号结尾!!!
    Flag    uint16
    QDCount uint16
    ANCount uint16
    NSCount uint16
    ARCount uint16
}
```

上面表示结构体的代码块中，有两个需要了解的Go基本知识点：

1. **数据类型**
    - 布尔类型
        - `bool`
    - 数字类型
        - `int`, `int8`, `int16`, `int32`, `int64`
        - `uint`, `uint8`, `uint16`, `uint32`, `uint64`
        - `float32`, `float64`, `complex64`, `complex128`
        - `byte`, `rune`, `uintptr`
    - 字符串类型
        - `string`
    - 复合类型
        - Array *（数组）*
        - Map *（映射）*
        - Slice *（切片）*
        - Struct *（结构体）*
        - Interface *（接口）*
        - Function *（函数）*
        - Channel *（通道）*
1. **命名规则**
    - 驼峰命名法，首字符可以为任意Unicode或下划线，其余字符可以为任意Unicode、数字或下划线，长度不限
    - 在对自定义的全局常量/变量、结构体、接口、函数/方法命名时，若首字符为大写字母，则该对象可被包外访问，否则只允许包内使用

对于Header中的Flag，有两种方式来处理，一是可以再定义一个结构体描述，二是定义个函数来设置Flag中的各个标识。由于需求暂时不涉及Flag中的标识，我们直接简单的使用第二种方式，顺便为大家介绍一下如何为结构体定义 **成员函数** ：

```go
func (h *Header) SetFlag(qr, opcode, aa, tc, rd, ra, rcode uint16) {
    h.Flag = qr<<15 + opcode<<11 + aa<<10 + tc<<9 + rd<<8 + ra<<7 + rcode
}
```

包域内，定义成员函数只需要在关键字`func`和函数名之间加上结构体或结构体指针 *（对指针有阴影的同学，把它当成Java中对象的引用就行）* 类型的变量即可，有一点点类似C/C++中类外成员函数定义，函数内用`.`访问对象的成员。当然，如果少了这个变量，就是普通的函数，遵循上述命名规则，也无法直接访问任何结构体的成员。

因此，大家应该可以初步的感受到Go非侵入式的设计理念了，先不细说，我们继续。

而Go的 **运算符** 也很简单，同样有算数、关系、逻辑、位和赋值几种，与其他主流语言基本类似，至于上面的左移运算是个什么概念，我就不在这里介绍了，有不太清楚的同学可以自行查阅资料。

除此之外，Go还保留了`*` *（指针）* 和`&` *（地址）* 两个与指针相关的运算符。

### Question

接下来是协议的核心，Question：

```plain
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

1. QNAME

    这就是要让DNS服务器解析的域名

1. QTYPE

    查询类型，与应答包共享的TYPE为QTYPE子集，列举几个常见的，其他的大家自己根据需要去查

    - A

        `1`，主机地址

    - NS

        `2`，权威域名服务器

    - CNAME

        `5`，别名

    - MX

        `15`，邮件交换

    - TXT

        `16`，文本字符串

    - \*

        `255`，所有记录
1. QCLASS

    查询类，与应答包共享的CLASS为QCLASS子集

    - IN

        `1`，Internet *（一般情况就用这个）*

    - CS

        `2`，CSNET

    - CH

        `3`，CHAOS

    - HS

        `4`，Hesiod

    - \*

        `255`，任意类

对于上述TYPE和CLASS这类不变的数值，我们可以在程序中直接使用对应值，更规范的做法是使用 **常量** 让它们具有可读性：

```go
// 形式一
const (
    TypeA     = 1
    TypeNS    = 2
    TypeCNAME = 5
    TypeMX    = 15
    TypeTXT   = 16

    ClassIN = 1
    ClassCS = 2
    ClassCH = 3
    ClassHS = 4
)

// 形式二
const QTypeAny = 255
const QClassAny = 255
```

由于Question的QNAME字节长度不定，在定义结构体时可以使用Go的 **切片** 类型来描述：

```go
type Question struct {
    QName  []byte // byte切片
    QType  uint16
    QClass uint16
}
```

切片是Go内置的一种『动态数组』，它包含初始长度和容量两个属性，其中容量在切片创建时为可选参数：

```go
// 使用make关键字创建切片
s = make([]byte, 10)
s = make([]byte, 10, 100)

// 也可以使用另一种形式进行切片的创建和初始化
s = []byte{}

// 对于增加超出预定义长度的元素，可以使用内置函数append()
s = append(s, byte(0))
```

Go的 **映射** 类型也是类似使用方法：

```go
m = make(map[string]string)
m = map[string]string{}
m["key"] = "value"

// 通常情况下，直接使用索引即可获得Map中对应键的值
// 但也可以用两个变量接收索引结果，第二个变量表示Map中是否存在对应键
value, ok := m["key"]
```

在DNS协议中，域名中的每个字符串片段被称为一个标签 *（label）* ，其表现形式并不是`www.domain.com`，而是`3www6domain3com`，即`标签长度+标签内容`。因此，我们定义一个Question的成员函数来转换普通域名字符串：

```go
// 可以使用import关键字导入其它包
import (
    "bytes"
    "encoding/binary"
)

// ...

func (q *Question) SetQName(qname string) {
    var buf bytes.Buffer

    for _, n := range strings.Split(qname, ".") {
        binary.Write(&buf, binary.BigEndian, byte(len(n))) // 标签长度
        binary.Write(&buf, binary.BigEndian, []byte(n)) // 标签内容
    }
    binary.Write(&buf, binary.BigEndian, eof) // 以0x00结束

    q.QName = buf.Bytes()
}
```

代码中的`for`语法里包含几个Go的知识点：

1. `strings.Split()`返回index和字符串，`_`表示忽略，即只拿分割后的字符串，因为Go要求所有定义的变量都要使用
1. `:=`为Go中 **变量** 的定义和赋值，等价于：
    ```go
    var n string
    for _, n = range strings.Split(qname, ".") {
        // ...
    }
    ```
    如果是在函数外定义变量，只能使用`var`的形式。另外，对同一个变量再次赋值时，只需要`=`即可
1. `range`关键字适用于数组、切片、映射和通道等数据类型的遍历，类似Python的`range()`

### Answer

然后是协议的关键，Answer：

```plain
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- NANE

    同Question的QNAME

- TYPE

    同Question的QTYPE中的TYPE子集

- CLASS

    同Question的QCLASS中的CLASS子集

- TTL

    资源记录被丢弃前的缓存时间，单位为秒

- RDLENGTH

    RDATA长度

- RDATA

    这就是解析结果，如果查询类型是A记录，它的值应该是4字节十六进制的IP地址

这里有两点是值得注意的：

1. 一个查询是可能对应多个结果的，每个结果的资源记录会对应一个Answer结构，也就是说，我们需要根据应答包Header中的ANCOUNT值来确定应答包中存在几个Answer
1. Answer、Authority和Additional的结构相同，官方称为Resource Record，但其中RDATA的具体结构会根据查询类型有不同

针对第2点，一般面向对象语言的解决方案是使用泛型。但是对不起，Go不支持泛型，所以我们定义一个 **接口** 来描述：

```go
type resourceData interface {
    value() string
}
```

定义结构体中属性或变量时，可以直接使用接口作为数据类型：

```go
type Resource struct {
    Name     []byte
    Type     uint16
    Class    uint16
    TTL      uint32
    RDLength uint16
    RData    resourceData
}
```

Go中的接口也是非侵入式的，任何对象只需要实现接口中定义的所有函数，即代表该对象实现了这个接口：

```go
type rdataA struct {
    addr [4]uint8
}

func (r *rdataA) value() string {
    return fmt.Sprintf("%d.%d.%d.%d", r.addr[0], r.addr[1], r.addr[2], r.addr[3])
}
```

对于NS和CNAME等查询类型而言，其结构相同，都是一个域名，因此可以定义一个基类，让它们去继承。不幸的是，Go也不支持继承这种特性，但是我们可以使用 **组合** *（看来Google的工程师都已经把设计模式印在思想里了，深谙其道，无论是Android还是Go，从底层核心到接口都有大量明显的设计模式运用痕迹）* 来实现：

```go
// 叶子对象（基类）
type rdataDomain struct {
    name []byte
}

func (r *rdataDomain) value() string {
    var labels []string
    for i := 0; i < len(r.name)-1; {
        l := int(r.name[i]) //3
        labels = append(labels, string(r.name[i+1:i+l+1]))
        i += l + 1
    }

    return strings.Join(labels, ".")
}

// 组合对象
type rdataNS struct {
    rdataDomain // 匿名叶子，可以看做继承，直接拥有叶子对象的全部属性和函数
    // 也可以使用常规属性来描述
    // domain rdataDomain

    // 当然还可以定义当前结构体独有的其他属性
}

type rdataCNAME struct {
    rdataDomain
}
```

关于接口的应用，包括接口转普通类型时的 **断言** ，我们通过给`Resource`定义一个`SetRData()`函数来了解一下：

```go
func (r *Resource) SetRData(rdata, data []byte) error {
    var rd resourceData // 接口类型
    switch r.Type {
    case TypeA:
        rd = new(rdataA) // 普通类型转接口是隐式的
        if len(rdata) != 4 {
            return errors.New("invalid resource record data")
        }
        for i, d := range rdata {
            // 接口转普通类型需要使用断言：rd.(*rdataA)，即断言接口rd为rdataA指针类型
            binary.Read(bytes.NewBuffer([]byte{d}), binary.BigEndian, &rd.(*rdataA).addr[i])

            // 断言和强制转换是不同的，Go中的强制转换用于普通类型之间的转换
            // 当然，得是互相之间可以转换的类型
            // var a float64 = 1
            // b := int(a)
        }
    // ...
    }
    r.RData = rd

    return nil
}
```

上述示例中还隐藏了一个Go的特性，那就是 **错误** 。Go严格的区分了错误 *（`error`）* 和异常 *（`panic`）* 两个概念，认为错误是业务过程的一部分，异常不是 *（和Java中的`Exception`和`Error`刚好相反）* 。

细心的同学会发现，代码中将`error`作为一个数据类型，以函数的返回值形式存在。调用该函数时，判断描述错误的变量值是否为空即可：

```go
if err := r.SetRData(rdata, data); err != nil {
    // 处理出现的错误
}
```

根据Go的『少即是多』设计哲学，只有需要通知上层进行必要的异常处理时，才返回`error`或抛出`panic`。否则，一律考虑使用状态、数量等形式描述，不要滥用。

## 数据传输

最后，我们定义一个函数来完成封包、发包和拆包：

```go
func Ask(server, qname string) ([]net.IP, error) {
    var names []net.IP

    reqData := pack(TypeA, qname) // 封包
    // 使用官方net包进行UDP连接
    conn, err := net.Dial("udp", server+":53")
    if err != nil {
        return nil, err
    }
    defer conn.Close() // 延迟处理
    conn.SetDeadline(time.Now().Add(time.Second * 3))
    // 发包
    if i, err := conn.Write(reqData); err != nil || i <= 0 {
        return nil, err
    }
    answers, err := unpack(conn) // 拆包
    if err != nil {
        return nil, err
    }
    for _, a := range answers {
        if a.Type != TypeA {
            continue
        }
        if ip := net.ParseIP(a.RData.value()); ip != nil {
            names = append(names, ip)
        }
    }

    return names, nil
}
```

其中官方的`net`包就不做过多解释了，大家可以去翻文档，这里重点说一下`defer`关键字。

`defer`意为推迟，后接函数 *（也可以用匿名函数组装多个动作）* ，即推迟至返回前被调用。`defer`为栈结构，定义了多个`defer`时，以先进后出顺序调用。熟悉Java的同学可以类比成`finally`语法，只是`finally`只作用于`try`代码块，而`defer`作用于整个函数。

### 封包

再看看封包的函数：

```go
func pack(qtype uint16, qname string) []byte {
    // 封Header
    // 结构体的实例化
    header := Header{
        ID:      0x0001, // !!!换行定义时必须以逗号结尾!!!
        QDCount: 1,
        ANCount: 0,
        NSCount: 0,
        ARCount: 0,
    }
    // 也可以使用另一种形式
    // header := new(Header)
    // header.ID = 0x0001
    // header.QDCount = 1
    header.SetFlag(0, 0, 0, 0, 1, 0, 0)

    // 封Question
    question := Question{
        QType:  qtype,
        QClass: ClassIN,
    }
    question.SetQName(qname)

    var buf bytes.Buffer
    binary.Write(&buf, binary.BigEndian, header)
    binary.Write(&buf, binary.BigEndian, question.QName)
    binary.Write(&buf, binary.BigEndian, []uint16{question.QType, question.QClass})

    return buf.Bytes()
}
```

简单需求的封包过程so easy，除了官方的`binary`包函数功能以外，逻辑上没有什么需要多说的。

### 拆包

把接收到的应答包拆开，取出我们需要的数据，就大功告成了：

```go
func unpack(rd io.Reader) ([]*Answer, error) {
    var (
        reader = bufio.NewReader(rd)
        data   []byte // 应答数据包缓存
        buf    []byte // 临时缓存
        err    error
        n      int
    )

    // 拆Header
    // ...

    // 拆Question
    question := new(Question)
    if buf, err = reader.ReadBytes(eof); err != nil { // 域名以0x00结尾
        return nil, err
    }
    data = append(data, buf...)
    question.QName = buf
    buf = make([]byte, 4)
    if n, err = reader.Read(buf); err != nil || n < 4 {
        return nil, err
    }
    data = append(data, buf...)
    binary.Read(bytes.NewBuffer(buf[0:2]), binary.BigEndian, &question.QType)
    binary.Read(bytes.NewBuffer(buf[2:]), binary.BigEndian, &question.QClass)

    // 拆Answer(s)
    answers := make([]*Answer, header.ANCount)
    buf, _ = reader.Peek(59)
    for i := 0; i < int(header.ANCount); i++ { // 根据Header中的ANCOUNT标识判断有几个Answer
        answer := new(Answer)
        // NAME
        var b byte
        var p uint16
        for {
            if b, err = reader.ReadByte(); err != nil {
                return nil, err
            }
            data = append(data, b)
            if b&pointer == pointer { // pointer是一个值为0xC0的byte类型常量
                buf = []byte{b ^ pointer, 0}
                if b, err = reader.ReadByte(); err != nil {
                    return nil, err
                }
                data = append(data, b)
                buf[1] = b
                binary.Read(bytes.NewBuffer(buf), binary.BigEndian, &p)
                if buf = getRefData(data, p); len(buf) == 0 {
                    return nil, errors.New("invalid answer packet")
                }
                answer.Name = append(answer.Name, buf...)
                break
            } else {
                answer.Name = append(answer.Name, b)
                if b == eof {
                    break
                }
            }
        }

        // TYPE、CLASS、TLL、RDLENGTH等其他数据
        // ...

        // RDATA
        buf = make([]byte, int(answer.RDLength))
        if n, err = reader.Read(buf); err != nil || n < int(answer.RDLength) {
            return nil, err
        }
        data = append(data, buf...)
        // 调用之前定义的SetRData()函数处理不同类型的RDATA
        if err = answer.SetRData(buf, data); err != nil {
            return nil, err
        }

        answers[i] = answer
    }

    // 拆Authority和Additional，如果有的话

    return answers, nil
}
```

这段代码稍微长一点，其中最懵逼的应该是拆Answer的NAME那一段 *（`for`代码块）* ，因为DNS协议中有一个很大的槽点我还没有介绍，那就是消息压缩 *（Message compression）* 。

### 消息压缩

DNS协议在设计时，为了减小数据包的大小，特意增加了一个消息压缩的方案 *（用不用由DNS服务器的实现决定）* ，我们直接看RFC的原文：

> In order to reduce the size of messages, the domain system utilizes a compression scheme which eliminates the repetition of domain names in a message. In this scheme, an entire domain name or a list of labels at the end of a domain name is replaced with a pointer to a prior occurance of the same name.

它使用一个代表偏移量的指针，指向之前重复出现过的域名或标签。因此，一个域名在数据包中的表现形式有三种：

1. 一串以`0x00`结束的标签
1. 一个指针
1. 一串以指针结束的标签

也就是说，它可以长这样：

```plain
3www6domain3com
```

也可以长这样：

```plain
[pointer]
```

更可以长这样：

```plain
3www6domain[pointer]
```

这个，嗯，行，设计者你开心就好。

那我们好好看看这个指针到底是怎么玩的。首先是它的结构：

```plain
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1  1|                OFFSET                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

比较简单，2个字节长度，并规定前两位必须为`1`，以和标签进行区分，其他位则为偏移量。

所以我们处理数据包中的域名时，只能对每个字节进行遍历，将它和`0xC0`进行按位与运算，若结果为`0xC0`，则认为它和后续一个字节组成了一个指针，再将它和`0xC0`进行按位异或运算，并与后一字节合并求得偏移量，否则直至`0x00`结束遍历 *（如果对这个过程描述比较模糊，建议对照前面的`for`代码块进行理解）* 。

拿到偏移量之后千万不要天真的认为，直接在我们缓存的应答数据中偏移对应字节，就可以顺利的读取到以`0x00`结束的域名的剩余标签了。因为这个压缩方案是可递归的！也就是说，你用偏移量拿到的标签串中，还有可能是以指针结束的！苍天饶过谁。

既然这样，我们还是写个函数来单独处理吧：

```go
func getRefData(data []byte, p uint16) []byte {
    var refData []byte

    // 从初始偏移量开始对应答数据包缓存进行遍历
    for i := int(p); i < len(data); i++ {
        // 读到新指针
        if b := data[i]; b&pointer == pointer {
            if i+1 >= len(data) {
                return []byte{}
            }
            // 更新偏移量，继续遍历
            binary.Read(bytes.NewBuffer([]byte{b^pointer, data[i+1]}), binary.BigEndian, &p)
            i = int(p - 1)
        } else {
            refData = append(refData, b)
            // 读到0x00即可结束
            if b == eof {
                break
            }
        }
    }

    return refData
}
```

至此，基本上可以满足我们解析域名得到IP的需求，Authority和Additional的处理与Answer基本相同，这里就不再继续了。

## 库调用

现在，我们可以在自己的脚本中引入`dns`包来调用其中的对象了：

```go
package main // 需要定义入口函数main()，就必须打成main包

import "github.com/gyyyy/dns"
// ...

// 入口函数
func main() {
    if ips, err := dns.Ask("8.8.8.8", "www.domain.com"); err == nil {
        // 得到解析后的IP列表
    }
}
```

如果我们希望批量解析，定一个小目标，一亿个域名，看着它这么一个个的跑肯定会出人命的。那我们最后来看看这个为云计算而生的Go自带的高并发光环吧：

```go
func getDomain() chan string {
    ch := make(chan string, 10) // 创建一个通道，10个缓存空间，用于goroutine间的数据传输

    go func() { // 使用go关键字，创建一个新的goroutine来执行该匿名函数，即多线程
        for _, domain := range domainList {
            ch <- domain
        }
        close(ch) // 关闭通道
    }()

    return ch
}

func main() {
    var wg sync.WaitGroup // 官方sync包中对象，可用于阻塞主线程，等待所有goroutine执行结束
    ch := getDomain()   // 该方法中的逻辑是异步执行的

    for c := range ch { // 遍历直至通道关闭
        wg.Add(1)
        go func(domain string) { // 为每个域名单独创建一个goroutine处理
            defer wg.Done() // 相当于wg.Add(-1)

            if ips, err := dns.Ask("8.8.8.8", domain); err == nil {
                // ...
            }
        }(c)
    }

    wg.Wait()
}
```

在当然你也可以创建多个生产者、消费者、资源池，以及多个公共DNS服务器来提高并发，只是，你的CPU和网络还好么 ;)

## 参考

1. [DOMAIN NAMES - CONCEPTS AND FACILITIES](http://www.ietf.org/rfc/rfc1034.txt)
1. [DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](http://www.ietf.org/rfc/rfc1035.txt)
1. [Awesome Go](https://github.com/avelino/awesome-go/)
1. [Alternative (more granular) approach to a DNS library](https://github.com/miekg/dns/)
1. [DNSPython](https://github.com/rthalley/dnspython/)