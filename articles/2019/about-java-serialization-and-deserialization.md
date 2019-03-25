# 浅析Java序列化和反序列化

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-java-blue.svg)
![Vuln Type](https://img.shields.io/badge/vuln_type-rce-red.svg)
![Tag](https://img.shields.io/badge/tag-deserialization-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1547407335-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 别说你懂反序列化，也别再说你不懂反序列化。</sub>

## 序列化机制

序列化 *（Serialization）* 是指将数据结构或对象状态转换成字节流 *（例如存储成文件、内存缓冲，或经由网络传输）* ，以留待后续在相同或另一台计算机环境中，能够恢复对象原来状态的过程。序列化机制在Java中有着广泛的应用，EJB、RMI、Hessian等技术都以此为基础。

### 序列化

我们先用一个简单的序列化示例来看看Java究竟是如何对一个对象进行序列化的：

```java
public class SerializationDemo implements Serializable {
    private String stringField;
    private int intField;

    public SerializationDemo(String s, int i) {
        this.stringField = s;
        this.intField = i;
    }

    public static void main(String[] args) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bout);
        out.writeObject(new SerializationDemo("gyyyy", 97777));
    }
}
```

如果熟悉PHP的同学应该知道，这个对象在经过PHP序列化后得到的字符串如下 *（因为PHP与Java的编程习惯有所区别，这里字段访问权限全改为了`public`，`private`和`protected`从表现形式上来说差不多，只是多了些特殊的标识而已，为了减少一些零基础的同学不必要的疑惑，这里暂不讨论）* ：

```plain
O:17:"SerializationDemo":2:{s:11:"stringField";s:5:"gyyyy";s:8:"intField";i:97777;}
```

其中，`O:17:"..."`表示当前是一个对象，以及该对象类名的字符串长度和值，`2:{...}`表示该类有2个字段 *（元素间用`;`分隔，键值对也分为前后两个元素表示，也就是说，如果是2个字段，则总共会包含4个元素）* ，`s:11:"..."`表示当前是一个长度为11的字符串，`i:...`表示当前是一个整数。

由此可知，PHP序列化字符串基本上是可人读的，而且对于类对象来说，字段等成员属性的序列化顺序与定义顺序一致。我们完全可以通过手工的方式来构造任意一个PHP对象的序列化字符串。

而该对象经过Java序列化后得到的则是一个二进制串：

```plain
ac ed 00 05 73 72 00 11  53 65 72 69 61 6c 69 7a    ....sr.. Serializ
61 74 69 6f 6e 44 65 6d  6f d9 35 3c f7 d6 0a c6    ationDem o.5<....
d5 02 00 02 49 00 08 69  6e 74 46 69 65 6c 64 4c    ....I..i ntFieldL
00 0b 73 74 72 69 6e 67  46 69 65 6c 64 74 00 12    ..string Fieldt..
4c 6a 61 76 61 2f 6c 61  6e 67 2f 53 74 72 69 6e    Ljava/la ng/Strin
67 3b 78 70 00 01 7d f1  74 00 05 67 79 79 79 79    g;xp..}. t..gyyyy
```

仔细观察二进制串中的部分可读数据，我们也可以差不多分辨出该对象的一些基本内容。但同样为了手写的目的 *（为什么有这个目的？原因很简单，为了不被语言环境束缚）* ，以及为接下来的序列化执行流程分析做准备，我们先依次来解读一下这个二进制串中的各个元素。

- `0xaced`，魔术头
- `0x0005`，版本号 *（JDK主流版本一致，下文如无特殊标注，都以JDK8u为例）*
- `0x73`，对象类型标识 *（`0x7n`基本上都定义了类型标识符常量，但也要看出现的位置，毕竟它们都在可见字符的范围，详见`java.io.ObjectStreamConstants`）*
- `0x72`，类描述符标识
- `0x0011...`，类名字符串长度和值 *（Java序列化中的UTF8格式标准）*
- `0xd9353cf7d60ac6d5`，序列版本唯一标识 *（`serialVersionUID`，简称SUID）*
- `0x02`，对象的序列化属性标志位，如是否是Block Data模式、自定义`writeObject()`，`Serializable`、`Externalizable`或`Enum`类型等
- `0x0002`，类的字段个数
- `0x49`，整数类型签名的第一个字节，同理，之后的`0x4c`为字符串类型签名的第一个字节 *（类型签名表示与JVM规范中的定义相同）*
- `0x0008...`，字段名字符串长度和值，非原始数据类型的字段还会在后面加上数据类型标识、完整类型签名长度和值，如之后的`0x740012...`
- `0x78` Block Data结束标识
- `0x70` 父类描述符标识，此处为`null`
- `0x00017df1` 整数字段`intField`的值 *（Java序列化中的整数格式标准）* ，非原始数据类型的字段则会按对象的方式处理，如之后的字符串字段`stringField`被识别为字符串类型，输出字符串类型标识、字符串长度和值

由此可以看出，除了基本格式和一些整数表现形式上的不同之外，Java和PHP的序列化结果还是存在很多相似的地方，比如除了具体值外都会对类型进行描述。

需要注意的是，Java序列化中对字段进行封装时，会按原始和非原始数据类型排序 *（有同学可能想问为什么要这么做，这里我只能简单解释原因有两个，一是因为它们两个的表现形式不同，原始数据类型字段可以直接通过偏移量读取固定个数的字节来赋值；二是在封装时会计算原始类型字段的偏移量和总偏移量，以及非原始类型字段的个数，这使得反序列化阶段可以很方便的把原始和非原始数据类型分成两部分来处理）* ，且其中又会按字段名排序。

而开头固定的`0xaced0005`也可以作为Java序列化二进制串 *（Base64编码为`rO0AB...`）* 的识别标识。

让我们把这个对象再改复杂些：

```java
class SerializationSuperClass implements Serializable {
    private String superField;
}

class SerializationComponentClass implements Serializable {
    private String componentField;
}

public class SerializationDemo extends SerializationSuperClass implements Serializable {
    private SerializationComponentClass component;
    // omit
}
```

它序列化后的二进制串大家可以自行消化理解一下，注意其中的嵌套对象，以及`0x71`表示的`Reference`类型标识 *（形式上与JVM的常量池类似，用于非原始数据类型的引用对象池索引，这个引用对象池在序列化和反序列化创建时的元素填充顺序会保持一致）* ：

```plain
ac ed 00 05 73 72 00 11  53 65 72 69 61 6c 69 7a    ....sr.. Serializ
61 74 69 6f 6e 44 65 6d  6f 1a 7f cd d3 53 6f 6b    ationDem o....Sok
15 02 00 03 49 00 08 69  6e 74 46 69 65 6c 64 4c    ....I..i ntFieldL
00 09 63 6f 6d 70 6f 6e  65 6e 74 74 00 1d 4c 53    ..compon entt..LS
65 72 69 61 6c 69 7a 61  74 69 6f 6e 43 6f 6d 70    erializa tionComp
6f 6e 65 6e 74 43 6c 61  73 73 3b 4c 00 0b 73 74    onentCla ss;L..st
72 69 6e 67 46 69 65 6c  64 74 00 12 4c 6a 61 76    ringFiel dt..Ljav
61 2f 6c 61 6e 67 2f 53  74 72 69 6e 67 3b 78 72    a/lang/S tring;xr
00 17 53 65 72 69 61 6c  69 7a 61 74 69 6f 6e 53    ..Serial izationS
75 70 65 72 43 6c 61 73  73 de c6 50 b7 d1 2f a3    uperClas s..P../.
27 02 00 01 4c 00 0a 73  75 70 65 72 46 69 65 6c    '...L..s uperFiel
64 71 00 7e 00 02 78 70  70 00 01 7d f1 73 72 00    dq.~..xp p..}.sr.
1b 53 65 72 69 61 6c 69  7a 61 74 69 6f 6e 43 6f    .Seriali zationCo
6d 70 6f 6e 65 6e 74 43  6c 61 73 73 3c 76 ba b7    mponentC lass<v..
dd 9e 76 c4 02 00 01 4c  00 0e 63 6f 6d 70 6f 6e    ..v....L ..compon
65 6e 74 46 69 65 6c 64  71 00 7e 00 02 78 70 70    entField q.~..xpp
74 00 05 67 79 79 79 79                             t..gyyyy
```

简单的分析一下序列化的执行流程：

1. `ObjectOutputStream`实例初始化时，将魔术头和版本号写入`bout` *（`BlockDataOutputStream`类型）* 中
1. 调用`ObjectOutputStream.writeObject()`开始写对象数据
    - `ObjectStreamClass.lookup()`封装待序列化的类描述 *（返回`ObjectStreamClass`类型）* ，获取包括类名、自定义`serialVersionUID`、可序列化字段 *（返回`ObjectStreamField`类型）* 和构造方法，以及`writeObject`、`readObject`方法等
    - `writeOrdinaryObject()`写入对象数据
        - 写入对象类型标识
        - `writeClassDesc()`进入分支`writeNonProxyDesc()`写入类描述数据
            - 写入类描述符标识
            - 写入类名
            - 写入SUID *（当SUID为空时，会进行计算并赋值，细节见下面关于SerialVersionUID章节）*
            - 计算并写入序列化属性标志位
            - 写入字段信息数据
            - 写入Block Data结束标识
            - 写入父类描述数据
        - `writeSerialData()`写入对象的序列化数据
            - 若类自定义了`writeObject()`，则调用该方法写对象，否则调用`defaultWriteFields()`写入对象的字段数据 *（若是非原始类型，则递归处理子对象）*

### 反序列化

继续用简单的示例来看看反序列化：

```java
public static void main(String[] args) throws ClassNotFoundException {
    byte[] data; // read from file or request
    ByteArrayInputStream bin = new ByteArrayInputStream(data);
    ObjectInputStream in = new ObjectInputStream(bin);
    SerializationDemo demo = (SerializationDemo) in.readObject();
}
```

它的执行流程如下：

1. `ObjectInputStream`实例初始化时，读取魔术头和版本号进行校验
1. 调用`ObjectInputStream.readObject()`开始读对象数据
    - 读取对象类型标识
    - `readOrdinaryObject()`读取数据对象
        - `readClassDesc()`读取类描述数据
            - 读取类描述符标识，进入分支`readNonProxyDesc()`
            - 读取类名
            - 读取SUID
            - 读取并分解序列化属性标志位
            - 读取字段信息数据
            - `resolveClass()`根据类名获取待反序列化的类的`Class`对象，如果获取失败，则抛出`ClassNotFoundException`
            - `skipCustomData()`循环读取字节直到Block Data结束标识为止
            - 读取父类描述数据
            - `initNonProxy()`中判断对象与本地对象的SUID和类名 *（不含包名）* 是否相同，若不同，则抛出`InvalidClassException`
        - `ObjectStreamClass.newInstance()`获取并调用离对象最近的非`Serializable`的父类的无参构造方法 *（若不存在，则返回`null`）* 创建对象实例
        - `readSerialData()`读取对象的序列化数据
            - 若类自定义了`readObject()`，则调用该方法读对象，否则调用`defaultReadFields()`读取并填充对象的字段数据

### 关于SerialVersionUID

在Java的序列化机制中，SUID占据着很重要的位置，它相当于一个对象的指纹信息，可以直接决定反序列化的成功与否，通过上面对序列化和反序列化流程的分析也可以看出来，若SUID不一致，是无法反序列化成功的。

但是，SUID到底是如何生成的，它的指纹信息维度包括对象的哪些内容，可能还是有很多同学不太清楚。这里我们对照[官方文档](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/class.html#a4100)的说明，结合JDK的源代码来为大家简单的梳理一下。

首先`ObjectStreamClass.getSerialVersionUID()`在获取SUID时，会判断SUID是否已经存在，若不存在才调用`computeDefaultSUID()`计算默认的SUID：

```java
public long getSerialVersionUID() {
    if (suid == null) {
        suid = AccessController.doPrivileged(
            new PrivilegedAction<Long>() {
                public Long run() {
                    return computeDefaultSUID(cl);
                }
            }
        );
    }
    return suid.longValue();
}
```

先顺带提一嘴，`AccessController.doPrivileged()`会忽略JRE配置的安全策略的检查，以特权的身份去执行`PrivilegedAction`接口中的`run()`，可以防止JDK底层在进行序列化和反序列化时可能出现的一些权限问题。这些内容与本文主题无关，不多作详细解释，感兴趣的同学可以去看看Java的Security包和其中的java.policy、java.security文件内容。

重点来了，计算SUID时，会先创建一个`DataOutputStream`对象，所有二进制数据写入其包装的`ByteArrayOutputStream`中：

1. 写入类名 *（UTF8）*
    ```java
    dout.writeUTF(cl.getName());
    ```
1. 写入类访问权限标识
    ```java
    int classMods = cl.getModifiers() &
        (Modifier.PUBLIC | Modifier.FINAL |
            Modifier.INTERFACE | Modifier.ABSTRACT);
    
    Method[] methods = cl.getDeclaredMethods();
    if ((classMods & Modifier.INTERFACE) != 0) {
        classMods = (methods.length > 0) ?
            (classMods | Modifier.ABSTRACT) :
            (classMods & ~Modifier.ABSTRACT);
    }
    dout.writeInt(classMods);
    ```
1. 如果不是数组类型，写入实现接口的接口名，按接口名排序
    ```java
    if (!cl.isArray()) {
        Class<?>[] interfaces = cl.getInterfaces();
        String[] ifaceNames = new String[interfaces.length];
        for (int i = 0; i < interfaces.length; i++) {
            ifaceNames[i] = interfaces[i].getName();
        }
        Arrays.sort(ifaceNames);
        for (int i = 0; i < ifaceNames.length; i++) {
            dout.writeUTF(ifaceNames[i]);
        }
    }
    ```
1. 写入非私有静态或瞬态字段信息数据，包括字段名、字段访问权限标识和字段签名，按字段名排序
    ```java
    Field[] fields = cl.getDeclaredFields();
    MemberSignature[] fieldSigs = new MemberSignature[fields.length];
    for (int i = 0; i < fields.length; i++) {
        fieldSigs[i] = new MemberSignature(fields[i]);
    }
    Arrays.sort(fieldSigs, new Comparator<MemberSignature>() {
        public int compare(MemberSignature ms1, MemberSignature ms2) {
            return ms1.name.compareTo(ms2.name);
        }
    });
    for (int i = 0; i < fieldSigs.length; i++) {
        MemberSignature sig = fieldSigs[i];
        int mods = sig.member.getModifiers() &
            (Modifier.PUBLIC | Modifier.PRIVATE | Modifier.PROTECTED |
                Modifier.STATIC | Modifier.FINAL | Modifier.VOLATILE |
                Modifier.TRANSIENT);
        if (((mods & Modifier.PRIVATE) == 0) ||
            ((mods & (Modifier.STATIC | Modifier.TRANSIENT)) == 0))
        {
            dout.writeUTF(sig.name);
            dout.writeInt(mods);
            dout.writeUTF(sig.signature);
        }
    }
    ```
1. 如果存在类初始化器 *（不是类实例化的构造方法，感兴趣的同学可以去看看JVM规范中的相关内容）* ，写入固定的初始化器信息数据
    ```java
    if (hasStaticInitializer(cl)) {
        dout.writeUTF("<clinit>");
        dout.writeInt(Modifier.STATIC);
        dout.writeUTF("()V");
    }
    ```
1. 写入非私有构造方法信息数据，包括方法名 *（固定为`<init>`）* 、方法访问权限标识和方法签名 *（分隔符`/`会替换成`.`的包名形式）* ，按方法签名排序
    ```java
    Constructor<?>[] cons = cl.getDeclaredConstructors();
    MemberSignature[] consSigs = new MemberSignature[cons.length];
    for (int i = 0; i < cons.length; i++) {
        consSigs[i] = new MemberSignature(cons[i]);
    }
    Arrays.sort(consSigs, new Comparator<MemberSignature>() {
        public int compare(MemberSignature ms1, MemberSignature ms2) {
            return ms1.signature.compareTo(ms2.signature);
        }
    });
    for (int i = 0; i < consSigs.length; i++) {
        MemberSignature sig = consSigs[i];
        int mods = sig.member.getModifiers() &
            (Modifier.PUBLIC | Modifier.PRIVATE | Modifier.PROTECTED |
                Modifier.STATIC | Modifier.FINAL |
                Modifier.SYNCHRONIZED | Modifier.NATIVE |
                Modifier.ABSTRACT | Modifier.STRICT);
        if ((mods & Modifier.PRIVATE) == 0) {
            dout.writeUTF("<init>");
            dout.writeInt(mods);
            dout.writeUTF(sig.signature.replace('/', '.'));
        }
    }
    ```
1. 写入非私有方法，包括方法名、方法访问权限标识和方法签名，按方法名和方法签名排序
    ```java
    MemberSignature[] methSigs = new MemberSignature[methods.length];
    for (int i = 0; i < methods.length; i++) {
        methSigs[i] = new MemberSignature(methods[i]);
    }
    Arrays.sort(methSigs, new Comparator<MemberSignature>() {
        public int compare(MemberSignature ms1, MemberSignature ms2) {
            int comp = ms1.name.compareTo(ms2.name);
            if (comp == 0) {
                comp = ms1.signature.compareTo(ms2.signature);
            }
            return comp;
        }
    });
    for (int i = 0; i < methSigs.length; i++) {
        MemberSignature sig = methSigs[i];
        int mods = sig.member.getModifiers() &
            (Modifier.PUBLIC | Modifier.PRIVATE | Modifier.PROTECTED |
                Modifier.STATIC | Modifier.FINAL |
                Modifier.SYNCHRONIZED | Modifier.NATIVE |
                Modifier.ABSTRACT | Modifier.STRICT);
        if ((mods & Modifier.PRIVATE) == 0) {
            dout.writeUTF(sig.name);
            dout.writeInt(mods);
            dout.writeUTF(sig.signature.replace('/', '.'));
        }
    }
    ```

以上就是SUID中包含的类的所有信息，得到的二进制串如下：

```plain
00 11 53 65 72 69 61 6c  69 7a 61 74 69 6f 6e 44    ..Serial izationD
65 6d 6f 00 00 00 01 00  14 6a 61 76 61 2e 69 6f    emo..... .java.io
2e 53 65 72 69 61 6c 69  7a 61 62 6c 65 00 08 69    .Seriali zable..i
6e 74 46 69 65 6c 64 00  00 00 02 00 01 49 00 0b    ntField. .....I..
73 74 72 69 6e 67 46 69  65 6c 64 00 00 00 02 00    stringFi eld.....
12 4c 6a 61 76 61 2f 6c  61 6e 67 2f 53 74 72 69    .Ljava/l ang/Stri
6e 67 3b 00 06 3c 69 6e  69 74 3e 00 00 00 01 00    ng;..<in it>.....
16 28 4c 6a 61 76 61 2e  6c 61 6e 67 2e 53 74 72    .(Ljava. lang.Str
69 6e 67 3b 49 29 56 00  04 6d 61 69 6e 00 00 00    ing;I)V. .main...
09 00 16 28 5b 4c 6a 61  76 61 2e 6c 61 6e 67 2e    ...([Lja va.lang.
53 74 72 69 6e 67 3b 29  56                         String;)V
```

最后，将二进制数据通过SHA1算法得到摘要，取前8位按BigEndian的字节顺序转换成长整型：

```java
long hash = 0;
for (int i = Math.min(hashBytes.length, 8) - 1; i >= 0; i--) {
    hash = (hash << 8) | (hashBytes[i] & 0xFF);
}
```

返回的`hash`就是最终的SUID了。

由此可知，当父类或非原始数据类型字段的类内部发生变更时，并不会影响当前类的SUID值，再结合之前的内容我们还可以引申出两个结论：

1. 若当前类自定义了`readObject()`，在反序列化时会正常执行`readObject()`中所有`ObjectInputStream.defaultReadObject()` *（如果调用了的话）* 之前的逻辑；否则在处理到变更对象时，仍会抛出`InvalidClassException`
1. 由于序列化会对类的字段进行排序，并在反序列化时按顺序遍历处理，所以反序列化会正常处理字段名比变更对象类型字段『小』的其他字段

### 关于`writeReplace()`和`readResolve()`

在前面的执行流程分析中，为了突出主要逻辑，我们主观的忽略了一些内容，其中就包括了序列化的`invokeWriteReplace()`和反序列化的`invokeReadResolve()`。

现在就来看看它们分别有什么作用：

- `writeReplace()`

    返回一个对象，该对象为实际被序列化的对象，在原对象序列化之前被调用，替换原对象成为待序列化对象

- `readResolve()`

    返回一个对象，该对象为实际反序列化的结果对象，在原对象反序列化之后被调用，不影响原对象的反序列化过程，仅替换结果

再从具体示例来体会一下：

```java
public class SerializationReplacementClass implements Serializable {
    protected String replacementField;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
    }

    private Object readResolve() {
        return new SerializationReplacementClass("resolve");
    }

    private SerializationReplacementClass(String s) {
        this.replacementField = s;
    }

    public SerializationReplacementClass() {
        this.replacementField = "replace";
    }
}

public class SerializationDemo implements Serializable {
    // omit
    private Object writeReplace() {
        return new SerializationReplacementClass();
    }
    // omit

    public static void main(String[] args) throws ClassNotFoundException {
        // omit
        SerializationReplacementClass demo = (SerializationReplacementClass) in.readObject();
    }
}
```

从序列化之后得到的二进制串中可以看到目标对象已经被替换成了`SerializationReplacementClass`：

```plain
ac ed 00 05 73 72 00 1d  53 65 72 69 61 6c 69 7a    ....sr.. Serializ
61 74 69 6f 6e 52 65 70  6c 61 63 65 6d 65 6e 74    ationRep lacement
43 6c 61 73 73 32 71 ac  e9 c1 d3 0b 7b 02 00 01    Class2q. ....{...
4c 00 10 72 65 70 6c 61  63 65 6d 65 6e 74 46 69    L..repla cementFi
65 6c 64 74 00 12 4c 6a  61 76 61 2f 6c 61 6e 67    eldt..Lj ava/lang
2f 53 74 72 69 6e 67 3b  78 70 74 00 07 72 65 70    /String; xpt..rep
6c 61 63 65                                         lace
```

而在反序列化之后得到的对象的`replacementField`字段值则为`resolve`，但在此之前`readObject()`也会被正常调用，当时`replacementField`字段值为`replace`。

### 关于`Externalizable`

`Serializable`接口还有一个比较常见的子类`Externalizable`，它比它爸爸特殊的地方就在于它需要自己实现读写方法 *（`readExternal()`和`writeExternal()`）* ，同时必须包含一个自己的无参构造方法 *（默认隐式的也可以）* 。

仍以示例说话：

```java
public class ExternalizationDemo implements Externalizable {
    private String stringField;
    private int intField;

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeUTF(this.stringField);
        out.writeInt(this.intField);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        this.stringField = "hello, i'm " + in.readUTF();
        this.intField = in.readInt() + 100000;
    }

    public ExternalizationDemo(String s, int i) {
        this.stringField = s;
        this.intField = i;
    }

    public ExternalizationDemo() {}
}
```

序列化之后得到的二进制串如下：

```plain
ac ed 00 05 73 72 00 13  45 78 74 65 72 6e 61 6c    ....sr.. External
69 7a 61 74 69 6f 6e 44  65 6d 6f d9 a9 04 75 84    izationD emo...u.
5d 06 8f 0c 00 00 78 70  77 0b 00 05 67 79 79 79    ].....xp w...gyyy
79 00 01 7d f1 78                                   y..}.x
```

与`Serializable`的区别：

- 对象的序列化属性标志位为`0x0c`，包括`Serializable`和Block Data的标志
- 序列化类的字段个数固定为0
- 序列化调用`writeExternalData()`转给类自定义的写方法，将写入的数据包装在新的Block Data块中，第一个字节为块长度 *（不含块头尾标识）*
- 反序列化调用`readExternalData()`转给类自定义的读方法，再调用对象的无参构造方法 *（若不存在，则返回`null`）* 进行实例化

## 反序列化漏洞

通过以上对Java的序列化机制的大致了解，我们可以想象一个场景 *（有基础的同学可以跳过本部分内容，当然，看一看也没坏处）* ：

> 当服务端允许接收远端数据进行反序列化时，客户端可以提供任意一个服务端存在的对象 *（包括依赖包中的对象）* 的序列化二进制串，由服务端反序列化成相应对象。如果该对象是由攻击者『精心构造』的恶意对象，而它自定义的`readObject()`中存在着一些『不安全』的逻辑，那么在对它反序列化时就有可能出现安全问题。

说到这，我提三个问题，请大家跟着我的思路去分析，先来看看第一个：

1. 为什么需要依赖反序列化对象的自定义`readObject()`？

大家都知道，正常来说，反序列化只是一个对象实例化然后赋值的过程，如果之后不主动调用它的内部方法，理论上最多只能控制它字段的值而已。那么有没有什么办法能够让它执行反序列化以外的逻辑呢？毕竟做的越多中间产生问题的概率就越大。

我们还是先以大家更熟悉的PHP来举个例。在PHP内部，保留了十多个被称为魔术方法的类方法，这些魔术方法一般会伴随着类的生命周期被PHP底层自动调用，用户可以在类中显式定义它们的逻辑。

就拿与反序列化关系最密切的`__wakeup()`来说，我们回到最初的那个类`SerializationDemo`，给它加一点东西：

```php
class SerializationDemo {
    public function __wakeup() {
        echo $this->stringField;
    }
}
```

在反序列化`SerializationDemo`这个对象时，就会调用`__wakeup()`执行里面的逻辑。示例中的逻辑只是输出一个字符串，如果改成`exec($this->stringField);`呢？

实际当然不会这么简单，有可能它是把自己的字段作为值作为参数调用了某个类的方法，而那个方法里对参数做了某些不安全的操作，甚至有可能经过多个类多个方法调用，形成一个调用链。

这就是默认的反序列化逻辑的一个逃逸过程。

到这里你可能已经想到了，Java反序列化中`readObject()`的作用其实就相当于PHP反序列化中的那些魔术方法，使反序列化过程在一定程度上受控成为可能，但也只是可能而已，是否真的可控，还是需要分析每个对象的`readObject()`具体是如何实现的 *（别急，后面有章节会有详细介绍）* 。

接着看第二个问题：

2. 反序列化对象的非`Serializable`父类无参构造方法是否能像PHP中的`__construct()`一样被利用？

答案应该是不行的。因为前面已经提到过，我们只能够控制反序列化对象的字段值，而Java与PHP不同的是，JDK底层会先调用无参构造方法实例化，再读取序列化的字段数据赋值，所以我们没有办法将可控的字段值在实例化阶段传入构造方法中对其内部逻辑产生影响。

最后一个：

3. `readResolve()`对反序列化漏洞有什么影响？

`readResolve()`只是替换反序列化结果对象，若是结果对象本身存在安全问题，它有可能让问题中断；若是`readObject()`存在安全问题，它无法避免。

### 经典的Apache Commons Collections

好，有了上面的基础，我们也照一回惯例，带大家一起分析一下Java历史上最出名也是最具代表性的Apache Commons Collections反序列化漏洞。

网上很多文章都是以WebLogic为漏洞环境，我们尊重开源，围绕1.637版本的Jenkins来开个头，先简单看看它的Cli组件的反序列化场景 *（这里只以CLI-connect协议为例，CLI2-connect会多出来一个SSL加解密的过程，这也是很多公开PoC在模拟Cli握手时选择CLI-connect协议的原因）* ：

1. 客户端向发送一个UTF8字符串`Protocol:CLI-connect`，前两位为字符串长度
1. 服务端`TcpSlaveAgentListener`在接收到数据之后，会创建一个`ConnectionHandler`对象读取一个UTF8字符串，判断协议版本，交给对应的协议进行处理
    - `CliProtocol`响应`Welcome`字符串，由`ChannelBuilder`为两端创建一个包含了`Connection`对象 *（IO流对象在里面）* 的`Channel`通信通道，并调用`negotiate()`进行交互
        - `Capability.writePreamble()`响应序列化后的`Capability`对象，其中使用`Mode.TEXT.wrap()`将输出流包装为`BinarySafeStream`，它会在写时进行Base64编码
        - 由于`ChannelBuilder`在build之前，调用了`withMode()`设置`mode`为`Mode.BINARY`，因此还会响应一个`0x00000000`
        - 等待接收后续数据，判断数据内容前缀为`Capability.PREAMBLE` *（`<===[JENKINS REMOTING CAPACITY]===>`）* 时，将`InputStream`传给`Capability.read()`
            - `Capability`同样会对输入流做一次`BinarySafeStream`包装，保证在读数据时解码得到原始二进制数据，再扔给输入流的`readObject()`继续读

回看`Connection`中自定义的`readObject()`，是一个普普通通的`ObjectInputStream`反序列化：

```java
public <T> T readObject() throws IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStream(in);
    return (T)ois.readObject();
}
```

现在我们假设已知1.637版本的Jenkins引用了存在反序列化漏洞的Commons Collections的版本的Jar包，那么只需要利用它构造一个恶意对象的序列化串，在与Jenkins Cli完成握手之后，将其Base64编码后的字符串发送过去就行了 *（当然，千万别忘了前面那串酷酷的前缀）* 。

### Payload构造

好的，现在让我们聚焦到Commons Collections内部，看看前辈们是如何利用它来让应用『产生』问题的。

我们先预备一个基本知识，在Java中，若想通过其原生JDK提供的接口执行系统命令，最常见的语句如下：

```java
Runtime rt = Runtime.getRuntime();
rt.exec(cmd);
```

很简单，一个单例模式的方法获取到`Runtime`的实例，再调用它的`exec()`执行命令。在表达式注入类RCE漏洞中也可以频繁看到利用各种条件特性来构造这段语句的身影，比如Struts2的OGNL：

```java
@java.lang.Runtime@getRuntime().exec(cmd)
```

又比如Spring的SpEL：

```java
T(java.lang.Runtime).getRuntime().exec(cmd)
```

这里替小白问个基础但又和接下来的内容有关的问题：为什么都要使用链式结构？

原因其实很简单，因为无论是表达式解析执行还是反序列化时，底层通过反射技术获取对象调用函数都会存在一个上下文环境，使用链式结构的语句可以保证执行过程中这个上下文是一致的。你也可以换个方式问自己，如果你第一次请求`Runtime.getRuntime()`，那如何保证第二次请求`rt.exec()`能够拿到第一次的`Runtime`对象呢？

了解了这个问题之后，我们就可以开始尝试用Commons Collections先来构造这个链式结构了。

前辈们为我们在Commons Collections中找到了一个用于对象之间转换的`Transformer`接口，它有几个我们用得着的实现类：

1. `ConstantTransformer`
    ```java
    public ConstantTransformer(Object constantToReturn) {
        super();
        iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return iConstant;
    }
    ```
1. `InvokerTransformer`
    ```java
    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }

    public Object transform(Object input) {
        // omit
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
        // omit
    }
    ```
1. `ChainedTransformer`
    ```java
    public ChainedTransformer(Transformer[] transformers) {
        super();
        iTransformers = transformers;
    }

    public Object transform(Object object) {
        for (int i = 0; i < iTransformers.length; i++) {
            object = iTransformers[i].transform(object);
        }
        return object;
    }
    ```

利用这几个对象，可以构造出下面这条链：

```java
Transformer[] trans = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
        new InvokerTransformer("invoke", new Class[] { Object.class, Object[].class }, new Object[] { null, new Object[0] }),
        new InvokerTransformer("exec", new Class[] { String.class }, new Object[] { cmd })};
Transformer chain = new ChainedTransformer(trans);
```

其中，数组的中间两个元素是最让人费解的，我们一句一句来解释 *（前方高能预警，请对照上面几个`Transformer`的逻辑仔细看，接下来的内容网上有些解释是存在出入的）* ：

1. 构造一个`ConstantTransformer`，把`Runtime`的`Class`对象传进去，在`transform()`时，始终会返回这个对象
1. 构造一个`InvokerTransformer`，待调用方法名为`getMethod`，参数为`getRuntime`，在`transform()`时，传入1的结果，此时的`input`应该是`java.lang.Runtime`，但经过`getClass()`后，`cls`为`java.lang.Class`，之后的`getMethod()`只能获取`java.lang.Class`的方法，因此才会定义的待调用方法名为`getMethod`，然后其参数才是`getRuntime`，它得到的是`getMethod`这个方法的`Method`对象，`invoke()`调用这个方法，最终得到的才是`getRuntime`这个方法的`Method`对象
1. 构造一个`InvokerTransformer`，待调用方法名为`invoke`，参数为空，在`transform()`时，传入2的结果，同理，`cls`将会是`java.lang.reflect.Method`，再获取并调用它的`invoke`方法，实际上是调用上面的`getRuntime()`拿到`Runtime`对象
1. 构造一个`InvokerTransformer`，待调用方法名为`exec`，参数为命令字符串，在`transform()`时，传入3的结果，获取`java.lang.Runtime`的`exec`方法并传参调用
1. 最后把它们组装成一个数组全部放进`ChainedTransformer`中，在`transform()`时，会将前一个元素的返回结果作为下一个的参数，刚好满足需求

既然第2、3步这么绕，我们又知道了为什么，是不是可以考虑用下面这种逻辑更清晰的方式来构造呢：

```java
Transformer[] trans = new Transformer[] {
        new ConstantTransformer(Runtime.getRuntime()),
        new InvokerTransformer("getRuntime", new Class[0], new Object[0]),
        new InvokerTransformer("exec", new Class[] { String.class }, new Object[] { cmd })};
```

答案是不行的。虽然单看整个链，无论是定义还是执行都是没有任何问题的，但是在后续序列化时，由于`Runtime.getRuntime()`得到的是一个对象，这个对象也需要参与序列化过程，而`Runtime`本身是没有实现`Serializable`接口的，所以会导致序列化失败。

也有同学可能看过ysoserial构造的Payload，它的习惯是先定义一个包含『无效』`Transformer`的`ChainedTransformer`，等所有对象装填完毕之后再利用反射将实际的数组放进去。这么做的原因作者也在一个[Issue](https://github.com/frohoff/ysoserial/issues/32)中给了解释，我们直接看原文：

> Generally any reflection at the end of gadget-chain set up is done to "arm" the chain because constructing it while armed can result in premature "detonation" during set-up and cause it to be inert when serialized and deserialized by the target application.

现在，有了这条`Transformer`链，就等着谁来执行它的`transform()`了。

网上流传的示例很多都是使用一个名为`TransformedMap`的装饰器来触发`transform()`，它在装饰时会传入原始`Map`、一个键转换器`Transformer`和一个值转换器`Transformer`，而它的父类在内部实现了一个`AbstractMapEntryDecorator`的子类，会在`setValue()`前调用`checkSetValue()`进行检查，而`TransformedMap.checkSetValue()`会调用它的值转换器的`transform()`，因此装饰任意一个有元素的`Map`就可以满足需求：

```java
Map m = TransformedMap.decorate(new HashMap(){{ put("value", "anything"); }}, null, chain);
```

这时，我们只需要再找一个包含可控`Map`字段，并会在反序列化时对这个`Map`进行`setValue()`或`get()`操作的公共对象。

幸运的是，前辈们在JDK较早的版本中发现了`AnnotationInvocationHandler`这个对象 *（较新版本的JDK可以使用`BadAttributeValueExpException`，在这里就不展开了）* ，它在初始化时可以传入一个`Map`类型参数赋值给字段`memberValues`，`readObject()`过程中如果满足一定条件就会对`memberValues`中的元素进行`setValue()`：

```java
private void readObject(java.io.ObjectInputStream s)
    s.defaultReadObject();

    AnnotationType annotationType = null;
    try {
        annotationType = AnnotationType.getInstance(type);
    } catch(IllegalArgumentException e) {
        throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
    }

    Map<String, Class<?>> memberTypes = annotationType.memberTypes();

    for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
        String name = memberValue.getKey();
        Class<?> memberType = memberTypes.get(name);
        if (memberType != null) {
            Object value = memberValue.getValue();
            if (!(memberType.isInstance(value) ||
                    value instanceof ExceptionProxy)) {
                memberValue.setValue(
                    new AnnotationTypeMismatchExceptionProxy(
                        value.getClass() + "[" + value + "]").setMember(
                            annotationType.members().get(name)));
            }
        }
    }
}
```

可以看到，在遍历`memberValues.entrySet()`时，会用键名在`memberTypes`中尝试获取一个`Class`，并判断它是否为`null`，这就是刚才说的需要满足的条件。接下来是网上很少提到过的一个结论：

首先，`memberTypes`是`AnnotationType`的一个字段，里面存储着`Annotation`接口声明的方法信息 *（键名为方法名，值为方法返回类型）* 。因此，我们在获取`AnnotationInvocationHandler`实例时，需要传入一个方法个数大于0的`Annotation`子类 *（一般来说，若方法个数大于0，都会包含一个名为`value`的方法）* ，并且原始`Map`中必须存在任意以这些方法名为键名的元素，且元素值不是该方法返回类型的实例，才能顺利进入`setValue()`的流程：

```java
Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor ctor = cls.getDeclaredConstructors()[0];
ctor.setAccessible(true);
Object o = ctor.newInstance(Target.class, m);
```

以上是`TransformedMap`的利用构造过程。而ysoserial官方更倾向于使用`LazyMap`作为装饰器，它在装饰时会传入原始`Map`和一个`Transformer`作为工厂，当`get()`获取值时，若键不存在，就会调用工厂的`transform()`创建一个新值放入`Map`中，因此装饰任意一个空`Map`也可以满足需求：

```java
Map m = LazyMap.decorate(new HashMap(), chain);
```

但与`TransformedMap`不同的是，`AnnotationInvocationHandler.readObject()`中并没有直接的对`memberTypes`执行`get()`操作，反而是在它的`invoke()`中存在`get()`，但又对方法名有一定的要求：

```java
public Object invoke(Object proxy, Method method, Object[] args) {
    String member = method.getName();
    Class<?>[] paramTypes = method.getParameterTypes();

    if (member.equals("equals") && paramTypes.length == 1 &&
        paramTypes[0] == Object.class)
        return equalsImpl(args[0]);
    assert paramTypes.length == 0;
    if (member.equals("toString"))
        return toStringImpl();
    if (member.equals("hashCode"))
        return hashCodeImpl();
    if (member.equals("annotationType"))
        return type;

    Object result = memberValues.get(member);
    // omit
}
```

所以，ysoserial使用Java动态代理的方式处理了`LazyMap`，使`readObject()`在调用`memberValues.entrySet()`时代理进入`AnnotationInvocationHandler.invoke()`阶段，刚好方法名`entrySet`也可以顺利的跳过前面的几个判断条件，最终达到目的。这也是为什么Payload中会包含两个`AnnotationInvocationHandler`的原因。

### 修复方案

Jenkins在1.638版本的`Connection.readObject()`中，将默认的`ObjectInputStream`改为了其自定义的子类`ObjectInputStreamEx`，并传入`ClassFilter.DEFAULT`校验过滤：

```java
public <T> T readObject() throws IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStreamEx(in,
            getClass().getClassLoader(), ClassFilter.DEFAULT);
    return (T)ois.readObject();
}
```

`ClassFilter.DEFAULT`长这样：

```java
public static final ClassFilter DEFAULT = new ClassFilter() {
    protected boolean isBlacklisted(String name) {
        if (name.startsWith("org.codehaus.groovy.runtime.")) {
            return true;
        } else if (name.startsWith("org.apache.commons.collections.functors.")) {
            return true;
        } else {
            return name.contains("org.apache.xalan");
        }
    }
};
```

还是一个简简单单的黑名单。

## POP的艺术

既然反序列化漏洞常见的修复方案是黑名单，就存在被绕过的风险，一旦出现新的POP链，原来的防御也就直接宣告无效了。

所以在反序列化漏洞的对抗史中，除了有大佬不断的挖掘新的反序列化漏洞点，更有大牛不断的探寻新的POP链。

POP已经成为反序列化区别于其他常规Web安全漏洞的一门特殊艺术。

既然如此，我们就用ysoserial这个项目，来好好探究一下现在常用的这些RCE类POP中到底有什么乾坤：

- BeanShell1
    - 命令执行载体：`bsh.Interpreter`
    - 反序列化载体：`PriorityQueue`
    - `PriorityQueue.readObject()`反序列化所有元素后，通过`comparator.compare()`进行排序，该`comparator`被代理给`XThis.Handler`处理，其`invoke()`会调用`This.invokeMethod()`从`Interpreter`解释器中解析包含恶意代码的`compare`方法并执行
- C3P0
    - 命令执行载体：`bsh.Interpreter`
    - 反序列化载体：`com.mchange.v2.c3p0.PoolBackedDataSource`
    - `PoolBackedDataSource.readObject()`进行到父类`PoolBackedDataSourceBase.readObject()`阶段，会调用`ReferenceIndirector$ReferenceSerialized.getObject()`获取对象，其中`InitialContext.lookup()`会去加载远程恶意对象并初始化，导致命令执行，有些同学可能不太清楚远程恶意对象的长相，举个简单的例子：
        ```java
        public class Malicious {
            public Malicious() {
                java.lang.Runtime.getRuntime().exec("calc.exe");
            }
        }
        ```
- Clojure
    - 命令执行载体：`clojure.core$comp$fn__4727`
    - 反序列化载体：`HashMap`
    - `HashMap.readObject()`反序列化各元素时，通过它的`hashCode()`得到hash值，而`AbstractTableModel$ff19274a.hashCode()`会从`IPersistentMap`中取`hashCode`键的值对象调用其`invoke()`，最终导致Clojure Shell命令字符串执行
- CommonsBeanutils1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`PriorityQueue`
    - `PriorityQueue.readObject()`执行排序时，`BeanComparator.compare()`会根据`BeanComparator.property` *（值为`outputProperties`）* 调用`TemplatesImpl.getOutputProperties()`，它在`newTransformer()`时会创建`AbstractTranslet`实例，导致精心构造的Java字节码被执行
- CommonsCollections1
    - 命令执行载体：`org.apache.commons.collections.functors.ChainedTransformer`
    - 反序列化载体：`AnnotationInvocationHandler`
    - 见前文
- CommonsCollections2
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`PriorityQueue`
    - `PriorityQueue.readObject()`执行排序时，`TransformingComparator.compare()`会调用`InvokerTransformer.transform()`转换元素，进而获取第一个元素`TemplatesImpl`的`newTransformer()`并调用，最终导致命令执行
- CommonsCollections3
    - 命令执行载体：`org.apache.commons.collections.functors.ChainedTransformer`
    - 反序列化载体：`AnnotationInvocationHandler`
    - 除`Transformer`数组元素组成不同外，与CommonsCollections1基本一致
- CommonsCollections4
    - 命令执行载体：`org.apache.commons.collections.functors.ChainedTransformer`
    - 反序列化载体：`PriorityQueue`
    - `PriorityQueue.readObject()`执行排序时，`TransformingComparator.compare()`会调用`ChainedTransformer.transform()`转换元素，进而遍历执行`Transformer`数组中的每个元素，最终导致命令执行
- CommonsCollections5
    - 命令执行载体：`org.apache.commons.collections.functors.ChainedTransformer`
    - 反序列化载体：`BadAttributeValueExpException`
    - `BadAttributeValueExpException.readObject()`当`System.getSecurityManager()`为`null`时，会调用`TiedMapEntry.toString()`，它在`getValue()`时会通过`LazyMap.get()`取值，最终导致命令执行
- CommonsCollections6
    - 命令执行载体：`org.apache.commons.collections.functors.ChainedTransformer`
    - 反序列化载体：`HashSet`
    - `HashSet.readObject()`反序列化各元素后，会调用`HashMap.put()`将结果放进去，而它通过`TiedMapEntry.hashCode()`计算hash时，会调用`getValue()`触发`LazyMap.get()`导致命令执行
- Groovy1
    - 命令执行载体：`org.codehaus.groovy.runtime.MethodClosure`
    - 反序列化载体：`AnnotationInvocationHandler`
    - `AnnotationInvocationHandler.readObject()`在通过`memberValues.entrySet()`获取`Entry`集合，该`memberValues`被代理给`ConvertedClosure`拦截`entrySet`方法，根据`MethodClosure`的构造最终会由`ProcessGroovyMethods.execute()`执行系统命令
- Hibernate1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`HashMap`
    - `HashMap.readObject()`通过`TypedValue.hashCode()`计算hash时，`ComponentType.getPropertyValue()`会调用`PojoComponentTuplizer.getPropertyValue()`获取到`TemplatesImpl.getOutputProperties`方法并调用导致命令执行
- Hibernate2
    - 命令执行载体：`com.sun.rowset.JdbcRowSetImpl`
    - 反序列化载体：`HashMap`
    - 执行过程与Hibernate1一致，但Hibernate2并不是传入`TemplatesImpl`执行系统命令，而是利用`JdbcRowSetImpl.getDatabaseMetaData()`调用`connect()`连接到远程RMI
- JBossInterceptors1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`org.jboss.interceptor.proxy.InterceptorMethodHandler`
    - `InterceptorMethodHandler.readObject()`在`executeInterception()`时，会根据`SimpleInterceptorMetadata`拿到`TemplatesImpl`放进`ArrayList`中，并传入`SimpleInterceptionChain`进行初始化，它在调用`invokeNextInterceptor()`时会导致命令执行
- JSON1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`HashMap`
    - `HashMap.readObject()`将各元素放进`HashMap`时，会调用`TabularDataSupport.equals()`进行比较，它的`JSONObject.containsValue()`获取对象后在`PropertyUtils.getProperty()`内动态调用`getOutputProperties`方法，它被代理给`CompositeInvocationHandlerImpl`，其中转交给`JdkDynamicAopProxy.invoke()`，在`AopUtils.invokeJoinpointUsingReflection()`时会传入从`AdvisedSupport.target`字段中取出来的`TemplatesImpl`，最终导致命令执行
- JavassistWeld1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`org.jboss.weld.interceptor.proxy.InterceptorMethodHandler`
    - 除JBoss部分包名存在差异外，与JBossInterceptors1基本一致
- Jdk7u21
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`LinkedHashSet`
    - `LinkedHashSet.readObject()`将各元素放进`HashMap`时，第二个元素会调用`equals()`与第一个元素进行比较，它被代理给`AnnotationInvocationHandler`进入`equalsImpl()`，在`getMemberMethods()`遍历`TemplatesImpl`的方法遇到`getOutputProperties`进行调用时，导致命令执行
- MozillaRhino1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`BadAttributeValueExpException`
    - `BadAttributeValueExpException.readObject()`调用`NativeError.toString()`时，会在`ScriptableObject.getProperty()`中进入`getImpl()`，`ScriptableObject$Slot`根据`name`获取到封装了`Context.enter`方法的`MemberBox`，并通过它的`invoke()`完成调用，而之后根据`message`调用`TemplatesImpl.newTransformer()`则会导致命令执行
- Myfaces1
    - 命令执行载体：`org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression`
    - 反序列化载体：`HashMap`
    - `HashMap.readObject()`通过`ValueExpressionMethodExpression.hashCode()`计算hash时，会由`getMethodExpression()`调用`ValueExpression.getValue()`，最终导致EL表达式执行
- Myfaces2
    - 命令执行载体：`org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression`
    - 反序列化载体：`HashMap`
    - 执行过程与Myfaces1一致，但Myfaces2的EL表达式并不是由使用者传入的，而是预制了一串加载远程恶意对象的表达式
- ROME
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`HashMap`
    - `HashMap.readObject()`通过`ObjectBean.hashCode()`计算hash时，会在`ToStringBean.toString()`阶段遍历`TemplatesImpl`所有字段的Setter和Getter并调用，当调用到`getOutputProperties()`时将导致命令执行
- Spring1
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider`
    - `SerializableTypeWrapper$MethodInvokeTypeProvider.readObject()`在调用`TypeProvider.getType()`时被代理给`AnnotationInvocationHandler`得到另一个Handler为`AutowireUtils$ObjectFactoryDelegatingInvocationHandler`的代理，之后传给`ReflectionUtils.invokeMethod()`动态调用`newTransformer`方法时被第二个代理拦截，它的`objectFactory`字段是第三个代理，因此`objectFactory.getObject()`会获得`TemplatesImpl`，最终导致命令执行
- Spring2
    - 命令执行载体：`org.apache.xalan.xsltc.trax.TemplatesImpl`
    - 反序列化载体：`org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider`
    - `SerializableTypeWrapper$MethodInvokeTypeProvider.readObject()`在动态调用`newTransformer`方法时，被第二个代理拦截交给`JdkDynamicAopProxy`，它在`AopUtils.invokeJoinpointUsingReflection()`时会传入从`AdvisedSupport.targetSource`字段中取出来的`TemplatesImpl`，最终导致命令执行

根据上面这些内容，我们可以得到几条简单的POP构造法则：

1. 当依赖中不存在可以执行命令的方法时，可以选择使用`TemplatesImpl`作为命令执行载体，并想办法去触发它的`newTransformer`或`getOutputProperties`方法
1. 可以作为入口的通用反序列化载体是`HashMap`、`AnnotationInvocationHandler`、`BadAttributeValueExpException`和`PriorityQueue`，它们都是依赖较少的JDK底层对象，区别如下：
    - `HashMap`，可以主动触发元素的`hashCode`和`equals`方法
    - `AnnotationInvocationHandler`，可以主动触发`memberValues`字段的`setValue`方法，本身也可以作为动态代理的Handler拦截如`Map.entrySet`等方法进入自己的`invoke`方法
    - `BadAttributeValueExpException`，可以主动触发`val`字段的`toString`方法
    - `PriorityQueue`，可以主动触发`comparator`字段的`compare`方法

## 总结

历年来，很多流行的Java组件框架都被爆出过反序列化漏洞，这已经有好多大牛们都进行过分析总结了，本文的主要目的也不在此，而是为了去深挖反序列化漏洞底层一些可能还没有被唤醒的地方。

不过有一点要切记，反序列化不止RCE。

## 参考

1. [JavaSE Document](https://docs.oracle.com/javase/8/docs/)
1. [Java OpenJDK Source Code](http://hg.openjdk.java.net/)
1. [Java OpenJDK GitHub Mirror](https://github.com/unofficial-openjdk/openjdk/)