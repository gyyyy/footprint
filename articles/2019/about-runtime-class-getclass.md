# 关于Java中`Runtime.class.getClass()`的细节分析

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-java-blue.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1550139196-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 在之前的[《浅析Java序列化和反序列化》](../2019/about-java-serialization-and-deserialization.md)一文的Payload构造章节中出现了一大堆的`Class`、`Method`和`Object`，让很多代码基础较弱的同学一脸懵逼。其中一个比较诡异的逻辑`Runtime.class.getClass()`，有朋友问它的结果为什么是`java.lang.Class`。对于这个问题，有Java语言基础的同学一般会回答『对象的类型本来就是`Class`，而`Class`也是对象，它的类型当然也是`Class`』，道理没错，但仔细想想，这还真是一个挺有意思的问题。</sub>

## 关于`Class`的名称

我们先重写一下这个问题的代码：

```java
Class rt = Runtime.class;
Class clz = rt.getClass();
```

通过断点调试观察变量，`rt`和`clz`同样都是`Class`对象，但`rt`无论是打印输出还是调用`getTypeName()`得到的都是『java.lang.Runtime』，而`clz`则是『java.lang.Class』。

为什么不一样？难道`Runtime`是`Class`的子类？当然不是，`Runtime`可是`Object`的亲儿子。

机智的你一定会跟进`Class`中看看它的`toString()`和`getTypeName()`两个方法的代码逻辑，原来它们都是调用`getName()`返回由这个`Class`所表示的对象的名称。

## 关于`.class`和`getClass()`

由此可知，`new Object().getClass()`得到的应该是名称为『java.lang.Object』的`Class`，记作`class java.lang.Object` *（以下类似）* ，而`Runtime.class`拿到的`Class`作为`Object`的子类，调用`getClass()`得到的却是`class java.lang.Class`。

因此，我们需要对比一下这两种获取`Class`的方法的区别：

- `.class`，又称『类字面量』，只能作用于类的关键字，返回编译时确定的类型
    ```java
    Object.class
    ```
- `getClass()`，`Object`的实例方法，返回运行时确定的类型
    ```java
    new Object().getClass()
    ```

在一般情况下，它俩的结果是可以相等的：

```java
Object obj = new Object()
Object.class == obj.getClass();      // true
Object.class.equals(obj.getClass()); // true
```

但当存在多态时，后者的区别就体现出来了：

```java
class gyyyy {}

Object obj = new Object();
Object gy = new gyyyy();
obj.getClass(); // class java.lang.Object
gy.getClass();  // class gyyyy
```

让我们回到最初的那个问题，答案已经呼之欲出了：`Runtime.class`获取的是`class java.lang.Runtime`，而该`Class`调用`getClass()`时，运行时确定的类型为`Class`而非方法拥有者`Object`，所以得到的第二个`Class`为`class java.lang.Class`。

看到这，一定有同学开始骂我又在水文章了：裤子都脱了你就给我看这个？说来说去都是一堆废话，跟没说一样。

别急，我们继续。

## JVM基础

既然上面的两种方法分别提到了编译时和运行时，不妨让我们站在JVM的角度再玩深一点。

先科普几个JVM相关的基础知识，让大家有个整体概念，其他的内容如果在后续分析过程中遇到了再穿插介绍。

### Classfile

每个类 *（包括内部类、匿名类、接口、注解、枚举和数组等）* 经过编译后，都会单独生成一个.class文件，里面是一堆用于表示和描述该类的字节码，Java规范中管它叫Classfile。

Classfile中的核心内容如下：

- 常量池 *（Constant Pool）*
- 访问权限标识 *（Access Flags）*
- 类 *（This Class）* 、父类 *（Super Class）* 、接口集合 *（Interfaces）*
- 字段集合 *（Fields）*
- 方法集合 *（Methods）*
- 属性集合 *（Attributes）* 

其中，常量池里存放了该类编译前声明和编译中优化计算的所有值，包括原始类型和引用类型 *（符号引用）* ，类相关信息都以名称和描述为主，但不涉及任何具体的值或引用 *（都依赖常量池索引）* 。属性集合中则存放了类、字段和方法所可能需要的属性信息，如类源文件信息、方法代码段、方法代码段的本地变量表等。

### 运行时内存基本结构

- 运行时数据区
    - 线程共享
        - 堆 *（Heap）*
            - 方法区 *（Method Area）*
                - 类 *（Class）*
                    - 运行时常量池 *（Run-Time Constant Pool）*
            - 对象 *（Objects）*
    - 线程私有
        - 线程 *（Threads）*
            - 程序计数器 *（Program Counter, PC）*
            - JVM堆栈 *（JVM Stack）*
                - 帧 *（Frames）*
                    - 本地变量表 *（Local Variables）*
                    - 操作数栈 *（Operand Stacks）*

其中，线程共享部分随JVM启动而创建，线程私有部分随线程创建而创建。Frame中存放的是方法数据而非Class数据，但一般来说，Object和方法的代码实现中都会存放它所属Class的引用。

需要注意的是，上面列出的Class和Object大致分别对应在Java代码中使用`class`或`interface`关键字声明的类和根据它们创建的类实例，而Java语言规范中所描述的`Class`和`Object`严格意义上来说都属于Class。

### 加载、链接和初始化

- 加载，是指根据指定名称寻找并读取Classfile，将其转换成Class的过程
- 链接，是指解析Class中的符号引用，并转换为运行时状态的过程
- 初始化，是指执行Class的`<cinit>`方法的过程

在这个阶段中，可以为Class创建一个新的`java/lang/Class`的Object，在其中定义一个字段中存放当前Class的引用，并将这个Object的引用放入Class中作为其类对象 *（非JVM规范，由实现方自行决定）* ，而这个所谓的类对象，就是我们最开始通过`.class`和`getClass()`获取到的那个`Class`对象。

### 方法执行过程

由于篇幅原因，这里只简单介绍实例方法的执行过程：

- 从常量池中取出方法引用，计算该方法参数个数
- 从操作数栈弹出当前类对象引用和其他参数，组成参数列表
- 为该方法创建新的`Frame`，将参数放入它的本地变量表中，将其压入JVM栈顶
- 解析并执行该方法代码段的指令集

方法的执行结果并不会直接返回给调用方，而是由`return`系列的指令将当前操作数栈顶元素取出，压入JVM栈中调用方所属Frame的操作数栈中。

## 刨根问底

现在，我们将示例代码放入`main`函数中，这段代码经过编译后会变成以下指令：

```plain
ldc #2
astore_1
aload_1
invokevirtual #3
astore_2
...
```

*（`#x`代表常量池索引值，可能会因为示例代码差异而不同。如果使用链式结构`Runtime.class.getClass()`，第2、3条指令会省略）*

大致解释一下：

- `ldc`指令会从常量池中取索引为`2`的元素，此时取到的是名为`java/lang/Runtime`的类引用类型常量，根据JVM规范的描述，如果是类引用类型常量，需要获取它的类对象引用 *（在前面加载、链接和初始化部分提到过的那个Object）* ，再将其压入操作数栈 *（对应`Runtime.class`）*
- `astore_1`指令会弹出操作数栈顶元素，放入本地变量表的`1`位置 *（`0`位置是`main`方法参数`args`）* ，此时该位置的变量名为`rt` *（对应`Class rt =`）*
- `aload_1`指令会从本地变量表中读取元素压入操作数栈 *（对应`rt`）*
- `invokevirtual`指令会从常量池中取索引为`3`的元素，此时取到的是名为`java/lang/Object.getClass`的方法引用类型常量，再弹出操作数栈顶获得之前`ldc`得到的类对象引用作为第一个参数，为该方法创建新的`Frame`并压入JVM堆栈，执行该方法的指令集，`return`时将结果压入方法调用方的操作数栈 *（对应`.getClass()`）*
- `astore_2`指令会弹出栈顶元素，放入本地变量表的`2`位置，此时该位置的变量名为`clz` *（对应`Class clz =`）*

由此，我们可以明确的知道变量`rt`存放的是`java/lang/Runtime`的类对象引用，变量`clz`存放的是`java/lang/Class`的类对象引用。由于类对象是在Class的链接过程中创建的，而在JVM中每个Class又是唯一的单例，因此同一个类以及它不同的实例获取到的类对象都是同一个。

结论不变。