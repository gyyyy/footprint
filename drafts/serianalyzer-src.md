# 带你读神器之Serianalyzer源代码分析

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-java-blue.svg)
![Tag](https://img.shields.io/badge/tag-deserialization-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-0000000000-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-5%25-brightgreen.svg)

<sub>* 在之前的[《浅析Java序列化和反序列化》](../2019/about-java-serialization-and-deserialization.md)一文中说到，POP是反序列化的一门艺术。通过分析ysoserial项目，会发现很多POP链的构造非常的巧妙甚至是复杂。这不禁让我们好奇，究竟大牛们是如何找到这些千奇百怪的POP链的呢？幸运的是，ysoserial项目的贡献者[@mbechler](https://github.com/mbechler/)开源了他用于寻找Java反序列化Gadget的静态字节码分析工具，就让我们一起来观摩一下大牛的神操作吧。</sub>

## `Main.main()`

入口很简单，就是根据参数创建`SerianalyzerConfig`交给`SerianalyzerInput`，再把剩余参数当作待分析目标路径遍历其中所有的Class文件 *（不支持嵌套Jar）* ，通过jandex的`Indexer.index()`解析成`ClassInfo`对象后转换成字节流放入`SerianalyzerInput.classData`字段中，最后初始化`Serianalyzer`并调用其`analyze()`直接进入分析流程。

## `Serianalyzer.analyze()`

通过`Index.getAllKnownImplementors()`获取所有实现了`Serializable`接口及其子类的类家族的`ClassInfo`对象，调用`checkClass()`  `TypeUtil.isSerializable()`

## 参考

1. [Serianalyzer](https://github.com/mbechler/serianalyzer/)
