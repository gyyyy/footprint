# Java XXE注入修复问题填坑实录

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-java-blue.svg)
![Vuln Type](https://img.shields.io/badge/vuln_type-xxei-red.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1549059080-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 前不久，[@图南](https://x3fwy.bitcron.com/)在分析WxJava的XXE注入漏洞时，发现是由于开发者错误使用了[Java官方一个容易被误解的API](https://x3fwy.bitcron.com/post/a-jdk-bug)，导致之前的修复方案失效。我和南哥交流之后，经过简单的跟踪分析，发现归根结底是Feature的问题，所以就带大家一起来填填这个坑吧。请在阅读本文之前好好的把南哥的文章看一遍，其中涉及到的内容我都不会再占篇幅描述了。</sub>

## 关于`DocumentBuilderFactory`

在我之前的[《XXE注入漏洞概述》](https://github.com/gyyyy/footprint/blob/master/articles/2018/xxe-injection-overview.md)一文中，以dom4j的`SAXParser`为例简单分析了它对XML文档的解析过程，虽然`DocumentBuilderFactory`使用的是`DOMParser`，但是很荣幸，它俩都会调用`XMLDocumentFragmentScannerImpl.scanDocument()`扫描XML文档。而且[OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)项目中也表示它们的修复方案是一致的：

> `DocumentBuilderFactory`, `SAXParserFactory` and `DOM4J` XML Parsers can be configured using the same techniques to protect them against XXE.

所以我们在这稍微简化一下分析过程，不再描述`DocumentBuilderFactory`的完整解析过程，为大家减减负，直接挑重点说。

## 标准的`DISALLOW_DOCTYPE_DECL_FEATURE`

这应该是OWASP最推荐的防御方案了，它与`LOAD_EXTERNAL_DTD`一起在`XMLDocumentScannerImpl`中被组成为一组`RECOGNIZED_FEATURES`，主要过程如下：

- 当`DocumentBuilderFactory.setFeature()`将`http://apache.org/xml/features/disallow-doctype-decl`设置为`true`时，`DOMParser`会改变内部`fConfiguration`变量中相应键的值，以及`XMLNSDocumentScannerImpl`中`fDisallowDoctype`变量的值
- 在调用`DOMParser.parse()`时，将`XML11Configuration`中`XMLDocumentScannerImpl`的`fDisallowDoctype`也重置为`true`
- `XMLDocumentFragmentScannerImpl.scanDocument()`由`PrologDriver.next()`依次扫描到`<`、`!`字符后进入`SCANNER_STATE_DOCTYPE`阶段，该阶段第一件事就是判断`fDisallowDoctype`的值，如果为`true`，则直接报告异常信息中断扫描

由此可知，为什么OWASP会这样描述这个方案：

> This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented

## 被误解的`setExpandEntityReferences()`

这次我们先看OWASP对它的描述：

> If for some reason support for inline DOCTYPEs are a requirement, then ensure the entity settings are disabled and beware that SSRF attacks and denial of service attacks are a risk.

简单的说，如果你需要支持内联DOCTYPE，可以使用`setExpandEntityReferences()`，但要注意SSRF和DoS风险。

那么我们就来分析一下它为什么没有效果：

- `DocumentBuilderFactory.setExpandEntityReferences()`传入`false`会改变`DocumentBuilderFactoryImpl`中`expandEntityRef`变量的值 *（默认为`true`）*
- `DocumentBuilderFactory.newDocumentBuilder()`创建`DocumentBuilderImpl`时，会根据`expandEntityRef`的 **相反值** 改变`fConfiguration`中`http://apache.org/xml/features/dom/create-entity-ref-nodes`的值
- `XMLParser.reset()`时，`AbstractDOMParser`中`fCreateEntityRefNodes`变量也被重置为`true`
- 在`XMLDocumentFragmentScannerImpl.scanDocument()`时，调用`scanDoctypeDecl()`扫描DOCTYPE，之后交给`DTDDriver.next()`处理实体声明
- 当进入`START_ELEMENT`阶段后，`startEntity()`会调用`scanEntityReference()`扫描并解析实体引用`&xxe;`，而在`endEntity()`判断`fCreateEntityRefNodes`为`false`时，将会移除掉该节点

由此可知，`setExpandEntityReferences()`的意思其实是实体引用的值解析后，是否仍将其原始的表示引用的节点保留Dom树中。设置为`false`的不展开代表保留，则会创建一个对应节点存放在Dom树中。

因此，如果是DTD扫描阶段的SSRF之类的攻击，无论`setExpandEntityReferences()`传入何值，都是不起任何防御作用的。

## 说在最后的话

在和南哥一起填这个坑的时候，我们发现网络上还是有不少关于XXE攻防相关的文章的修复建议中只提到了`setExpandEntityReferences(false)`这个方案，有被Java官方误导过的同学都赶紧更正一下吧。

## 参考

1. [修不好的洞，JDK的坑——从WxJava XXE注入漏洞中发现了一个对JDK的误会](https://x3fwy.bitcron.com/post/a-jdk-bug)
1. [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)