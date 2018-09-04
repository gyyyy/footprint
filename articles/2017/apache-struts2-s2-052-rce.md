---
title: Struts2远程代码执行（S2-052）漏洞分析
date: 2017-09-06 05:15:12
tags: [web, java, struts2, xstream, deserialize, rce, cve]
---

### 漏洞编号

CVE-2017-9805

### 漏洞介绍

根据漏洞作者博客中的描述，问题出现在struts2-rest-plugin插件XStreamHandler中的`toObject()`方法，其中未对传入的值进行任何限制，在使用XStream反序列化转换成对象时，导致任意代码执行漏洞。

### 环境搭建

直接部署struts-2.5.12-all中的struts2-rest-showcase项目即可，从下图可以看出，插件的默认配置支持XML扩展。

![01.png](apache-struts2-s2-052-rce/01.png)

运行看看，默认的是XHTML扩展。

![02.png](apache-struts2-s2-052-rce/02.png)

转换成XML请求也是成功的，但是注意Content-Type需要改成application/xml类型。

![03.png](apache-struts2-s2-052-rce/03.png)

### 构造PoC

用[marshalsec工具](https://github.com/mbechler/marshalsec)生成payload，工具简单使用方式如下：

```shell
java -cp marshalsec-0.0.1-SNAPSHOT-all.jar marshalsec.<Marshaller> [-a] [-v] [-t] [<gadget_type> [<arguments...>]]
```

看看工具作者的paper，针对XStream支持很多种payload，找一个Struts2也支持的即可。

![04.png](apache-struts2-s2-052-rce/04.png)

本文选择的是ImageIO，对应的gadget_type可以通过查看marshalsec的源码得到。

![05.png](apache-struts2-s2-052-rce/05.png)

生成payload。

![06.png](apache-struts2-s2-052-rce/06.png)

### 复现验证

![07.png](apache-struts2-s2-052-rce/07.png)