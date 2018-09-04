# 编写安全的PHP <译>

![Category](https://img.shields.io/badge/category-methodology-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-php-blue.svg)
![Timestamp](https://img.shields.io/badge/timestamp-0000000000-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-25%25-orange.svg)

<small>* 本文非完全直译，想了解作者原意，请直接阅读[<i class="fa fa-link"></i> 英文原文](https://www.addedbytes.com/blog/?tag=writing%20secure%20php)。</small>

学习如何避免PHP中最常见的错误，让你的网站更加安全。

PHP是一种非常容易学习的语言，许多没有任何编程背景的人都使用它作为网站前后端动态交互的选择。不幸的是，这通常意味着PHP程序员，特别是那些新手，都意识不到他们的Web应用可能存在潜在的安全威胁。下面列举了一些比较常见的问题，以及如何避免它们的方案。

## 原则一：永远不要相信你的用户

这个话题无论说多少遍都不够，千万，永远不要相信你的用户会给你发送你期望的数据。我经常听到很多人对这类问题的反应是『哦，没人会对我的网站感兴趣』。撇开那些无法避免的问题，并不总是恶意用户会利用安全漏洞————普通用户无意中的误操作也有可能让问题很容易的暴露出来。

因此，所有Web开发的基本原则就是：永远不要相信你的用户。总是假想你的网站从用户那得到的每一条数据都包含了恶意代码，包括你觉得你已经在客户端使用如JavaScript等进行过验证了的数据。如果你能做到这一点，说明你已经有了一个良好的开始。如果PHP安全对你来说很重要，那么这将是最重要的一个原则。就我个人而言，我自己编制了一个『PHP安全表』放在我的办公桌旁边，上面标注了很多安全相关的原则和要点，这一条原则就用大粗体写在了第一行。

## 全局变量

在很多编程语言中，你都必须显式的创建一个变量来使用它。在PHP中，你可以在php.ini文件中启用选项`register_globals`，它允许你使用全局变量，而你并不需要去显式的创建它。

思考一下下面的代码：

```php
if ($password == "my_password") {
    $authorized = 1;
}

if ($authorized == 1) {
    echo "Lots of important stuff.";
}
```

对于很多人来说，这段代码似乎看起来没什么问题，而且这种代码会被使用在整个Web应用中。但是，如果服务器启用了`register_globals`，用户只需要在请求的URL中添加`?authorized=1`即可让任何人访问你的网站中需要授权才能看到的内容。这是最常见的PHP安全问题之一。

幸运的是，有几种很简单的方案都可以解决这个问题。第一种，也可能是最好的一种，就是禁用`register_globals`选项。第二种，只使用显示创建过的变量。在上面的例子中，你只需要在脚本的开头，增加`$authorized = 0;`即可：

```php
$authorized = 0;
if ($password == "my_password") {
    $authorized = 1;
}

if ($authorized == 1) {
    echo "Lots of important stuff.";
}
```

## 错误

无论是对于程序员还是黑客来说，错误都是一个非常有用的工具。开发人员需要通过错误定位和修复Bug，而黑客需要通过错误来发现网站的各种信息，从服务器目录结构到数据库登录信息。如果可能的话，最好是关闭一个生产应用中所有的错误报告。PHP可以通过修改.htaccess或php.ini文件，将`error_reporting`设置为`0`。在测试环境中，你可以设置不同的错误报告等级。