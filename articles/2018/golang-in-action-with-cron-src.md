# 定时任务管理Cron源代码浅析，Go语言实战

![Category](https://img.shields.io/badge/category-security_develop-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-go-blue.svg)
![Tag](https://img.shields.io/badge/tag-cron-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1539756687-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 在信息整合、漏洞扫描等平台的开发过程中，经常会遇到定时任务执行的需求，如Windows的定时任务计划和Linux的crontab都是为了这类需求而产生的。本文对Github上一个Go版的cron包进行分析，带大家熟悉一下它的具体实现。</sub>

## 初始化Cron对象

先来看看`Cron`的整体定义：

```go
type Cron struct {
    entries  []*Entry
    stop     chan struct{}
    add      chan *Entry
    snapshot chan []*Entry
    running  bool
    ErrorLog *log.Logger
    location *time.Location
}
```

从它的`running`、`add`和`stop`字段定义可以看出来，这个`Cron`对象可以同时对多个定时任务进行管理。

我们先不管其他的自定义类型，继续往下看。

默认的初始化函数`New()`会带上时区调用`NewWithLocation()`创建一个`Cron`：

```go
func NewWithLocation(location *time.Location) *Cron {
    return &Cron{
        entries:  nil,
        add:      make(chan *Entry),
        stop:     make(chan struct{}),
        snapshot: make(chan []*Entry),
        running:  false,
        ErrorLog: nil,
        location: location,
    }
}
```

其中的`Entry`包含了任务和它的计划时间信息：

```go
type Entry struct {
    Schedule Schedule
    Next     time.Time
    Prev     time.Time
    Job      Job
}
```

`Schedule`是一个接口，用于计算下次执行时间：

```go
type Schedule interface {
    Next(time.Time) time.Time
}
```

## 启动

`Cron`对象定义了`Start()`和`Run()`两个方法用于启动，区别仅在于`Start()`是多线程启动的，它们都会在内部调用`run()`。

`run()`先计算每个任务的下次执行时间：

```go
now := c.now()
for _, entry := range c.entries {
    entry.Next = entry.Schedule.Next(now)
}
```

然后在无限循环中，先对当前所有`Entry`按下次执行时间排序，以最先执行的任务时间设置计时器`time.Timer` *（由于它利用动态计算下次执行时间的方案对执行时间进行精细控制，因此并未使用`time.Ticker`对象）* ：

```go
for {
    sort.Sort(byTime(c.entries))

    var timer *time.Timer
    if len(c.entries) == 0 || c.entries[0].Next.IsZero() {
        timer = time.NewTimer(100000 * time.Hour)
    } else {
        timer = time.NewTimer(c.entries[0].Next.Sub(now))
    }

    // ...
}
```

当前不存在任务时，它给了一个足够长的时间进入『休眠』。

再使用`select`监听各个通道的信号量，由于`timer.C`、`add`和`stop`信号量在计时器资源上存在竞争，本来是不需要使用外部循环来处理并发信号量的，外部循环是为了保证`snapshot`之后，仍然会处理其他信号量：

```go
for {
    select {
    case now = <-timer.C:
        // ...
    case newEntry := <-c.add:
        // ...
    case <-c.snapshot:
        // ...
    case <-c.stop:
        // ...
    }

    break
}
```

## 执行

当`run()`中的`timer.C`通道接收到值后，遍历任务列表，多线程执行所有下次执行时间在当前时间之前的任务：

```go
case now = <-timer.C:
    now = now.In(c.location)
    for _, e := range c.entries {
        if e.Next.After(now) || e.Next.IsZero() {
            break
        }
        go c.runWithRecovery(e.Job)
        e.Prev = e.Next
        e.Next = e.Schedule.Next(now)
    }
```

## 新增

`AddFunc()`会将传入的任务执行函数包裹一个`Job`接口标准的`Run()`函数，再调用`AddJob()`按照规范解析表达式字符串获得`Schedule`对象：

```go
schedule, err := Parse(spec)
```

其中解析对象`Parser`定义如下：

```go
type Parser struct {
    options   ParseOption
    optionals int
}
```

`options`是解析选项标识位，默认解析器为：

```go
var defaultParser = NewParser(
    Second | Minute | Hour | Dom | Month | DowOptional | Descriptor,
)
```

`optionals`是可选项数量，目前只计算了`DowOptional`：

```go
optionals := 0
if options&DowOptional > 0 {
    options |= Dow
    optionals++
}
```

解析过程简单来说分成了两种情况：

1. 当判断表达式第一个字符为`@`时，按`Descriptor`解析 *（如`@yearly`、`@annually`、`@monthly`、`@weekly`、`@daily`、`@midnight`、`@hourly`和`@every [duration]`）*
1. 否则正常解析，细节略

解析得到的`Schedule`和任务一起封装成`Entry`，如果`Cron`未启动，则将它直接放入任务列表中，否则扔进`add`通道：

```go
if !c.running {
    c.entries = append(c.entries, entry)
    return
}

c.add <- entry
```

当`run()`中的`add`通道接收到值后，停止计时器，计算当前新任务的下次执行时间，将它放入任务列表中 *（随后执行的下次循环，将会对所有任务重新排序）* ：

```go
case newEntry := <-c.add:
    timer.Stop()
    now = c.now()
    newEntry.Next = newEntry.Schedule.Next(now)
    c.entries = append(c.entries, newEntry)
```

## 查看

如果`Cron`已启动，则给`snapshot`通道放进一个信号 *（空值`nil`当然也可以作为信号量）* 阻塞等待执行结果，否则直接调用`entrySnapshot()`返回所有`Entry`的副本：

```go
func (c *Cron) Entries() []*Entry {
    if c.running {
        c.snapshot <- nil
        x := <-c.snapshot
        return x
    }
    return c.entrySnapshot()
}
```

当`run()`中的`snapshot`通道接收到值后，将`entrySnapshot()`的执行结果又重新放入`snapshot`中还回去：

```go
case <-c.snapshot:
    c.snapshot <- c.entrySnapshot()
    continue
```

## 停止

将一个空结构体作为信号量放入`stop`通道中即可通知上述`run()`中断执行：

```go
func (c *Cron) Stop() {
    if !c.running {
        return
    }
    c.stop <- struct{}{}
    c.running = false
}
```

当`stop`通道接收到值后，停止计时器并退出：

```go
case <-c.stop:
    timer.Stop()
    return
}
```

## 总结

整体来说，这个包的结构比较清晰，并且正确使用了Go的`Chan`机制来避免并发环境中大量的锁开销。在它的设计基础上还可以比较方便的修改成其他类型的轻量级任务管理包，具备一定的参考价值。

## 参考

1. [Cron](https://github.com/robfig/cron/)