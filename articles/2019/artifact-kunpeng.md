# 带你读神器之PoC框架KunPeng

![Category](https://img.shields.io/badge/category-security_develop-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-go-blue.svg)
![Tag](https://img.shields.io/badge/tag-poc-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1548875438-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 转安全之后粗略的读过很多开源工具，一直考虑写一些神器的源代码分析文章。回想以前PocSuite和BugScan那时插件化PoC盛行，很多人都梦寐以求自己能拥有这么一套强大的PoC框架，昨天看到[@wolf](https://github.com/ywolf/)和几个大牛们开源了一个Go的跨语言PoC检测框架KunPeng，刚好它代码量不大，适合过年，就拿它当作这个系列的开篇吧。</sub>

根据官方文档的介绍，这个项目是以动态链接库的形式提供给Go以及其他语言进行调用的，因此会存在调用方和被调用方两个角色，请大家仔细区分。

## 获取对象

调用方调用`plugin`包加载so文件，并获取其中的`Greeter`对象：

```go
plug, _ := plugin.Open("./kunpeng_go.so")
g, _ := plug.Lookup("Greeter")
```

由于`Plugin.Lookup()`获得的是一个`interface{}`类型对象，需要将其进行一次类型断言才能访问到`Greeter`对象内的公有属性。好在Go具有非侵入式接口的语言特性，使调用方在本地定义一个属于`Greeter`对象公有方法子集的接口就能断言成功：

```go
type Greeter interface {
	Check(string) ([]map[string]string)
    GetPlugins() []map[string]string
    ...
}

// omit
kunpeng, ok := g.(Greeter)
// kunpeng.GetPlugins()
```

## 执行检测

调用方定义一个`Task`结构体，实例化后转成JSON字符串传给`Greeter.Check()`，即可等待检测结果：

```go
type Meta struct {
	System   string   `json:"system"`
	PathList []string `json:"pathlist"`
	FileList []string `json:"filelist"`
	PassList []string `json:"passlist"`
}

type Task struct {
	Type   string `json:"type"`
	Netloc string `json:"netloc"`
	Target string `json:"target"`
	Meta   Meta   `json:"meta"`
}

// omit
task, _ := json.Marshal(Task{"service", "0.0.0.0:0000", "mysql", Meta{}})
result := kunpeng.Check(string(task))
```

被调用方的`Check()`在解析JSON字符串拿到`plugin.Task`对象 *（结构体与调用方定义的`Task`一致）* 后，直接交给`plugin.Scan()`去执行实际检测逻辑，拿到的结果又转成JSON字符串返回：

```go
func Check(task *C.char) *C.char {
	var m plugin.Task
    if err := json.Unmarshal([]byte(C.GoString(task)), &m); err != nil {
        return C.CString("[]")
	}
	result := plugin.Scan(m)
	if len(result) == 0{
		return C.CString("[]")
	}
	b, err := json.Marshal(result)
    if err != nil {
        return C.CString("[]")
	}
	return C.CString(string(b))
}
```

从上面的代码中可以看到，为了支持跨语言调用，KunPeng使用更底层兼容性更高的CGo来处理几个入口函数中的原始数据类型。

`plugin.Scan()`分别遍历`GoPlugins`和`JSONPlugins` *（两种类型插件的具体区别见下面插件开发和插件加载章节）* ，根据`Task`的`Target`字段选择PoC子集进行检测并返回结果集合：

```go
func Scan(task Task) (result []map[string]interface{}) {
	for n, pluginList := range GoPlugins {
		if strings.Contains(strings.ToLower(task.Target), strings.ToLower(n)) || task.Target == "all" {
			for _, plugin := range pluginList {
				plugin.Init()
				if len(task.Meta.PassList) == 0 {
					task.Meta.PassList = Config.PassList
				}
				if !plugin.Check(task.Netloc, task.Meta) {
					continue
				}
				for _, res := range plugin.GetResult() {
					result = append(result, util.Struct2Map(res))
				}
			}
		}
	}
	if task.Type == "service" {
		return result
	}
	for target, pluginList := range JSONPlugins {
		if strings.Contains(strings.ToLower(task.Target), strings.ToLower(target)) || task.Target == "all" {
			for _, plugin := range pluginList {
				if yes, res := jsonCheck(task.Netloc, plugin); yes {
					result = append(result, util.Struct2Map(res))
				}
			}
		}
	}
	return result
}
```

## 插件开发

### Go类型插件

KunPeng定义了一个用于描述插件信息的公有结构体`Plugin`：

```go
type References struct {
	URL string `json:"url"`
	CVE string `json:"cve"`
}

type Plugin struct {
	Name       string     `json:"name"`
	Remarks    string     `json:"remarks"`
	Level      int        `json:"level"`
	Type       string     `json:"type"`
	Author     string     `json:"author"`
	References References `json:"references"`
	Request    string
	Response   string
}
```

以及公有接口`GoPlugin`：

```go
type GoPlugin interface {
	Init() Plugin
	Check(string, TaskMeta) bool
	GetResult() []Plugin
}
```

由于KunPeng未定义插件的相关基类及缺省字段和方法，所以我们需要在`plugin/go/`目录下创建一个新的.go文件，在其中自定义一个包含`info`和`result`字段的结构体来表示新的插件：

```go
type pluginXXX struct {
	info   plugin.Plugin
	result []plugin.Plugin
}
```

随后，为该结构体实现`GoPlugin`接口中所有的方法：

```go
func (p *pluginXXX) Init() plugin.Plugin {
    p.info = plugin.Plugin{}
}

func (p *pluginXXX) Check(netloc string, meta TaskMeta) bool {
    // 自定义检测过程逻辑，成功返回true，失败返回false
    return false
}

func (p *pluginXXX) GetResult() []plugin.Plugin {
    return p.result
}
```

并在文件的`init()`方法中调用`plugin.Regist()`注册该插件即可：

```go
func init() {
	plugin.Regist("xxx", new(plugin))
}
```

### JSON类型插件

KunPeng同样为我们准备好了用于描述JSON插件信息的公有结构体`JSONPlugin`，并对它实现了统一的检测方法`jsonCheck()`：

```go
type JSONPlugin struct {
	Target  string `json:"target"`
	Meta    Plugin `json:"meta"`
	Request struct {
		Path     string `json:"path"`
		PostData string `json:"postdata"`
	} `json:"request"`
	Verify struct {
		Type  string `json:"type"`
		Match string `json:"match"`
	} `json:"verify"`
}

func jsonCheck(URL string, p JSONPlugin) (bool, Plugin) {
    // 常规的HTTP发包和结果比较，略
    return false, result
}
```

我们可以在`plugin/json/`目录下创建一个新的.json文件，写入我们需要的信息 *（具体内容参考官方文档）* 即可：

```json
{
    "target": "xxx",
    "meta": {
        "name": "xxx",
        "remarks": "xxx",
        "level": 0,
        "type": "RCE",
        "author": "gyyyy",
        "references": {
            "url": "https://github.com/gyyyy/",
            "cve": ""
        }
    },
    "request":{
        "path": "/index.html",
        "postData": ""
    },
    "verify":{
        "type": "string",
        "match": "gyyyy"
    }
}
```

## 插件加载

### Go类型插件

前面说了，Go类型插件需要在`init()`时进行注册，`Regist()`会将插件对象以`target`为键放入`GoPlugins`集合，并初始化插件信息：

```go
func Regist(target string, plugin GoPlugin) {
	GoPlugins[target] = append(GoPlugins[target], plugin)
	var pluginInfo = plugin.Init()
}
```

由于入口文件中匿名导入了`plugin/go`包，所以在程序启动时，所有编写好的Go类型插件就都会`init()`到`GoPlugins`中完成加载。

### JSON类型插件

相比之下，JSON类型插件的加载过程就要繁琐一些。

入口文件匿名导入`plugin/json`包后，会调用`plugin/json/init.go`文件中的`init()`方法进行加载：

```go
func init() {
	loadJSONPlugin(false, "/plugin/json/")
	go loadExtraJSONPlugin()
}
```

`loadJSONPlugin()`遍历目录中的所有.json文件，交给`readPlugin()`进行处理。`readPlugin()`读取文件后将JSON字符串解析为`JSONPlugin`对象返回，所有非重复插件对象将以`target`为键全部放入`JSONPlugins`集合中。

而新开的Goroutine调用`loadExtraJSONPlugin()`，每隔20秒对配置的`extra_plugin_path`目录执行`loadJSONPlugin()`操作进行加载。

为了节省篇幅这里就不细述了。

## 说在最后的话

非常敬佩几位大牛的开源精神，请大家多多PR，为这个新生的PoC框架和漏洞库贡献一份力量。

## 参考

1. [KunPeng](https://github.com/opensec-cn/kunpeng/)