# 带你读神器之子域名监控工具Sublert

![Category](https://img.shields.io/badge/category-security_develop-blue.svg)
![Research](https://img.shields.io/badge/research-web_security-blue.svg)
![Language](https://img.shields.io/badge/lang-python-blue.svg)
![Tag](https://img.shields.io/badge/tag-monitor-green.svg)
![Timestamp](https://img.shields.io/badge/timestamp-1553498298-lightgrey.svg)
![Progress](https://img.shields.io/badge/progress-100%25-brightgreen.svg)

<sub>* 最近在看一些监控类的开源产品和方案，碰巧今天ASRC推了篇公众号文章，是关于一个通过HTTPS证书监控子域名的小工具Sublert，代码量很少，可以带大家一起速读一下它的源代码。</sub>

该项目只有一个简单的Python脚本，它通过Crontab和Slack的Webhook实现定时执行和实时推送，因此我们只聚焦它本身的主要逻辑。

## 准备工作

调用`tld`包的`get_fld()`函数，获取从命令行参数中传入的待监控或待移除监控域名的一级域名：

```python
try:
    domain = get_fld(domain, fix_protocol = True)
    return domain
```

初始化两个全局队列`q1`和`q2`，分别用于多线程中增加监控域名和获取新增子域名操作：

```python
global q1
global q2
q1 = queue.Queue(maxsize=0)
q2 = queue.Queue(maxsize=0)
```

当然，在脚本初始化时，已经判断了当前Python版本引入不同的队列包：

```python
is_py2 = sys.version[0] == "2"
if is_py2:
    import Queue as queue
else:
    import queue as queue
```

如果命令行参数没有指定待监控域名，则逐行读取`domains.txt`文件中的域名放入`q1`和`q2`，创建并启动两个`Thread`分别从`q1`和`q2`中读取域名交给`adding_new_domain()`和`check_new_subdomains()`开始获取子域名信息，否则直接调用`adding_new_domain()`函数：

```python
if not domain_to_monitor:
    num = sum(1 for line in open("domains.txt"))
    for i in range(max(threads, num)):
        if not (q1.empty() and q2.empty()):
            t1 = threading.Thread(target = adding_new_domain, args = (q1, ))
            t2 = threading.Thread(target = check_new_subdomains, args = (q2, ))
            t1.start()
            t2.start()
            threads_list.append(t1)
            threads_list.append(t2)
else:
    adding_new_domain(domain_to_monitor)
for t in threads_list:
    t.join()
```

`adding_new_domain()`和`check_new_subdomains()`主要都是调用`cert_database.lookup()`获取HTTPS证书中的子域名记录。其中，当命令行参数没有指定待监控域名时，`adding_new_domain()`函数只查询没有历史结果的域名 *（`output`目录下没有对应名称文件）* ；而`check_new_subdomains()`则查询所有域名，临时结果保存在名称以`_tmp`结尾的文件中。

## 获取HTTPS证书中的子域名

将域名传入`cert_database.lookup()`，使用`crt.sh`官方数据库 *（PostgreSQL）* 模糊查询指定域名的子域名信息，将查询结果去重排序并返回，写入`output`目录下的对应名称文件中：

```python
conn = psycopg2.connect("dbname={0} user={1} host={2}".format(DB_NAME, DB_USER, DB_HOST))
conn.autocommit = True
cursor = conn.cursor()
cursor.execute("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(domain))
for result in cursor.fetchall():
    matches = re.findall(r"\'(.+?)\'", str(result))
    for subdomain in matches:
        try:
            if get_fld("https://" + subdomain) == domain:
                unique_domains.add(subdomain.lower())
        except: pass
return sorted(unique_domains)
```

若数据库查询出现异常，则直接请求Web API获取数据：

```python
base_url = "https://crt.sh/?q={}&output=json"
if wildcard:
    domain = "%25.{}".format(domain)
    url = base_url.format(domain)
subdomains = set()
user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0'
req = requests.get(url, headers={'User-Agent': user_agent}, timeout=20, verify=False)
if req.status_code == 200:
    try:
        content = req.content.decode('utf-8')
        data = json.loads(content)
        for subdomain in data:
            subdomains.add(subdomain["name_value"].lower())
        return sorted(subdomains)
```

## 筛选新增子域名

分别读取指定域名的结果文件和临时结果文件，调用`difflib.ndiff()`对比文件内容，取新增项作为最终结果：

```python
file1 = open("./output/" + domain_to_monitor.lower() + '.txt', 'r')
file2 = open("./output/" + domain_to_monitor.lower() + '_tmp.txt', 'r')
diff = difflib.ndiff(file1.readlines(), file2.readlines())
changes = [l for l in diff if l.startswith('+ ')]
newdiff = []
for c in changes:
    c = c.replace('+ ', '')
    c = c.replace('*.', '')
    c = c.replace('\n', '')
    result.append(c)
    result = list(set(result))
```

`dns_resolution()`调用`dns.resolver.query()`解析子域名的IP：

```python
dns_output = dns.resolver.query(domain,qtype, raise_on_no_answer = False)
```

最后，将解析结果一起发送给Slack的Webhook，删除结果文件并将临时结果文件重命名作为新的结果文件，走人拜拜。

## 说在最后的话

本系列的主要目标人群是代码经验较少的同学，所以前面几篇都会选择体量不大的实用型工具的源代码进行分析，后续会逐渐扩展到中大型的平台化项目。

阅读文章时建议打开项目源代码自己同步看，重点关注作者在解决一个具体问题时的自动化思路，以及他在构建项目时是如何组织代码和逻辑结构的。

至于说每个项目是否满足你理想中神器的标准，这真的不重要。

## 参考

1. [Sublert](https://github.com/yassineaboukir/sublert/)