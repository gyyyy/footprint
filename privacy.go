package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/russross/blackfriday"
	yaml "gopkg.in/yaml.v2"
)

var (
	pre, iv        []byte
	privRoot, _    = filepath.Abs("articles/privacy")
	cryptTitle     = []byte("# 锟斤拷锟斤拷锟斤拷")
	copyright      = "*（由于版权原因，该文章内容不公开）*\n\n"
	regTS          = regexp.MustCompile(`timestamp-(\d{10})-lightgrey`)
	regIMG         = regexp.MustCompile(`!\[[^\]]+\]\(([^\)]+)\)`)
	errInvalidFile = errors.New("invalid file")
)

func initKey(name string) error {
	o := &struct{ Pre, IV string }{}
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(b, o); err != nil {
		return err
	}
	pre, iv = []byte(o.Pre), []byte(o.IV)
	return nil
}

func padding(t []byte, n int) []byte {
	p := n - len(t)%n
	return append(t, bytes.Repeat([]byte{byte(p)}, p)...)
}

func unpadding(d []byte) []byte {
	n := len(d)
	return d[:(n - int(d[n-1]))]
}

func encrypt(file string) error {
	b, err := ioutil.ReadFile(filepath.Join(privRoot, file+"$.md"))
	if err != nil {
		return err
	}
	bs := bytes.SplitN(b, []byte("\n\n"), 3)
	if len(bs) != 3 || len(bs[2]) <= 0 {
		return errInvalidFile
	}
	ts := regTS.FindSubmatch(bs[1])
	if len(ts) != 2 {
		return errInvalidFile
	}
	c, err := aes.NewCipher(append(pre, ts[1]...))
	if err != nil {
		return err
	}
	var (
		data = padding(bs[2], c.BlockSize())
		out  = make([]byte, len(data))
	)
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(out, data)
	b = bytes.Replace(b, bs[0], cryptTitle, 1)
	b = bytes.Replace(b, bs[2], []byte(copyright+base64.StdEncoding.EncodeToString(out)), 1)
	return ioutil.WriteFile(filepath.Join(privRoot, file+".md"), b, 0666)
}

func decrypt(path, title string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bs := bytes.SplitN(b, []byte("\n\n"), 4)
	if len(bs) != 4 || len(bs[3]) <= 0 {
		return nil, errInvalidFile
	}
	ts := regTS.FindSubmatch(bs[1])
	if len(ts) != 2 {
		return nil, errInvalidFile
	}
	c, err := aes.NewCipher(append(pre, ts[1]...))
	if err != nil {
		return nil, errInvalidFile
	}
	data, err := base64.StdEncoding.DecodeString(string(bs[3]))
	if err != nil {
		return nil, errInvalidFile
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(out, data)
	b = bytes.Replace(b, bs[0], []byte("# "+strings.ToUpper(title)), 1)
	b = bytes.Replace(b, append(bs[2], []byte("\n\n")...), []byte{}, 1)
	b = bytes.Replace(b, bs[3], unpadding(out), 1)
	return b, nil
}

func index(w http.ResponseWriter, r *http.Request) {
	privs := make([]string, 0)
	if err := filepath.Walk(privRoot, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || strings.ToLower(filepath.Ext(path)) != ".md" || strings.HasSuffix(filepath.Base(path), "$.md") {
			return nil
		}
		privs = append(privs, path)
		return nil
	}); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	htm := "<html><head><title>Index of /privacy</title></head><body><h1>Index of /privacy</h1><pre>"
	for _, p := range privs {
		htm += "      <a href=\"/view?p=" +
			url.QueryEscape(strings.TrimSuffix(strings.TrimPrefix(p, privRoot+string(filepath.Separator)), filepath.Ext(p))) +
			"\" target=\"_blank\">" +
			strings.Replace(strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)), "-", " ", -1) +
			"</a>\n"
	}
	htm += "</pre></body></html>"
	w.Write([]byte(htm))
}

func view(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var (
		path      = r.FormValue("p")
		data, err = decrypt(filepath.Join(privRoot, path+".md"), strings.Replace(filepath.Base(path), "-", " ", -1))
	)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	data1 := data
	for _, v := range regIMG.FindAllSubmatch(data1, -1) {
		if u, err := url.Parse(string(v[1])); err == nil && u.Host == "" {
			data1 = bytes.Replace(data1, v[0], bytes.Replace(v[0], v[1], append([]byte("/img/"), v[1]...), 1), 1)
		}
	}
	htm := "<html><head><title>" +
		strings.ToUpper(strings.Replace(path, "-", " ", -1)) +
		"</title><style type=\"text/css\">img{max-width:100%;} body{margin:0;}</style></head>" +
		"<body><div style=\"display:flex;overflow:hidden;height:100%;\">" +
		"<pre style=\"flex:0 0 calc(50% - 40px);margin:0;padding:20px;overflow:scroll;\">" +
		html.EscapeString(string(data)) +
		"</pre><div style=\"flex:0 0 calc(50% - 40px);margin:0;padding:20px;overflow:scroll;\">" +
		string(blackfriday.MarkdownBasic(data1)) +
		"</div></div></body></html>"
	w.Write([]byte(htm))
}

func main() {
	var (
		key  = flag.String("key", "", "privacy key")
		mode = flag.String("mode", "dec", "privacy mode")
		file = flag.String("f", "", "privacy file")
	)
	flag.Parse()
	if *key == "" {
		flag.Usage()
		return
	}
	if err := initKey(*key); err != nil {
		log.Fatalln(err)
	}
	switch *mode {
	case "enc":
		if *file == "" {
			flag.Usage()
			return
		}
		if err := encrypt(*file); err != nil {
			log.Fatalln(err)
		}
	case "dec":
		http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir(privRoot))))
		http.HandleFunc("/", index)
		http.HandleFunc("/view", view)
		log.Println("browse at http://127.0.0.1:9798/")
		if err := http.ListenAndServe("127.0.0.1:9798", nil); err != nil {
			log.Fatalln(err)
		}
	default:
		flag.Usage()
	}
}
