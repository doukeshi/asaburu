//go:build !wasm

package asaburu

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

const (
	TEMPLATE_DIR = "templates"
	BASEOF_FILE  = "baseof.tmpl"
)

var (
	FRONT_MATTER_START = []byte("<!----")
	FRONT_MATTER_END   = []byte("---->")
)

var (
	prefixFlag = flag.String("p", "/", "Base path prefix for the server's URLs.")
	prefixFunc = func(fpath string) string {
		prefix := *prefixFlag
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		return path.Join(prefix, fpath)
	}
	wasmFiles  = filepath.Join(TEMPLATE_DIR, "wasm", "*.tmpl")
	layoutFile = filepath.Join(TEMPLATE_DIR, BASEOF_FILE)
	indexFile  = filepath.Join(TEMPLATE_DIR, "index.tmpl")

	funcMap = template.FuncMap{
		"year": func() string {
			return time.Now().Format("2006")
		},
		"stringsHasPrefix": strings.HasPrefix,
		"prefix":           prefixFunc,
		"navs": func() []struct{ Title, Href string } {
			return []struct{ Title, Href string }{
				{"Asaburu", prefixFunc("/")},
				{"pifu.me", "https://pifu.me/"},
			}
		},
	}
	indexTemplate = template.Must(template.New(BASEOF_FILE).Funcs(funcMap).ParseFiles(layoutFile, indexFile))
	indexParams   = makeParams(indexFile)
)

type Tmpl struct {
	htmlMap   map[string]Meta
	WasmLinks map[string]Params
}

type Meta struct {
	tt     *template.Template
	params Params
}

type Params struct {
	Title  string
	Remark string
}

func NewTmpl() *Tmpl {
	makeTmpl := func(tmplFiles string) map[string]Meta {
		paths, err := filepath.Glob(tmplFiles)
		if err != nil {
			panic(fmt.Errorf("failed to glob templates: %w", err))
		}
		tmplMap := make(map[string]Meta)
		for _, path := range paths {
			key := strings.TrimSuffix(filepath.Base(path), ".tmpl")
			tt := template.Must(template.New(BASEOF_FILE).Funcs(funcMap).ParseFiles(layoutFile, path))
			tmplMap[key] = Meta{tt, makeParams(path)}
		}
		return tmplMap
	}

	htmlMap := makeTmpl(wasmFiles)
	wasmLinks := make(map[string]Params)
	for k, v := range htmlMap {
		wasmLinks[k] = v.params
	}
	return &Tmpl{htmlMap, wasmLinks}
}

func (t *Tmpl) GenerateHTML(folder string) error {
	generate := func(fpath string, tt *template.Template, data any) error {
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return fmt.Errorf("failed to os.MkdirAll, Error: %w", err)
		}
		f, err := os.Create(fpath)
		if err != nil {
			return fmt.Errorf("failed to os.Create, Error: %w", err)
		}
		defer f.Close()
		err = tt.Execute(f, data)
		if err != nil {
			return fmt.Errorf("failed to tmpl.Execute, Error: %w", err)
		}
		return nil
	}
	for key, meta := range t.htmlMap {
		fpath := filepath.Join(folder, key, "index.html")
		if err := generate(fpath, meta.tt, meta.params); err != nil {
			return err
		}
	}
	if err := generate(filepath.Join(folder, "index.html"), indexTemplate, struct {
		WasmLinks map[string]Params
		Params
	}{t.WasmLinks, indexParams}); err != nil {
		return err
	}
	return nil
}

func makeParams(path string) Params {
	readFrontMatter := func(fpath string) ([]byte, error) {
		file, err := os.Open(fpath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file, Error: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		if !scanner.Scan() {
			return nil, fmt.Errorf("file is empty")
		}
		firstLine := bytes.TrimSpace(scanner.Bytes())
		if !bytes.Equal(firstLine, FRONT_MATTER_START) {
			return nil, fmt.Errorf("invalid front matter")
		}

		var lines [][]byte
		for scanner.Scan() {
			line := scanner.Bytes()
			if bytes.Equal(bytes.TrimSpace(line), FRONT_MATTER_END) {
				break
			}
			buf := make([]byte, len(line))
			copy(buf, line)
			lines = append(lines, buf)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scanner.Scan Error: %w", err)
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("front matter not found")
		}
		return bytes.Join(lines, []byte("\n")), nil
	}

	var params Params
	if b, err := readFrontMatter(path); err != nil {
		panic(fmt.Errorf("failed to readFrontMatter, Error: %w", err))
	} else {
		if err := yaml.Unmarshal(b, &params); err != nil {
			panic(fmt.Errorf("failed to yaml.Unmarshal, Error: %w", err))
		}
	}
	return params
}
