package asaburu

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"syscall"
)

type Result struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"err,omitempty"`
}

func (r Result) ToJSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{ "err": "Failed to json.Marshal" }`
	}
	return string(b)
}

const (
	ENC_HEX    = "hex"
	ENC_BASE64 = "base64"
)

var encMap = map[string]struct {
	enFunc func([]byte) string
	deFunc func(string) ([]byte, error)
}{
	ENC_HEX:    {hex.EncodeToString, hex.DecodeString},
	ENC_BASE64: {base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString},
	"string": {
		func(b []byte) string { return string(b) },
		func(s string) ([]byte, error) { return []byte(s), nil }},
}

var EncodeArr = []string{ENC_HEX, ENC_BASE64}

func IsValidEncode(name string) bool {
	for _, x := range EncodeArr {
		if x == name {
			return true
		}
	}
	return false
}

func EncodeToString(b []byte, enc string) string {
	x, ok := encMap[enc]
	if !ok {
		panic("invalid encoding: " + enc)
	}
	return x.enFunc(b)
}

func DecodeString(s string, enc string) ([]byte, error) {
	x, ok := encMap[enc]
	if !ok {
		panic("invalid encoding: " + enc)
	}
	return x.deFunc(s)
}

type LoSt map[string]string

func LogInfo(msg string, obj LoSt) {
	var sb strings.Builder
	sb.WriteString("[")
	sb.WriteString(msg)
	sb.WriteString("]\n")
	for k, v := range obj {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\t")
	}
	sb.WriteString("\n")
	syscall.Write(syscall.Stdout, []byte(sb.String()))
}

func LogError(msg string, err error) {
	var sb strings.Builder
	sb.WriteString("[")
	sb.WriteString(msg)
	sb.WriteString("]\n")
	if err != nil {
		sb.WriteString("Error: ")
		sb.WriteString(err.Error())
	}
	sb.WriteString("\n")
	syscall.Write(syscall.Stderr, []byte(sb.String()))
}

func logWrite(fd int, msg string, obj LoSt) {
	var sb strings.Builder
	sb.WriteString("[")
	sb.WriteString(msg)
	sb.WriteString("]\n")
	for k, v := range obj {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\t")
	}
	sb.WriteString("\n")
	syscall.Write(fd, []byte(sb.String()))
}
