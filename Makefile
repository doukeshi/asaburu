STATIC_DIR := static
OUT_DIR := public
PREFIX ?= /

.PHONY: wasm public serve build clean

# public/asaburu.wasm: cmd/wasm/main.go go/*.go
# 	tinygo build -target wasm -o $@ $<
# $(STATIC_DIR)/wasm_exec.js: $(shell tinygo env TINYGOROOT)/targets/wasm_exec.js
# 	cp $< $@6

public/asaburu.wasm: cmd/wasm/main.go go/*.go
	GOOS=js GOARCH=wasm go build -o $@ $<

$(STATIC_DIR)/wasm_exec.js: $(shell go env GOROOT)/lib/wasm/wasm_exec.js
	cp $< $@

wasm: $(STATIC_DIR)/wasm_exec.js public/asaburu.wasm

public:
	cp $(STATIC_DIR)/* $(OUT_DIR)

serve: wasm public
	go run cmd/serve/main.go -o $(OUT_DIR) -p $(PREFIX)

build: wasm public
	go run cmd/serve/main.go -o $(OUT_DIR) -p $(PREFIX) -b

clean:
	rm -rf $(OUT_DIR)/*
	rm -rf $(STATIC_DIR)/wasm_exec.js
