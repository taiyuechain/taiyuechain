# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: taiyue deps android ios taiyue-cross swarm evm all test clean
.PHONY: taiyue-linux taiyue-linux-386 taiyue-linux-amd64 taiyue-linux-mips64 taiyue-linux-mips64le
.PHONY: taiyue-linux-arm taiyue-linux-arm-5 taiyue-linux-arm-6 taiyue-linux-arm-7 taiyue-linux-arm64
.PHONY: taiyue-darwin taiyue-darwin-386 taiyue-darwin-amd64
.PHONY: taiyue-windows taiyue-windows-386 taiyue-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest
DEPS = $(shell pwd)/internal/jsre/deps

taiyue:
	build/env.sh go run build/ci.go install ./cmd/taiyue
	@echo "Done building."
	@echo "Run \"$(GOBIN)/taiyue\" to launch taiyue."

deps:
	cd $(DEPS) &&	go-bindata -nometadata -pkg deps -o bindata.go bignumber.js web3.js
	cd $(DEPS) &&	gofmt -w -s bindata.go
	@echo "Done generate deps."

swarm:
	build/env.sh go run build/ci.go install ./cmd/swarm
	@echo "Done building."
	@echo "Run \"$(GOBIN)/swarm\" to launch swarm."

all:
	build/env.sh go run build/ci.go install

# android:
#	build/env.sh go run build/ci.go aar --local
#	@echo "Done building."
#	@echo "Import \"$(GOBIN)/taiyue.aar\" to use the library."

# ios:
#	build/env.sh go run build/ci.go xcode --local
#	@echo "Done building."
#	@echo "Import \"$(GOBIN)/taiyue.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

lint: ## Run linters.
	build/env.sh go run build/ci.go lint

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

taiyue-cross: taiyue-linux taiyue-darwin taiyue-windows taiyue-android taiyue-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-*

taiyue-linux: taiyue-linux-386 taiyue-linux-amd64 taiyue-linux-arm taiyue-linux-mips64 taiyue-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-*

taiyue-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/taiyue
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep 386

taiyue-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/taiyue
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep amd64

taiyue-linux-arm: taiyue-linux-arm-5 taiyue-linux-arm-6 taiyue-linux-arm-7 taiyue-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep arm

taiyue-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/taiyue
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep arm-5

taiyue-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/taiyue
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep arm-6

taiyue-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/taiyue
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep arm-7

taiyue-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/taiyue
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep arm64

taiyue-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/taiyue
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep mips

taiyue-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/taiyue
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep mipsle

taiyue-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/taiyue
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep mips64

taiyue-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/taiyue
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-linux-* | grep mips64le

taiyue-darwin: taiyue-darwin-386 taiyue-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-darwin-*

taiyue-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/taiyue
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-darwin-* | grep 386

taiyue-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/taiyue
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-darwin-* | grep amd64

taiyue-windows: taiyue-windows-386 taiyue-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-windows-*

taiyue-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/taiyue
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-windows-* | grep 386

taiyue-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/taiyue
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/taiyue-windows-* | grep amd64
