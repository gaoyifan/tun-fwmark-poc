CLANG ?= clang
CC ?= gcc
GO ?= go
ARCH_INCLUDE := /usr/include/$(shell gcc -dumpmachine)
BPF_SRCS := bpf/tun_fwmark.bpf.c
BPF_OBJS := $(BPF_SRCS:.c=.o)
POC := scripts/tun_fwmark_poc
POC_GO := scripts/tun_fwmark_poc_go

.PHONY: all all-go clean test test-go bench bench-go

all: $(BPF_OBJS) $(POC)

all-go: $(BPF_OBJS) $(POC_GO)

bpf/%.bpf.o: bpf/%.bpf.c
	$(CLANG) -O2 -g -Wall -Werror -target bpf -I$(ARCH_INCLUDE) -c $< -o $@

$(POC): scripts/tun_fwmark_poc.c
	$(CC) -O2 -g -Wall -Werror $< -o $@ -lbpf -lelf -lz

$(POC_GO): scripts/tun_fwmark_poc.go
	CGO_ENABLED=0 $(GO) build -o $@ $<

clean:
	rm -f $(BPF_OBJS) $(POC) $(POC_GO)

test: all
	sudo -n ./$(POC)

test-go: all-go
	sudo -n ./$(POC_GO)

bench: all
	sudo -n ./$(POC) --bench 2000

bench-go: all-go
	sudo -n ./$(POC_GO) --bench 2000

