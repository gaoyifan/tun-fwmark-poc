CLANG ?= clang
CC ?= gcc
ARCH_INCLUDE := /usr/include/$(shell gcc -dumpmachine)
BPF_SRCS := bpf/tun_fwmark.bpf.c
BPF_OBJS := $(BPF_SRCS:.c=.o)
POC := scripts/tun_fwmark_poc

.PHONY: all clean test bench

all: $(BPF_OBJS) $(POC)

bpf/%.bpf.o: bpf/%.bpf.c
	$(CLANG) -O2 -g -Wall -Werror -target bpf -I$(ARCH_INCLUDE) -c $< -o $@

$(POC): scripts/tun_fwmark_poc.c
	$(CC) -O2 -g -Wall -Werror $< -o $@ -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJS) $(POC)

test: all
	sudo -n ./$(POC)

bench: all
	sudo -n ./$(POC) --bench 2000

