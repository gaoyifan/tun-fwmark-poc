CLANG ?= clang
ARCH_INCLUDE := /usr/include/$(shell gcc -dumpmachine)
BPF_SRCS := bpf/tun_ingress_mark_strip.bpf.c bpf/tun_egress_mark_prepend.bpf.c
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all clean

all: $(BPF_OBJS)

bpf/%.bpf.o: bpf/%.bpf.c
	$(CLANG) -O2 -g -Wall -Werror -target bpf -I$(ARCH_INCLUDE) -c $< -o $@

clean:
	rm -f $(BPF_OBJS)
