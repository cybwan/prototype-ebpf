BPF_FS=/sys/fs/bpf
PIN_OBJECT_NS_PATH=/sys/fs/bpf
PIN_GLOBAL_NS_PATH=/sys/fs/bpf/tc/globals

NET_DEV ?= ens33

.PHONY: all clean

all:

#.PHONY: $(BPF_FS) $(PIN_GLOBAL_NS_PATH)
$(BPF_FS):
	mountpoint -q $@ || mount -t bpf none $@

$(PIN_GLOBAL_NS_PATH): $(BPF_FS)
	[ -d $@ ] || sudo mkdir -p $@

load-map-acc_map: $(PIN_GLOBAL_NS_PATH)
	[ -f $(PIN_GLOBAL_NS_PATH)/acc_map ] || sudo bpftool map create $(PIN_GLOBAL_NS_PATH)/acc_map type array key 4 value 4 entries 2 name acc_map

clean-acc_map:
	[ -f $(PIN_GLOBAL_NS_PATH)/acc_map ] && sudo rm -f $(PIN_GLOBAL_NS_PATH)/acc_map

pull:
	git pull

test:
	tc qdisc add dev $(NET_DEV) clsact
	tc filter add dev $(NET_DEV) ingress bpf da obj ../tc_kern.o sec classifier/ingress
	tc filter add dev $(NET_DEV) egress  bpf da obj ../tc_kern.o sec classifier/egress

test-cancel:
	sudo tc filter delete dev $(NET_DEV) ingress
	sudo tc filter delete dev $(NET_DEV) egress
	sudo tc qdisc delete dev $(NET_DEV) clsact

tc-ingress-show:
	tc filter show dev $(NET_DEV) ingress

tc-egress-show:
	tc filter show dev $(NET_DEV) egress

map:
	bpftool map show

prog:
	bpftool prog show

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe|grep bpf_trace_printk

tcpdump:
	sudo tcpdump tcp -i $(NET_DEV) -nev
	#tcpdump tcp -i $(NET_DEV) -nnevSX
	#tcpdump tcp -i $(NET_DEV) -nnevSX port 5000