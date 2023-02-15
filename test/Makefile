BPF_FS ?= /sys/fs/bpf
NET_DEV ?= ens36

.PHONY: all clean

all:

.PHONY: $(BPF_FS)
$(BPF_FS):
	mountpoint -q $@ || mount -t bpf none $@

pull:
	git pull

dnat:
	sudo ip link set dev $(NET_DEV) xdp obj ../xdp_dnat_kern.o

test:
	#sudo ip link set dev $(NET_DEV) xdp obj ../xdp_dnat_kern.o
	sudo tc qdisc add dev $(NET_DEV) clsact
	sudo tc filter add dev $(NET_DEV) ingress bpf direct-action obj ../tc_snat_kern.o sec nat
	sudo tc filter add dev $(NET_DEV) egress bpf direct-action obj ../tc_dnat_kern.o sec nat


cancel:
	#sudo ip link set dev $(NET_DEV) xdp off
	sudo tc filter delete dev $(NET_DEV) ingress
	sudo tc filter delete dev $(NET_DEV) egress
	sudo tc qdisc delete dev $(NET_DEV) clsact

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe|grep bpf_trace_printk

tcpdump:
	sudo tcpdump tcp -i $(NET_DEV) -nev
	#tcpdump tcp -i $(NET_DEV) -nnevSX
	#tcpdump tcp -i $(NET_DEV) -nnevSX port 5000