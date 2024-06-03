#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include "headers/bpf/bpf_helpers.h"

#define DEFAULT_DROP_PORT 4040

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} drop_port_map SEC(".maps");

SEC("xdp")
int xdp_drop_tcp_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 key = 0;
    __u16 *drop_port;
    __u16 h_proto;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    eth = data;
    h_proto = eth->h_proto;

    if (h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + nh_off;
    nh_off += sizeof(*ip);
    if (data + nh_off > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = data + nh_off;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    drop_port = bpf_map_lookup_elem(&drop_port_map, &key);
    if (!drop_port)
        return XDP_PASS;

    if (tcp->dest == __constant_htons(*drop_port))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

