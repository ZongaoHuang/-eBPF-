#include "bpf_helpers.h"
#include <arpa/inet.h>
#include "stdlib.h"
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define MAX_RULES  512
#define NANO_TO_SEC 1000000000
#define default_pps 100
#define default_bps 100000
#define default_syn_count 50
#define default_udp_count 500

struct ip_stats{
    __u64 pps;  //每秒数据包数
    __u64 bps;  //每秒字节数
    __u64 next_update;  //下一次更新时间
};

struct syn_stats{
    __u64 syn_count;  //syn包数
    __u64 next_update;  //下一次更新时间
};

struct udp_stats{
    __u64 udp_count;  //udp包数
    __u64 next_update;  //下一次更新时间
};

BPF_MAP_DEF(syn_counter) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(struct syn_stats),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(syn_counter);

BPF_MAP_DEF(udp_counter) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(struct udp_stats),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(udp_counter);

BPF_MAP_DEF(ip_counter) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ip_stats),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_counter);

BPF_MAP_DEF(ip_blacklist_t) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_blacklist_t);

BPF_MAP_DEF(ip_blacklist_p) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_blacklist_p);

BPF_MAP_DEF(config_pps) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 1
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(config_pps);

BPF_MAP_DEF(config_bps) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 2
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(config_bps);

BPF_MAP_DEF(block_flag) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32), //key = 3
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(block_flag);

BPF_MAP_DEF(unblock_time) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 4
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(unblock_time);

BPF_MAP_DEF(config_syn) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 5
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(config_syn);

BPF_MAP_DEF(config_udp) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 6
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(config_udp);

BPF_MAP_DEF(arp_flag) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 7
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(arp_flag);

BPF_MAP_DEF(arp_table) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //IP地址
    .value_size = sizeof(__u64), //MAC地址 
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(arp_table);

BPF_MAP_DEF(drop_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 8
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(drop_cnt);

BPF_MAP_DEF(pass_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 9
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(pass_cnt);

BPF_MAP_DEF(wrong_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 10
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(wrong_cnt);

BPF_MAP_DEF(temp_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 11
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(temp_cnt);

BPF_MAP_DEF(now_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 12
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(now_cnt);

BPF_MAP_DEF(next_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 13
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(next_cnt);

BPF_MAP_DEF(btime_cnt) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),  //key = 14
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(btime_cnt);

struct arp_hdr {
    __u16 hardware_type;      // 硬件类型
    __u16 protocol_type;      // 协议类型
    __u8 hardware_size;        // mac地址长度
    __u8 protocol_size;        // ip地址长度
    __u16 opcode;             // 操作码
    unsigned char sender_hard_addr[ETH_ALEN]; // 发送方硬件地址
    __u32 sender_proto_addr;  // 发送方协议地址
    unsigned char target_hard_addr[ETH_ALEN]; // 目标硬件地址
    __u32 target_proto_addr;  // 目标协议地址
}__attribute__((packed));

/*
BPF_MAP_DEF(jump_table) = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .max_entries = 8,
};
BPF_MAP_ADD(jump_table);
*/

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end; //数据包的结束指针
  void *data = (void *)(long)ctx->data; //数据包的起始指针

  //将数据包的起始指针转换为以太网头部结构体的指针
  struct ethhdr *ether = data;
  __u32 drop_cnt_key=8;
  __u32 pass_cnt_key=9;
  __u32 wrong_cnt_key=10;
  __u64* drop_cnt_value = NULL;
  __u64* pass_cnt_value = NULL;
  __u64* wrong_cnt_value = NULL;
  //以太网头部超出边界说明以太网头部不完整，要丢弃
  if (data + sizeof(*ether) > data_end) { 
    wrong_cnt_value = bpf_map_lookup_elem(&wrong_cnt, &wrong_cnt_key);
    if (wrong_cnt_value) {
      __u64 new_wrong_cnt_value =*wrong_cnt_value + 1;
      bpf_map_update_elem(&wrong_cnt, &wrong_cnt_key, &new_wrong_cnt_value, BPF_ANY);
    }
    return XDP_DROP;
  }

  if (ether->h_proto != htons(ETH_P_IP) && ether->h_proto != htons(ETH_P_ARP) ) {  
    // 非IPv4或arp数据包，直接放行
    return XDP_PASS;
  }

  if (ether->h_proto == htons(ETH_P_ARP)) {
    void* arp_data = data + sizeof(*ether);
    struct arp_hdr *arp = arp_data;
    if (arp_data + sizeof(*arp) > data_end) {
      wrong_cnt_value = bpf_map_lookup_elem(&wrong_cnt, &wrong_cnt_key);
      if (wrong_cnt_value) {
        __u64 new_wrong_cnt_value =*wrong_cnt_value + 1;
        bpf_map_update_elem(&wrong_cnt, &wrong_cnt_key, &new_wrong_cnt_value, BPF_ANY);
      }
      return XDP_DROP;
    }
    __u32 arp_flag_key=7;
    __u64 *arp_flag_value = bpf_map_lookup_elem(&arp_flag, &arp_flag_key);
    if (arp_flag_value==NULL) {
      return XDP_PASS;
    }
    if (*arp_flag_value!=0) { //根据ip-mac映射表进行过滤
      __u32 saddr = arp->sender_proto_addr;
      saddr = htonl(saddr); //将主机字节序转换为网络字节序
      __u64* macValue = bpf_map_lookup_elem(&arp_table, &saddr);
      if (macValue==NULL) {
        drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
        if (drop_cnt_value) {
          __u64 new_drop_cnt_value =*drop_cnt_value + 1;
          bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
        }
        return XDP_DROP;
      } else {
        __u64 mac_int = 0;
        unsigned char *mac =arp->sender_hard_addr;
        for (int i = 0; i < ETH_ALEN; i++) {
            mac_int <<= 8; // 左移 8 位，为新字节腾出空间
            mac_int |= mac[i]; // 将当前字节与结果结合
        }
        if (mac_int!=*macValue) {
          drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
          if (drop_cnt_value) {
            __u64 new_drop_cnt_value =*drop_cnt_value + 1;
            bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
          }
          return XDP_DROP;
        }
      }
    }
    pass_cnt_value = bpf_map_lookup_elem(&pass_cnt, &pass_cnt_key);
    if (pass_cnt_value) {
      __u64 new_pass_cnt_value =*pass_cnt_value + 1;
      bpf_map_update_elem(&pass_cnt, &pass_cnt_key, &new_pass_cnt_value, BPF_ANY);
    }
    return XDP_PASS;
  }

  struct iphdr *ip=NULL;
  data += sizeof(*ether); //将数据指针移动到IPv4头部
  ip = data;  
  //检查IPv4头部是否超出数据包的边界
  if (data + sizeof(*ip) > data_end) {
    wrong_cnt_value = bpf_map_lookup_elem(&wrong_cnt, &wrong_cnt_key);
    if (wrong_cnt_value) {
      __u64 new_wrong_cnt_value =*wrong_cnt_value + 1;
      bpf_map_update_elem(&wrong_cnt, &wrong_cnt_key, &new_wrong_cnt_value, BPF_ANY);
    }
    return XDP_DROP;
  }

  __u32 saddr = ip->saddr;
  saddr = htonl(saddr); //将主机字节序转换为网络字节序
  __u64 *blocked_perm = NULL;    // Check ip_blacklist_p
  blocked_perm=bpf_map_lookup_elem(&ip_blacklist_p, &saddr);
  if (blocked_perm) {
    drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
    if (drop_cnt_value) {
      __u64 new_drop_cnt_value =*drop_cnt_value + 1;
      bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
    }
    return XDP_DROP;
  }

  __u64 *blocked_temp = NULL;    // Check ip_blacklist_t
  blocked_temp=bpf_map_lookup_elem(&ip_blacklist_t, &saddr);
  struct ip_stats* ip_stats_pointer= NULL;
  ip_stats_pointer=bpf_map_lookup_elem(&ip_counter, &saddr);
  __u64 now = bpf_ktime_get_ns(); //获取当前的内核时间戳(纳秒)
  __u16 pkt_len = data_end - data;

  if (blocked_temp) {
    __u32 block_flag_key=3;
    __u32 unblock_time_key=4;
    __u64 *block_flag_value = bpf_map_lookup_elem(&block_flag, &block_flag_key);
    __u64 *unblock_time_value = bpf_map_lookup_elem(&unblock_time, &unblock_time_key);
    if (block_flag_value==NULL || unblock_time_value==NULL) {
      return XDP_DROP;
    }
    if (*block_flag_value!=0) {
      drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
      if (drop_cnt_value) {
        __u64 new_drop_cnt_value =*drop_cnt_value + 1;
        bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
      }
      return XDP_DROP;
    }
    if (ip_stats_pointer) {
      __u32 now_cnt_key=12;
      __u32 next_cnt_key=13;
      __u32 btime_cnt_key=14;
      __u64 nowtemp=now;
      __u64 nexttemp=ip_stats_pointer->next_update;
      __u64 btimetemp=(*unblock_time_value) * NANO_TO_SEC;
      bpf_map_update_elem(&now_cnt, &now_cnt_key, &nowtemp, BPF_ANY);
      bpf_map_update_elem(&next_cnt, &next_cnt_key, &nexttemp, BPF_ANY);
      bpf_map_update_elem(&btime_cnt, &btime_cnt_key, &btimetemp, BPF_ANY);
      if (now - ip_stats_pointer->next_update >= (*unblock_time_value)*NANO_TO_SEC) {
        bpf_map_delete_elem(&ip_blacklist_t, &saddr);
        struct ip_stats new_ip_stats={0};
        new_ip_stats.pps = 1;
        new_ip_stats.bps = pkt_len;
        new_ip_stats.next_update = now + NANO_TO_SEC;
        bpf_map_update_elem(&ip_counter, &saddr, &new_ip_stats, BPF_ANY);
        pass_cnt_value = bpf_map_lookup_elem(&pass_cnt, &pass_cnt_key);
        if (pass_cnt_value) {
          __u64 new_pass_cnt_value =*pass_cnt_value + 1;
          bpf_map_update_elem(&pass_cnt, &pass_cnt_key, &new_pass_cnt_value, BPF_ANY);
        }
        __u32 temp_cnt_key=11;
        __u64 *temp_cnt_value = bpf_map_lookup_elem(&temp_cnt, &temp_cnt_key);
        if (temp_cnt_value) {
          __u64 new_temp_cnt_value =*temp_cnt_value + 1;
          bpf_map_update_elem(&temp_cnt, &temp_cnt_key, &new_temp_cnt_value, BPF_ANY);
        }
        return XDP_PASS;
      }
    } else {
      struct ip_stats new_ip_stats={0};
      new_ip_stats.pps = 1;
      new_ip_stats.bps = pkt_len;
      new_ip_stats.next_update = now + NANO_TO_SEC;
      bpf_map_update_elem(&ip_counter, &saddr, &new_ip_stats, BPF_ANY);
    }
    drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
    if (drop_cnt_value) {
      __u64 new_drop_cnt_value =*drop_cnt_value + 1;
      bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
    }
    return XDP_DROP;
  }
  struct ip_stats new_ip_stats={0};
  if (ip_stats_pointer) {
    if (now > ip_stats_pointer->next_update) {
      new_ip_stats.pps = 1;
      new_ip_stats.bps = pkt_len;
      new_ip_stats.next_update = now + NANO_TO_SEC;
    } else {
      new_ip_stats.pps = ip_stats_pointer->pps + 1;
      new_ip_stats.bps = ip_stats_pointer->bps + pkt_len;
      new_ip_stats.next_update = ip_stats_pointer->next_update;
    }
  } else {
    new_ip_stats.pps = 1;
    new_ip_stats.bps = pkt_len;
    new_ip_stats.next_update = now + NANO_TO_SEC;
  }
  bpf_map_update_elem(&ip_counter, &saddr, &new_ip_stats, BPF_ANY);
  ip_stats_pointer=bpf_map_lookup_elem(&ip_counter, &saddr);
  if (ip_stats_pointer==NULL) {
    return XDP_DROP;
  }
  __u32 limit_pps = default_pps;
  __u32 limit_bps = default_bps;
  __u32 pps_key=1;
  __u32 bps_key=2;
  __u64 *pps_value = bpf_map_lookup_elem(&config_pps, &pps_key);
  __u64 *bps_value = bpf_map_lookup_elem(&config_bps, &bps_key);
  if (pps_value) {
    limit_pps = *pps_value;
  }
  if (bps_value) {
    limit_bps = *bps_value;
  }

  if (ip_stats_pointer->pps > limit_pps || ip_stats_pointer->bps > limit_bps) {
    __u32 value=1;
    bpf_map_update_elem(&ip_blacklist_t, &saddr, &value, BPF_ANY);
    drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
    if (drop_cnt_value) {
      __u64 new_drop_cnt_value =*drop_cnt_value + 1;
      bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
    }
    return XDP_DROP;
  }

  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
  data += ip->ihl * 4;
  switch (ip->protocol) {
    case IPPROTO_TCP:
      tcph = data;
      if (data  + sizeof(*tcph) > data_end) {
        wrong_cnt_value = bpf_map_lookup_elem(&wrong_cnt, &wrong_cnt_key);
        if (wrong_cnt_value) {
          __u64 new_wrong_cnt_value =*wrong_cnt_value + 1;
          bpf_map_update_elem(&wrong_cnt, &wrong_cnt_key, &new_wrong_cnt_value, BPF_ANY);
        }
        return XDP_DROP;
      }
      break;
    case IPPROTO_UDP:
      udph = data;
      if (data  + sizeof(*udph) > data_end) {
        wrong_cnt_value = bpf_map_lookup_elem(&wrong_cnt, &wrong_cnt_key);
        if (wrong_cnt_value) {
          __u64 new_wrong_cnt_value =*wrong_cnt_value + 1;
          bpf_map_update_elem(&wrong_cnt, &wrong_cnt_key, &new_wrong_cnt_value, BPF_ANY);
        }
        return XDP_DROP;
      }
  }


  if (tcph  && (tcph->syn == 1) && (tcph->ack == 0)) {
    __u16 dport = ntohs(tcph->dest);
    struct syn_stats* syn_stats_pointer= NULL;
    syn_stats_pointer=bpf_map_lookup_elem(&syn_counter, &dport);
    struct syn_stats new_syn_stats={0};
    if (syn_stats_pointer) {
      if (now > syn_stats_pointer->next_update) {
        new_syn_stats.syn_count = 1;
        new_syn_stats.next_update = now + NANO_TO_SEC;
      } else {
        new_syn_stats.syn_count = syn_stats_pointer->syn_count + 1;
        new_syn_stats.next_update = syn_stats_pointer->next_update;
      }
    } else {
      new_syn_stats.syn_count = 1;
      new_syn_stats.next_update = now + NANO_TO_SEC;
    }
    bpf_map_update_elem(&syn_counter, &dport, &new_syn_stats, BPF_ANY);
    syn_stats_pointer=bpf_map_lookup_elem(&syn_counter, &dport);
    if (syn_stats_pointer==NULL) {
      return XDP_PASS;
    }
    __u64 limit_syn = default_syn_count;
    __u32 syn_count_key=5;
    __u64 *syn_count_value = bpf_map_lookup_elem(&config_syn, &syn_count_key);
    if (syn_count_value) {
      limit_syn = *syn_count_value;
    }
    if (syn_stats_pointer->syn_count > limit_syn) {
      __u32 value=1;
      bpf_map_update_elem(&ip_blacklist_t, &saddr, &value, BPF_ANY);
      drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
      if (drop_cnt_value) {
        __u64 new_drop_cnt_value =*drop_cnt_value + 1;
        bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
      }
      return XDP_DROP;
    }
  }


  if (udph) {
    __u16 dport = ntohs(udph->dest);
    struct udp_stats* udp_stats_pointer= NULL;
    udp_stats_pointer=bpf_map_lookup_elem(&udp_counter, &dport);
    struct udp_stats new_udp_stats={0};
    if (udp_stats_pointer) {
      if (now > udp_stats_pointer->next_update) {
        new_udp_stats.udp_count = 1;
        new_udp_stats.next_update = now + NANO_TO_SEC;
      } else {
        new_udp_stats.udp_count = udp_stats_pointer->udp_count + 1;
        new_udp_stats.next_update = udp_stats_pointer->next_update;
      }
    } else {
      new_udp_stats.udp_count = 1;
      new_udp_stats.next_update = now + NANO_TO_SEC;
    }
    bpf_map_update_elem(&udp_counter, &dport, &new_udp_stats, BPF_ANY);
    udp_stats_pointer=bpf_map_lookup_elem(&udp_counter, &dport);
    if (udp_stats_pointer==NULL) {
      return XDP_PASS;
    }
    __u64 limit_udp = default_udp_count;
    __u32 udp_count_key=6;
    __u64 *udp_count_value = bpf_map_lookup_elem(&config_udp, &udp_count_key);
    if (udp_count_value) {
      limit_udp = *udp_count_value;
    }
    if (udp_stats_pointer->udp_count > limit_udp) {
      __u32 value=1;
      bpf_map_update_elem(&ip_blacklist_t, &saddr, &value, BPF_ANY);
      drop_cnt_value = bpf_map_lookup_elem(&drop_cnt, &drop_cnt_key);
      if (drop_cnt_value) {
        __u64 new_drop_cnt_value =*drop_cnt_value + 1;
        bpf_map_update_elem(&drop_cnt, &drop_cnt_key, &new_drop_cnt_value, BPF_ANY);
      }
      return XDP_DROP;
    }
  }

  pass_cnt_value = bpf_map_lookup_elem(&pass_cnt, &pass_cnt_key);
  if (pass_cnt_value) {
    __u64 new_pass_cnt_value =*pass_cnt_value + 1;
    bpf_map_update_elem(&pass_cnt, &pass_cnt_key, &new_pass_cnt_value, BPF_ANY);
  }
  return XDP_PASS;
}

/*
SEC("xdp")
int firewall_arp(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end; //数据包的结束指针
  void *data = (void *)(long)ctx->data; //数据包的起始指针
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) { 
    return XDP_DROP;
  }
  if (ether->h_proto != htons(ETH_P_ARP) ) {  
    
      //调用 firewall 函数
      //int index=0;
      //bpf_tail_call(ctx, &jump_table, index);
    
    return XDP_PASS;
  }
  data += sizeof(*ether);
  struct arphdr *arp = data;
  if (data + sizeof(*arp) > data_end) {
    return XDP_DROP;
  }
  return XDP_PASS;
}
*/

char _license[] SEC("license") = "GPL";

/*
#define ETH_ALEN 6        // MAC地址长度
#define ETH_HLEN 14       // 以太网头部长度

struct ethhdr {
    unsigned char h_dest[ETH_ALEN];  // 目的MAC地址
    unsigned char h_source[ETH_ALEN]; // 源MAC地址
    __be16 h_proto;                   // 以太网协议类型
} __attribute__((packed));



#define ETH_P_IP  0x0800 // IP协议
#define ETH_P_ARP 0x0806 // ARP协议
#define ETH_P_ALL 0x0003 // 所有协议

*/