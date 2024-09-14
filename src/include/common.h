
#ifndef COMMON_
#define COMMON_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include "limits.h"



#define TARGET_PORT 443


typedef struct {
    unsigned char * sni_server_name;
    unsigned char sni_server_name_array[MAX_HOST_NAME];
    u16 sni_server_name_len;
    u16 offset_from_begining_data;
} SNI;

void to_uppercase(unsigned char *str, int len);
void to_lowercase(unsigned char *str, int len);
void to_upparcase_char(unsigned char * ch);
void print_data(char * data, int data_len, const char* pref);
void print_skb_data(struct sk_buff *skb, int offset_tcp_ip, const char* pref);
bool check_tlshandshake(const unsigned char * data, unsigned int data_len);
SNI Get_sni(/*const */unsigned char * data, unsigned int data_len, const char * pref);
bool check_skb_for_linearize(struct sk_buff *skb);
bool linearize_skb(struct sk_buff *skb);
__sum16 tcp_v4_check_custom(struct sk_buff *skb);
void recalculate_tcp_checksum(struct sk_buff *skb);
int debugUpdateChecksumAndSend(struct sk_buff *skb);
void UpdateChecksum(char *prefix,struct sk_buff *skb);
inline void crc_tcpip_headers(struct sk_buff * ret_sk);
unsigned int fragment_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int send_partial_packet(struct sk_buff *skb, unsigned int len);
void PrintHeaderDetails(const struct sk_buff *skb, const unsigned char * pref);

#endif //COMMON_