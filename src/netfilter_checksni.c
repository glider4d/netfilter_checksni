#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <error_codes.h>
#include <common.h>
// #include "netfilter_checksni.h"




MODULE_LICENSE("GPL");
MODULE_AUTHOR("glider");
MODULE_DESCRIPTION("capture outgoing packets on port 443");

static struct nf_hook_ops netfilter_ops;




static KN_STATUS CheckTcp(struct sk_buff *skb){
struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    if (!ip_header)
        return IP_HEADER_GET_ERROR;

    if (!tcp_header)
        return TCP_HEADER_GET_ERROR;

    if (ip_header->protocol == IPPROTO_TCP) return SUCCESS_ERROR;
    return PROTOCOL_SELECTION_ERROR;
}

static KN_STATUS CheckTcpPort(struct sk_buff *skb, int portNumber){
    struct tcphdr *tcp_header = tcp_hdr(skb);
    struct iphdr *ip_header = ip_hdr(skb);
    

    if (!ip_header)
        return IP_HEADER_GET_ERROR;

    if (!tcp_header)
        return TCP_HEADER_GET_ERROR;

    if (!(ip_header->protocol == IPPROTO_TCP)) return PROTOCOL_SELECTION_ERROR;

    if(ntohs(tcp_header->dest) == portNumber ) return SUCCESS_ERROR;
    return CHOSEN_ANOTHER_PORT_ERROR;
}


static int GetDataLenForTcp(struct sk_buff *skb){

    if (CheckTcp(skb) != SUCCESS_ERROR) return -1;

    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    int offset_tcp_ip = (ip_header->ihl * 4 + tcp_header->doff * 4);
    int data_len = skb->len - offset_tcp_ip;
    return data_len;
}

// static KN_STATUS print_sni_without_data_copy(struct sk_buff *skb){
//     struct iphdr *ip_header;
//     struct tcphdr *tcp_header;
    
//     ip_header = ip_hdr(skb);
//     tcp_header = tcp_hdr(skb);

//     if (!ip_header)
//         return IP_HEADER_GET_ERROR;

//     if (!tcp_header)
//         return TCP_HEADER_GET_ERROR;
    

//     return SUCCESS_ERROR;
// }


static KN_STATUS SkbTcpDataCopy(const struct sk_buff *skb, int data_len, char *buff){
        struct iphdr *ip_header;
        struct tcphdr *tcp_header;
        
        ip_header = ip_hdr(skb);
        tcp_header = tcp_hdr(skb);
        if ( skb_copy_bits(skb, ip_header->ihl * 4 + tcp_header->doff * 4, buff, data_len) != 0) 
            return COPY_BUFFER_ERROR;
        return SUCCESS_ERROR;
}

static void PrintSeparator(const char *pref){
    printk(KERN_INFO "%s:---------------------------------------------------------------", pref);
}
static KN_STATUS print_sni_without_data_copy(struct sk_buff *skb, const char * pref){
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    if (!ip_header)
        return IP_HEADER_GET_ERROR;

    if (!tcp_header)
        return TCP_HEADER_GET_ERROR;


    KN_STATUS checkTcpKnStatus = CheckTcp(skb);
    if (checkTcpKnStatus != SUCCESS_ERROR) return checkTcpKnStatus;

    KN_STATUS checkTcpPortKnStatus = CheckTcpPort(skb, TARGET_PORT);
    if (checkTcpPortKnStatus != SUCCESS_ERROR) return checkTcpPortKnStatus;

    int data_len = GetDataLenForTcp(skb);
    if ( data_len < 0 ) return DATA_ISNT_CORRECT_ERROR;
    else if (data_len == 0) return DOSNT_CONTAIN_DATA_ERROR;


    if(!check_skb_for_linearize(skb))
        if (!linearize_skb(skb)) return DATA_LINEAROZED_ERROR;

    int offset_tcp_ip = (ip_header->ihl * 4 + tcp_header->doff * 4);
    bool isTlsHandshake = check_tlshandshake(skb->data + offset_tcp_ip, data_len);

 
    if(isTlsHandshake){
        PrintSeparator(pref);
        PrintHeaderDetails(skb, pref);
        SNI sni = Get_sni(skb->data + offset_tcp_ip, data_len, pref);
        if (sni.sni_server_name_len > 0)
            printk(KERN_INFO "%s: sni sni_server_name_array = %s\n", pref, sni.sni_server_name_array);
        else 
            printk(KERN_INFO "%s: failed to get sni", pref);
    }
    
    return SUCCESS_ERROR; 
}

static KN_STATUS print_sni_with_data_copy(struct sk_buff *skb, const char * pref){
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    if (!ip_header)
        return IP_HEADER_GET_ERROR;

    if (!tcp_header)
        return TCP_HEADER_GET_ERROR;


    KN_STATUS checkTcpKnStatus = CheckTcp(skb);
    if (checkTcpKnStatus != SUCCESS_ERROR) return checkTcpKnStatus;

    KN_STATUS checkTcpPortKnStatus = CheckTcpPort(skb, TARGET_PORT);
    if (checkTcpPortKnStatus != SUCCESS_ERROR) return checkTcpPortKnStatus;

    int data_len = GetDataLenForTcp(skb);
    if ( data_len < 0 ) return DATA_ISNT_CORRECT_ERROR;
    else if (data_len == 0) return DOSNT_CONTAIN_DATA_ERROR;


    if(!check_skb_for_linearize(skb))
        if (!linearize_skb(skb)) return DATA_LINEAROZED_ERROR;

    char * data4 = kmalloc(data_len, GFP_KERNEL);
    if (!data4) return ALLOCATE_MEMORY_ERROR;
    KN_STATUS skbTcpDataCopyStatus = SkbTcpDataCopy(skb, data_len, data4);
    if (skbTcpDataCopyStatus == COPY_BUFFER_ERROR) {
        kfree(data4);
        return skbTcpDataCopyStatus;
    }
    bool isTlsHandshake = check_tlshandshake(data4, data_len);

    
    if(isTlsHandshake){
        PrintSeparator(pref);
        PrintHeaderDetails(skb, pref);
        SNI sni = Get_sni(data4, data_len, pref);
        if (sni.sni_server_name_len > 0)
            printk(KERN_INFO "%s: sni sni_server_name_array = %s\n", pref, sni.sni_server_name_array);
        else 
            printk(KERN_INFO "%s: failed to get sni", pref);
    }
    kfree(data4);
    return SUCCESS_ERROR;    
}


 

static unsigned int hook_func(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state) {

 
    
    //KN_STATUS error_code = print_sni_with_data_copy(skb, "NETFILTER_CHECKSNI");
    KN_STATUS  error_code = print_sni_without_data_copy(skb, "NETFILTER_CHECKSNI");


    if (error_code == SUCCESS_ERROR) {
         SNI sni = Get_sni(data4, data_len);
    }
    
    
    return NF_ACCEPT; //  

}

static int __init packet_sniffer_init(void) {
    int ret;

    netfilter_ops.hook = hook_func;
    netfilter_ops.pf = NFPROTO_IPV4;//PF_INET;
    netfilter_ops.hooknum =  NF_INET_POST_ROUTING;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &netfilter_ops);
  
    if (ret) {
        printk(KERN_ERR "Failed to register Netfilter hook: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "Netfilter module loaded\n");
    return 0;
}

static void __exit packet_sniffer_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(packet_sniffer_init);
module_exit(packet_sniffer_exit);
