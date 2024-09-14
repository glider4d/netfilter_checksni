#include "common.h"
#include <error_codes.h>

void to_uppercase(unsigned char *str, int len) {
    for(int i = 0; i < len; i ++)
        str[i] = toupper(str[i]);
}

void to_lowercase(unsigned char *str, int len){
    for (int i = 0; i < len; i ++){
        str[i] = tolower(str[i]);
    }
}

void to_upparcase_char(unsigned char * ch){
    *ch = toupper(*ch);
}

void print_data(char * data, int data_len, const char* pref);
void print_skb_data(struct sk_buff *skb, int offset_tcp_ip, const char* pref) {
    if (skb_is_nonlinear(skb)) {
        if (skb_linearize(skb) < 0) {
            pr_err("Failed to linearize skb\n");
            return;
        }
    }


    print_data(skb->data+offset_tcp_ip, skb->len/*-offset_tcp_ip*/, pref);
 
}

void print_data(char * data, int data_len, const char* pref){
    unsigned int i = 0;
    char * data_str;
    data_str = kmalloc(data_len * 3 + 1, GFP_KERNEL);
    int pos = 0;
    for (i = 0; i < data_len && pos < data_len * 3; i++) {
        pos += snprintf(&data_str[pos], data_len * 3 + 1 - pos, "%02X ", data[i]);
    }
    data_str[pos] = '\0';  
    printk(KERN_INFO "%s \nTCP Data: %s\n", pref, data_str);
    kfree(data_str);
}
#define TLS_HANDSHAKE 0X16
#define TLS_CLIENT_HELLO 0X01

bool check_tlshandshake(const unsigned char * data, unsigned int data_len){
    unsigned int pos = 0;

 
    if (data == NULL) return false;

    if (data_len < 5) return false;

    if (data[pos] != TLS_HANDSHAKE)//22 or 0x16 {handshake sign}
        return false;
    pos += 5; //skip the handshake header

    //check client hello

    if (data[pos] != TLS_CLIENT_HELLO) return false;
    return true;
}

 

SNI Get_sni(/*const */unsigned char * data, unsigned int data_len, const char * pref){
    SNI result;
    result.sni_server_name_len = -1;
    result.offset_from_begining_data = -1;
    result.sni_server_name = NULL;
    unsigned int pos = 0;

    if (data == NULL) return result;
    if (data_len < 5) return result;
    if (data[pos] != TLS_HANDSHAKE) return result;
    pos += 5;//skip the handshake header
    if (data[pos] != TLS_CLIENT_HELLO) return result;

    pos += 1; //skip handshake type
    pos += 3; //skip length
    pos += 2; //skip version
    pos += 32;//skip random

    //Skip session ID len
    if (pos >= data_len) return result;
    //for debug
    

    unsigned char sessionIdLen = data[pos];
    printk(KERN_INFO "%s: Session Len = %02X\n", pref, sessionIdLen);
    pos += 1;

    //skip sessionID
    pos += sessionIdLen;
    //skip cipher suites len
    //for debug
    printk(KERN_INFO "%s: cipher first byte = %02x\n", pref, data[pos]);
    printk(KERN_INFO "%s: cipher second byte = %02x\n", pref, data[pos+1]);
    u16 cipher_suites_len = data[pos]<<8|data[pos + 1];//major and minor bytes

    printk(KERN_INFO "%s: cipher suites len = %02X\n", pref, cipher_suites_len);
    pos += 2 + cipher_suites_len;

    //skip compression methods

    if (pos + 1 > data_len) return result;
    pos += 1 + data[pos];

    //process extensions
    if (pos + 2 > data_len) return result;
    u16 extensions_len = data[pos]<<8|data[pos+1];//major and minor bytes

    // u8 step_size = 4;
    int step_count = 0;
    pos += 2;
    while (pos + 4 <= data_len && extensions_len > 0){
        unsigned int ext_type = data[pos]<<8 | data[pos + 1];
        unsigned int ext_len = data[pos + 2] << 8 | data[pos + 3];
        printk(KERN_INFO "%s: step_count = %d, ext_type = %02X, ext_len = %d\n", pref, step_count, ext_type, ext_len);
        step_count++;
        if (ext_type == 0x00){//sni extension
            if (pos + 5 <= data_len) {
                unsigned int sni_len = data[pos + 2] << 8 | data[pos + 3];
                unsigned int server_name_len = data[pos + 7] << 8 | data[pos+8];


                printk(KERN_INFO "%s: serve_name_len = %d", pref, sni_len);
                printk(KERN_INFO "%s: server_name_len = %d\n", pref, server_name_len);
                
                printk(KERN_INFO "%s: after kmalloc\n", pref);
                result.sni_server_name_len = server_name_len + 1;
                printk(KERN_INFO "%s: result.sni_server_name_len = %d\n", pref, result.sni_server_name_len);
                if (result.sni_server_name_len > 0) {//|| result.sni_server_name) {
                    printk(KERN_INFO "%s: IN_IF\n", pref);
                    result.offset_from_begining_data = pos + 9;
                    memcpy(result.sni_server_name_array, &data[pos + 9], server_name_len);
                    printk(KERN_INFO "%s: IN_IF after memcpy\n", pref);
                    result.sni_server_name_array[sni_len] = '\0';
                    printk(KERN_INFO "%s: IN_IF after add 0\n", pref);
                    return result;
                }
            }
            break;
        }

        pos += 4;
        pos += ext_len;
        extensions_len -= ext_len + 4;
    }

    

    return result;
}




bool check_skb_for_linearize(struct sk_buff *skb){
    return !skb_is_nonlinear(skb);
}

bool linearize_skb(struct sk_buff *skb){
    if (check_skb_for_linearize(skb)) return true;
    if (skb_linearize(skb) < 0) return false;
    return true;
}

__sum16 tcp_v4_check_custom(struct sk_buff *skb) {
    struct tcphdr *th = tcp_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    int tcp_len = skb->len - skb_transport_offset(skb);
    return csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP, csum_partial(th, tcp_len, 0));
}

void recalculate_tcp_checksum(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);   // Получаем IP-заголовок
    struct tcphdr *tcph = tcp_hdr(skb); // Получаем TCP-заголовок

    

    // Пересчёт контрольной суммы TCP
    printk(KERN_INFO "TCPH->check before recalc = %x\n", tcph->check);
    // Обнуляем текущую контрольную сумму TCP
    tcph->check = 0;
    tcph->check = tcp_v4_check(skb->len - iph->ihl * 4, iph->saddr, iph->daddr,
                               csum_partial(tcph, skb->len - iph->ihl * 4, 0));
    printk(KERN_INFO "TCPH->check after recalc = %x\n", tcph->check);
    
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4,
                                IPPROTO_TCP, csum_partial(tcph, skb->len - iph->ihl * 4, 0));

    printk(KERN_INFO "TCPH->check 2after recalc = %x\n", tcph->check);
}

int debugUpdateChecksumAndSend(struct sk_buff *skb)
{
    if (dev_queue_xmit(skb) == 0) return SUCCESS_ERROR;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    int tcp_len = skb->len - ip_hdrlen(skb);

    // Пересчёт TCP контрольной суммы
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP, csum_partial(tcph, tcp_len, 0));

    // Пересчёт IP контрольной суммы
    iph->check = 0;
    ip_send_check(iph);

    // Отправка пакета
    if (dev_queue_xmit(skb) < 0) {
        printk(KERN_ERR "Error sending packet\n");
        return ERROR;
    } else {
        printk(KERN_INFO "debugUpdateChecksumAndSend: %x\n", tcph->check);
    }

    return SUCCESS_ERROR;
}

void UpdateChecksum(char *prefix,struct sk_buff *skb){
    struct iphdr *ip_header;

    struct tcphdr *tcpHdr;
    tcpHdr = tcp_hdr(skb);

    ip_header = ip_hdr(skb);
    printk(KERN_INFO "%s: BEFORE Computed IP Checksum :%x, TCP Checksum :%x,  Network : %x\n",prefix, ip_header->check,tcpHdr->check,htons(tcpHdr->check));
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    skb->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);


    if ( (ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP) ) {

    if(skb_is_nonlinear(skb))
        skb_linearize(skb);  // very important.. You need this.

    if (ip_header->protocol == IPPROTO_TCP) {
        
        unsigned int tcplen;

        
        skb->csum =0;
        tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
        tcpHdr->check = 0;
        tcpHdr->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcpHdr, tcplen, 0));

        printk(KERN_INFO "%s: AFTER Computed IP Checksum :%x, TCP Checksum :%x,  Network : %x\n",prefix, ip_header->check,tcpHdr->check,htons(tcpHdr->check));

    } else if (ip_header->protocol == IPPROTO_UDP) {
        /*
        struct udphdr *udpHdr;
        unsigned int udplen;

        udpHdr = udp_hdr(skb);
        skb->csum =0;
        udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
        udpHdr->check = 0;
        udpHdr->check = udp_v4_check(udplen,ip_header->saddr, ip_header->daddr,csum_partial((char *)udpHdr, udplen, 0));;

        printk(KERN_INFO "%s: UDP Len :%d, Computed UDP Checksum :%x : Network : %x\n",prefix,udplen,udpHdr->check,htons(udpHdr->check));*/
    }

    }
}
//---------------------------------------------------------------------------------------------------------------







inline void crc_tcpip_headers(struct sk_buff * ret_sk)
{
  ip_hdr(ret_sk)->check = 0x0;
  tcp_hdr(ret_sk)->check = 0x0;

  ret_sk->ip_summed = CHECKSUM_NONE;
  ip_hdr(ret_sk)->check = ip_fast_csum(ip_hdr(ret_sk), ip_hdr(ret_sk)->ihl);

  /* full checksum calculation */
  ret_sk->csum = skb_checksum(ret_sk,
                              ip_hdrlen(ret_sk),
                              ret_sk->len - ip_hdrlen(ret_sk), 0);

  tcp_hdr(ret_sk)->check = csum_tcpudp_magic(ip_hdr(ret_sk)->saddr,
                                             ip_hdr(ret_sk)->daddr,
                                             ret_sk->len - ip_hdrlen(ret_sk),
                                             IPPROTO_TCP,
                                             ret_sk->csum);

printk(KERN_INFO "%s: BEFORE Computed IP Checksum :%x, TCP Checksum :%x,  Network : %x\n","crc_tcpip_headers", ip_hdr(ret_sk)->check,tcp_hdr(ret_sk)->check,htons(tcp_hdr(ret_sk)->check));


}
//---------------------------------------------------------------------------------------------------------------
// Основная функция для фрагментации пакета
unsigned int fragment_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    unsigned int tcp_hdr_len = tcph->doff * 4;
    unsigned int ip_hdr_len = iph->ihl * 4;
    unsigned int data_len = skb->len - ip_hdr_len - tcp_hdr_len;

    // Если данных недостаточно для фрагментации, выходим
    if (data_len <= 100) {
        return NF_ACCEPT;
    }

    // Определяем точки разделения пакета
    unsigned int first_part_size = data_len / 2;
    // unsigned int second_part_size = data_len - first_part_size;

    // Клонирование пакета
    struct sk_buff *second_skb = skb_clone(skb, GFP_ATOMIC);
    if (!second_skb) {
        printk(KERN_ERR "Failed to clone skb\n");
        return NF_DROP;
    }

    printk(KERN_INFO "fragment_packet: skb->len = %u, skb->data_len = %u\n", skb->len, skb->data_len);
    printk(KERN_INFO "fragment_packet: second_skb->len = %u, second_skb->data_len = %u\n",second_skb->len, second_skb->data_len);
    int total_length = skb->len + skb_transport_offset(skb) + skb_network_offset(skb);
    printk(KERN_INFO "fragment_packet: total_length = %u\n", total_length);
    // Обрезаем первый пакет
    skb_trim(skb, ip_hdr_len + tcp_hdr_len + first_part_size);
    UpdateChecksum("1from fragment_packet: ", skb);
    crc_tcpip_headers(skb);
    
    // tcp_checksum(skb);
    // ip_checksum(iph);

    // Убираем данные из второго пакета
    skb_pull(second_skb, ip_hdr_len + tcp_hdr_len + first_part_size);
    skb_reset_transport_header(second_skb);
    skb_reset_network_header(second_skb);
    UpdateChecksum("2from fragment_packet: ", second_skb);
    crc_tcpip_headers(second_skb);
    // tcp_checksum(second_skb);
    // ip_checksum(ip_hdr(second_skb));

    // Отправляем оба пакета
    dev_queue_xmit(skb);
    dev_queue_xmit(second_skb);
    struct iphdr *iph_skb = ip_hdr(skb);
    struct iphdr *iph_second_skb = ip_hdr(second_skb);
    
    
    printk(KERN_ERR "iph_skb->id = %u, iph_second_skb->id = %u\n", iph_skb->id, iph_second_skb->id);
    printk(KERN_ERR "skb->data_len = %u, = second_skb->data_len = %u\n", skb->data_len, second_skb->data_len);
    print_data(skb->data, skb->data_len, "first bits:");
    print_data(second_skb->data, second_skb->data_len, "first bits:");

    return NF_STOLEN;
}

//--------------------------------------------------------------------------------------------------------------














// Предполагаем, что у нас есть пакет skb, который мы получили в каком-то сетевом hook-е.

int send_partial_packet(struct sk_buff *skb, unsigned int len)
{
    struct sk_buff *skb_clone_packet;

    // Клонируем оригинальный skb, чтобы не модифицировать его
    skb_clone_packet = skb_clone(skb, GFP_ATOMIC);
    if (!skb_clone_packet) {
        printk(KERN_ERR "Failed to clone skb\n");
        return -ENOMEM;
    }

    // Получаем заголовок IP-пакета
    struct iphdr *ip_header_original = ip_hdr(skb);
    if (!ip_header_original)
        return NF_ACCEPT;

    struct iphdr *ip_header_clone = ip_hdr(skb);
    if (!ip_header_clone)
        return NF_ACCEPT;

    printk(KERN_INFO "1Orognal id = %u, Clone id = %u\n", ip_header_original->id, ip_header_clone->id);
    

    printk(KERN_INFO "skb_clone_packet->len %u BEFORE_TRIM\n", skb_clone_packet->len);
    // Обрезаем пакет до длины len (оставляем только первые len байт)
    //skb_trim(skb_clone_packet, len);  // skb_trim возвращает void, поэтому просто вызываем её
    printk(KERN_INFO "2Orognal id = %u, Clone id = %u\n", ip_header_original->id, ip_header_clone->id);

    UpdateChecksum("UpdateAfterTrim", skb_clone_packet);

    printk(KERN_INFO "3Orognal id = %u, Clone id = %u\n", ip_header_original->id, ip_header_clone->id);

    printk(KERN_INFO "skb_clone_packet->len %u AFTER_TRIM\n", skb_clone_packet->len);
    
    // Отправляем обрезанный пакет
    int ret = dev_queue_xmit(skb_clone_packet); // Отправляем в сетевой стек
    //ret = dev_queue_xmit(skb_clone_packet); // Отправляем в сетевой стек
    if (ret < 0) {
        printk(KERN_ERR "Failed to send the packet: %d\n", ret);
        kfree_skb(skb_clone_packet); // Освобождаем память в случае ошибки
        return ret;
    }

    return SUCCESS_ERROR; // Успех
}


void PrintHeaderDetails(const struct sk_buff *skb, const unsigned char * pref) {
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    u16 ip_id = ntohs(ip_header->id);
    printk(KERN_INFO "%s: ID ip: %u", pref, ip_id);
    printk(KERN_INFO "%s: Packet to port 443 intercepted\n", pref);
    printk(KERN_INFO "%s: Source IP: %pI4\n", pref, &ip_header->saddr);
    printk(KERN_INFO "%s: Destination IP: %pI4\n", pref, &ip_header->daddr);
    printk(KERN_INFO "%s: Source port: %u\n", pref, ntohs(tcp_header->source));
    printk(KERN_INFO "%s: Destination port: %u\n", pref, ntohs(tcp_header->dest));
    printk(KERN_INFO "%s: Packet length: %u\n", pref, skb->len);

    //-----------------------------------------------------------------------------
    printk(KERN_INFO "%s: ip_header->ihl = %u\n", pref, ip_header->ihl);
    printk(KERN_INFO "%s: tcp_header->doff = %u\n", pref, tcp_header->doff);
}