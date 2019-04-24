#include <node_api.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
//#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include <pcap.h>
#include "sniffer.h"

typedef struct {
    struct packet_node* _next;

    char  *packet;
    int packet_size;

    int _retransmitted;
    int _out_of_order;    

    unsigned int tcp_seq;
} packet_node;

typedef struct {
    struct tcp_node* _next;

    char *ip_src;
    unsigned short ip_src_port;
    char *ip_dst;
    unsigned short ip_dst_port;

    packet_node* _req;
    packet_node* _res;
} tcp_node;

tcp_node* tcp_head;

typedef struct {
    int _offline;
    struct bpf_program _fp;     
    pcap_t *_handle;
    int _packet_cnt;
    tcp_node* _output;
    napi_ref _callback;
    napi_async_work _work;
} carrier;

carrier the_carrier;

#define nullptr NULL

packet_node* 
create_packet_node(char *payload, int size_payload, unsigned int tcp_seq)
{
    packet_node *n = malloc(sizeof(packet_node));
    n->packet = malloc(size_payload);
    memcpy(n->packet, payload, size_payload);
    n->packet_size = size_payload;
    n->tcp_seq = tcp_seq;
    n->_retransmitted = 0;
    n->_out_of_order = 0;    
    n->_next = NULL;

    return n;
}

void
add_packet_node(packet_node **head, char *payload, int size_payload, unsigned int tcp_seq)
{
    packet_node *walker = *head; 
    packet_node *prev = NULL;

    packet_node *n = create_packet_node(payload, size_payload, tcp_seq);

    while(walker != NULL){
        if(tcp_seq < walker->tcp_seq) {
            n->_out_of_order++;

            if(prev == NULL) {
                n->_next = walker;
                *head = n;
            } else {
                prev->_next = n;
                n->_next = walker;
            }

            return;
        } else if(tcp_seq == walker->tcp_seq) {
            n->_retransmitted = walker->_retransmitted;
            n->_out_of_order = walker->_out_of_order;
            n->_retransmitted++;

            if(prev == NULL) {
                n->_next = walker->_next;
                *head = n;
                free(walker->packet);
                free(walker);
            } else {
                prev->_next = n;
                n->_next = walker->_next;
                free(walker->packet);
                free(walker);
            }

            return;
        } 

        if(walker->_next == NULL) {
            break;
        }

        prev = walker;
        walker = walker->_next;
    };

    walker->_next = n;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ethhdr *ethernet;
    const struct iphdr *ip;
    const struct ip6_hdr *ip6;
    const struct tcphdr *tcp;
    const char *payload;
    const char *src;
    const char *dst;

    int size_ip;
    int size_tcp;
    int size_payload;
    
    ethernet = (struct ethhdr*)(packet);

    ip = (struct iphdr*)(packet + ETH_HLEN);

    if(IP_V(ip) == 4) {
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        if(ip->ip_p != IPPROTO_TCP) {
            printf("   * Invalid TCP protocol: %u\n", ip->ip_p);
            return;
        }
    }

    if(IP_V(ip) == 6) {
        ip6 = (struct ip6_hdr*)(ip); 

        size_ip = sizeof(struct ip6_hdr);

        if(ip6->ip6_nxt != IPPROTO_TCP) {
            printf("   * Invalid TCP protocol: %u\n", ip6->ip6_nxt);
            return;
        }
    }

    tcp = (struct tcphdr*)(packet + ETH_HLEN + size_ip);
    size_tcp = tcp->th_off*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    payload = (u_char *)(packet + ETH_HLEN + size_ip + size_tcp);

    size_payload = header->len - (ETH_HLEN + size_ip + size_tcp);

    if (size_payload > 0) {
        if(IP_V(ip) == 4) {
            src = malloc(INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->ip_src), src, INET_ADDRSTRLEN);
            dst = malloc(INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->ip_dst), dst, INET_ADDRSTRLEN);
        }

        if(IP_V(ip) == 6) {
            src = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6->ip6_src), src, INET6_ADDRSTRLEN);
            dst = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6->ip6_dst), dst, INET6_ADDRSTRLEN);
        }

        unsigned short src_port = ntohs(tcp->th_sport);

        unsigned short dst_port = ntohs(tcp->th_dport);

        unsigned int tcp_seq = ntohl(tcp->th_seq);
        unsigned int tcp_ack = ntohl(tcp->th_ack);

        bool payload_updated = false;

        tcp_node* walker = tcp_head;

        while(walker != NULL){
            if(strcmp(walker->ip_src, src)==0 && walker->ip_src_port == src_port
                && strcmp(walker->ip_dst, dst)==0 && walker->ip_dst_port == dst_port) {
                add_packet_node(&walker->_req, payload, size_payload, tcp_seq);
                payload_updated = true;
                break;
            }

            if(strcmp(walker->ip_src, dst)==0 && walker->ip_src_port == dst_port 
                && strcmp(walker->ip_dst, src)==0 && walker->ip_dst_port == src_port) {
                if(walker->_res == NULL) {
                    walker->_res = create_packet_node(payload, size_payload, tcp_seq);
                } else {
                    add_packet_node(&walker->_res, payload, size_payload, tcp_seq);
                }
                payload_updated = true;
                break;              
            }

            if(walker->_next == NULL) {
                break;
            }

            walker = walker->_next;
        }

        if(!payload_updated) {
            tcp_node *n = malloc(sizeof(tcp_node));
            n->ip_src = src;
            n->ip_src_port = src_port;
            n->ip_dst = dst;
            n->ip_dst_port = dst_port;

            n->_req = create_packet_node(payload, size_payload, tcp_seq); 
            n->_res = NULL;

            n->_next = NULL;

            if(walker != NULL) {
                walker->_next = n;
            }

            if(tcp_head == NULL) {
                tcp_head = n;
            }
        } else {
            free(src);
            free(dst);
        }

    }

    return;
}

void
assemble(packet_node *head, char **payload, int *payload_size, int *retransmitted, int *out_of_order)
{
    packet_node *walker = head;
    int prev_size = 0;

    while(walker != NULL) {
        *payload_size = walker->packet_size + *payload_size;
        *retransmitted = walker->_retransmitted + *retransmitted;
        *out_of_order = walker->_out_of_order + *out_of_order;
        *payload = realloc(*payload, *payload_size);
        memcpy(&(*payload)[prev_size], walker->packet, walker->packet_size);
        prev_size = *payload_size;
        packet_node *tmp = walker;
        walker = walker->_next;
        free(tmp->packet);
        free(tmp);
    }
}

void
Execute(napi_env env, void* data)
{
    // io thread
    carrier* c = (carrier *)(data);

    if (c != &the_carrier) {
        napi_throw_type_error(env, nullptr, "Wrong data parameter to Execute.");
        return;
    }

    int res; 

    while(true) {
        res = pcap_dispatch(c->_handle, c->_packet_cnt, got_packet, NULL);

        if(res == -1) {
            printf("\nerror reading packets: %s\n", pcap_geterr(c->_handle));
        }

        if(res < 0 || (res > 0 && c->_offline == 1)) break;
    }

    // after addon.stop() we're here
    pcap_close(c->_handle);
    pcap_freecode(&c->_fp);

    c->_output = tcp_head;

    return;
}

void
Complete(napi_env env, napi_status status, void* data)
{
    // main thread
    carrier* c = (carrier *)(data);

    if (c != &the_carrier) {
        napi_throw_type_error(env, nullptr, "Wrong data parameter to Complete.");
        return;
    }

    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "Execute callback failed.");
        return;
    }

    napi_value callback;
    napi_get_reference_value(env, c->_callback, &callback);
    napi_value global;
    napi_get_global(env, &global);

    napi_value result;
    tcp_node* walker = c->_output;
    while (walker != NULL) {
        if(walker->_req == NULL && walker->_res == NULL) {
            printf("\nerror parsing http request/response\n");
            continue;
        }

        char *req_payload = NULL;
        int req_payload_size = 0;
        int req_retransmitted = 0;
        int req_out_of_order = 0;

        if(walker->_req != NULL) {
            assemble(walker->_req, &req_payload, &req_payload_size, &req_retransmitted, &req_out_of_order);
        }

        char *res_payload = NULL;
        int res_payload_size = 0;
        int res_retransmitted = 0;
        int res_out_of_order = 0;

        if(walker->_res != NULL) {
            assemble(walker->_res, &res_payload, &res_payload_size, &res_retransmitted, &res_out_of_order);
        }

        int argc = 2;

        napi_value argv[argc];
        napi_get_null(env, &argv[0]);

        napi_value rv[2];
        napi_create_object(env, &argv[1]);
            napi_value req[3];
            napi_create_object(env, &rv[0]);
            napi_set_named_property(env, argv[1], "req", rv[0]);
                napi_create_buffer_copy(env, req_payload_size, req_payload, NULL, &req[0]);
                napi_set_named_property(env, rv[0], "payload", req[0]);
                napi_create_int32(env, req_retransmitted, &req[1]);
                napi_set_named_property(env, rv[0], "dup", req[1]);
                napi_create_int32(env, req_out_of_order, &req[2]);
                napi_set_named_property(env, rv[0], "ooo", req[2]);              
            napi_value res[3];
            napi_create_object(env, &rv[1]);
            napi_set_named_property(env, argv[1], "res", rv[1]);
                napi_create_buffer_copy(env, res_payload_size, res_payload, NULL, &res[0]);
                napi_set_named_property(env, rv[1], "payload", res[0]);
                napi_create_int32(env, res_retransmitted, &res[1]);
                napi_set_named_property(env, rv[1], "dup", res[1]);
                napi_create_int32(env, res_out_of_order, &res[2]);
                napi_set_named_property(env, rv[1], "ooo", res[2]);    
        napi_call_function(env, global, callback, argc, argv, &result);

        tcp_node *tmp = walker;
        walker = walker->_next;
        free(tmp->ip_src);
        free(tmp->ip_dst);
        free(tmp);

        free(req_payload);
        free(res_payload);
    }

    napi_delete_reference(env, c->_callback);
    napi_delete_async_work(env, c->_work);
}

#define EXIT_FAILURE 1

pcap_t*
get_handle(char* device, char* pcap_file, char* filter_exp, struct bpf_program fp)
{
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(device == NULL) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        dev = device;
    }

    printf("listening on %s\n", dev);

    if(pcap_file != NULL) {
        printf("\nreading file: %s\n", pcap_file);
        if (!(handle = pcap_open_offline(pcap_file, errbuf))) {
            fprintf(stderr, "Couldn't open file, %s, for reading: %s\n", pcap_file, errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        handle = pcap_create(dev, errbuf);

        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }

        pcap_set_promisc(handle, 0);
        pcap_set_snaplen(handle, 65535);
        pcap_set_timeout(handle, 1000);
        pcap_activate(handle);

        if (pcap_setnonblock(handle, 1, errbuf) == -1) {
            fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    } 

    return handle;
}

char*
get_config(napi_value env, napi_value *argv, char *prop_name)
{
    napi_value field_name;
    napi_create_string_utf8(env, prop_name, NAPI_AUTO_LENGTH, &field_name);

    napi_value output;
    napi_get_property(env, argv[0], field_name, &output);

    napi_valuetype t;
    napi_typeof(env, output, &t);
    if(t == napi_string) {
        size_t prop_size = 0;
        napi_get_value_string_utf8(env, output, NULL, 0, &prop_size);

        if(prop_size > 0) {
            char *prop = malloc(prop_size+1);

            napi_get_value_string_utf8(env, output, prop, prop_size+1, &prop_size);

            return prop;
        }
    }
    return NULL;
}

void
queue_work(napi_value env, napi_value *argv)
{
    napi_value resource_name;
    napi_create_reference(env, argv[1], 1, &the_carrier._callback);
    napi_create_string_utf8(env, "TestResource", NAPI_AUTO_LENGTH, &resource_name);
    napi_create_async_work(env, argv[0], resource_name, Execute, Complete, &the_carrier, &the_carrier._work);
    napi_queue_async_work(env, the_carrier._work);
}

napi_value
Start(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2];
    napi_value _this;
    void* data;
    napi_get_cb_info(env, info, &argc, argv, &_this, &data);

    napi_valuetype t;
    napi_typeof(env, argv[0], &t);
    napi_typeof(env, argv[1], &t);

    char *device = get_config(env, argv, "device");
    char *pcap_file = get_config(env, argv, "pcap_file");
    char *packet_cnt = get_config(env, argv, "packet_cnt");
    char *pcap_filter = get_config(env, argv, "pcap_filter");
    the_carrier._offline = pcap_file != NULL ? 1 : 0;
    the_carrier._handle = get_handle(device, pcap_file, pcap_filter, the_carrier._fp);
    the_carrier._packet_cnt = atoi(packet_cnt);
    free(device);
    free(pcap_file);
    free(packet_cnt);
    free(pcap_filter);

    queue_work(env, argv);

    return nullptr;
}

napi_value
Stop(napi_env env, const napi_callback_info info)
{
    sleep(1); // wait for packets to arrive

    pcap_breakloop(the_carrier._handle);

    return nullptr;
}

#define DECLARE_NAPI_METHOD(name, func) { (name), 0, (func), 0, 0, 0, napi_default, 0 }

napi_value
Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
            DECLARE_NAPI_METHOD("start", Start),
            DECLARE_NAPI_METHOD("stop", Stop)
    };

    napi_define_properties(env, exports, 2, properties);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
