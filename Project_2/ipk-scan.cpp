#include <iostream>
#include <unistd.h>
#include <algorithm>
#include <vector>
#include <pcap/pcap.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <signal.h>
#include "ipk-scan.h"

#define PORT 4853
#define PCKT_LEN 8192
#define REPEAT 2 //Number of trying to send packet

using namespace std;

pcap_t *handler;

void help(void)
{
    cout << "Help:\n";
    cout << "run with -pu PORTS -pt PORTS [-i interface] [DomainName | IpAddress]\n";
    cout << "-pu is for scanning by UDP and -pt for TCP protocol";
    cout << "PORTS can be \"1,2,3...\", \"4-50\" or combination like \"1,2,4-50\"\n";
    cout << "either DomainName or IpAddress is required\n";
    cout << "at least one PORT is required\n";
}

/*
    Source: https://stackoverflow.com/questions/4583386/listening-using-pcap-with-timeout
    Author: lemonsqueeze
*/
//////////////////////////////////////////
void alarm_handler(int sig)
{
    pcap_breakloop(handler);
}
//////////////////////////////////////////

void callback(u_char *args, const struct pcap_pkthdr* header, const u_char* packet)
{
    alarm(0);
}

/*
    Function inspired by https://www.cnblogs.com/rollenholt/articles/2590959.html
    Author: Rollen Holt
*/
//////////////////////////////////////////
unsigned short csum(unsigned short *ptr, int nbytes)
{
    long sum = 0;
    unsigned short oddbyte = 0;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);

    return (unsigned short)~sum;
}
//////////////////////////////////////////

//parse numbers from arg and push them to vector
void ports(char *endptr, vector <int> *vec)
{
    char *ptr1, *ptr2;
    long port1, port2;
    ptr1 = strstr(endptr, ",");
    ptr2 = strstr(endptr, "-");
    --endptr;//it's easier to have to move by 1 everywhere
    //Combination x,y-z...
    while (ptr1 && ptr2) {
        if (ptr1 < ptr2) {
            port1 = strtol(&endptr[1], &endptr, 10);
            if (endptr != ptr1) {
                cerr << "int conversion failure1\n";
                help();
                exit(EXIT_FAILURE);
            }
            (*vec).push_back(port1);
            ptr1 = strstr(&ptr1[1], ",");
        } else {
            port1 = strtol(&endptr[1], &endptr, 10);
            if (endptr != ptr2) {
                cerr << "int conversion failure2\n";
                help();
                exit(EXIT_FAILURE);
            }
            port2 = strtol(&endptr[1], &endptr, 10);
            if (endptr != ptr1) {
                cerr << "int conversion failure3\n";
                help();
                exit(EXIT_FAILURE);
            }
            if (port1 > port2)
                swap(port1, port2);
            while (port1 <= port2) {
                (*vec).push_back(port1);
                ++port1;
            }
            ptr1 = strstr(&ptr1[1], ",");
            ptr2 = strstr(&ptr2[1], "-");
        }
    }
    //Just x-y
    if (ptr2) {
        port1 = strtol(&endptr[1], &endptr, 10);
        if (endptr != ptr2) {
            cerr << "int conversion failure4\n";
            help();
            exit(EXIT_FAILURE);
        }
        port2 = strtol(&endptr[1], &ptr1, 10);
        if (ptr1[0] != '\0' || &endptr[1] == ptr1) {
            cerr << "int conversion failure5\n";
            help();
            exit(EXIT_FAILURE);
        }
        if (port1 > port2)
            swap(port1, port2);
        while (port1 <= port2) {
            (*vec).push_back(port1);
            ++port1;
        }
        return;
    }
    //Just x,y,z...
    while (ptr1) {
        port1 = strtol(&endptr[1], &endptr, 10);
        if (endptr != ptr1) {
            cerr << "int conversion failure6\n";
            help();
            exit(EXIT_FAILURE);
        }
        (*vec).push_back(port1);
        ptr1 = strstr(&ptr1[1], ",");
    }
    //Just x
    port1 = strtol(&endptr[1], &ptr1, 10);
    if (ptr1[0] != '\0') {
        cerr << "int conversion failure7\n";
        help();
        exit(EXIT_FAILURE);
    }
    if (&endptr[1] != ptr1)
        (*vec).push_back(port1);
}

/*
    Function inspired by example
    Source: http://man7.org/linux/man-pages/man3/getifaddrs.3.html
*/
//////////////////////////////////////////
struct ifaddrs *getInterface(struct ifaddrs **ifaddr, char *name, int family) {
    if (getifaddrs(ifaddr)) {
        cerr << "getifaddrs failure\n";
        help();
        exit(EXIT_FAILURE);
    }

    struct ifaddrs *ifa = (*ifaddr);
    if (name == NULL) {
        while (ifa) {
            if ((ifa->ifa_flags & IFF_LOOPBACK) == 0) {
                if ((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)) {
                    if (ifa->ifa_addr->sa_family == family) {
                        printf("Interface:    %s\n", ifa->ifa_name);
                        printf("Interface IP: %s\n", inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                        return ifa;
                    }
                }
            }
            ifa = ifa->ifa_next;
        }
    } else {
        while (ifa) {
            if (!strcmp(ifa->ifa_name, name) && (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)) {
                if (ifa->ifa_addr->sa_family == family) {
                    printf("Interface:    %s\n", ifa->ifa_name);
                    printf("Interface IP: %s\n\n", inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                    return ifa;
                }
            }
            ifa = ifa->ifa_next;
        }
    }
    return NULL;
}
//////////////////////////////////////////

int main(int argc, char *argv[]) {
    signal(SIGALRM, alarm_handler);
    struct ifaddrs *ifaddr, *interface;
    vector <int> vecUDP, vecTCP;
    char *address = NULL, *intername = NULL;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-p")) {
            i += 2;
            if (i >= argc) {
                cerr << "-pu/-pt is last\n";
                help();
                return EXIT_FAILURE;
            }
            if (!strcmp(argv[i-1], "-u"))
                ports(argv[i], &vecUDP);
            else if (!strcmp(argv[i-1], "-t"))
                ports(argv[i], &vecTCP);
            else {
                cerr << "incorrectly -pu/-pt\n";
                help();
                return EXIT_FAILURE;
            }
        } else if (!strcmp(argv[i], "-pu")) {
            ++i;
            if (i == argc) {
                cerr << "-pu is last\n";
                help();
                return EXIT_FAILURE;
            }
            ports(argv[i], &vecUDP);
        } else if (!strcmp(argv[i], "-pt")) {
            ++i;
            if (i == argc) {
                cerr << "-pt is last\n";
                help();
                return EXIT_FAILURE;
            }
            ports(argv[i], &vecTCP);
        } else if (!strcmp(argv[i], "-i")) {
            ++i;
            if (i == argc) {
                cerr << "-i is last\n";
                help();
                return EXIT_FAILURE;
            }
            if (intername) {
                cerr << "too many interfaces\n";
                help();
                return EXIT_FAILURE;
            }
            intername = argv[i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            help();
            return EXIT_SUCCESS;
        } else {
            //domain/IP
            if (address) {
                cerr << "too many arguments\n";
                help();
                return EXIT_FAILURE;
            }
            address = argv[i];
        }
    }

    sort(vecUDP.begin(), vecUDP.end());
    sort(vecTCP.begin(), vecTCP.end());
    vecUDP.erase(unique(vecUDP.begin(), vecUDP.end()), vecUDP.end());
    vecTCP.erase(unique(vecTCP.begin(), vecTCP.end()), vecTCP.end());

    if (vecTCP.empty() && vecUDP.empty()) {
        cerr << "No ports to scan\n";
        help();
        return EXIT_FAILURE;
    }
    if (!vecTCP.empty() && (vecTCP.front() < 0 || vecTCP.back() > 65535)) {
        cerr << "Invalid TCP port\n";
        help();
        return EXIT_FAILURE;
    }
    if (!vecUDP.empty() && (vecUDP.front() < 0 || vecUDP.back() > 65535)) {
        cerr << "Invalid UDP port\n";
        help();
        return EXIT_FAILURE;
    }
    /*
        Next block inspired by Jiri Hnidek
        https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d
    */
    //////////////////////////////////////////
    struct addrinfo *result, *res;
    char addrstr[40];
    void *ptr;

    if (getaddrinfo(address, NULL, NULL, &result)) {
        cerr << "getifaddrinfo unsuccessfull.\n";
        help();
        exit(EXIT_FAILURE);
    }

    res = result;
    while (res) {
        if (res->ai_family == AF_INET) {
            inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 40);
            ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
            inet_ntop (res->ai_family, ptr, addrstr, 40);
            break;
        } else if (res->ai_family == AF_INET6) {
            inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 40);
            ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
            inet_ntop (res->ai_family, ptr, addrstr, 40);
            break;
        }
        res = res->ai_next;
    }

    if (res == NULL) {
        freeaddrinfo(result);
        cerr << "Could not connect.\n";
        help();
        exit(EXIT_FAILURE);
    }

    printf("Host:         %s\n", address);
    printf("Host IP:      %s\n", addrstr);
    //////////////////////////////////////////

    if (!(interface = getInterface(&ifaddr, intername, res->ai_family))) {
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        cerr << "No address avaiable for interface.\n";
        help();
        return EXIT_FAILURE;
    }

    char errbuff[PCAP_ERRBUF_SIZE];
    handler = pcap_create(interface->ifa_name, errbuff);
    if (!handler) {
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        cerr << errbuff;
        help();
        return EXIT_FAILURE;
    }

    if (pcap_set_rfmon(handler, pcap_can_set_rfmon(handler) == 1) || pcap_set_promisc(handler, 1)) {
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        cerr << "Could not set settings1.\n";
        help();
        return EXIT_FAILURE;
    }
    if (pcap_set_snaplen(handler, 2048) || pcap_set_timeout(handler, 1)) {
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        cerr << "Could not set settings2.\n";
        help();
        return EXIT_FAILURE;
    }

    if (pcap_activate(handler)) {
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        cerr << "Could not activate handler.\n";
        help();
        return EXIT_FAILURE;
    }

    int soTCP = socket(res->ai_family, SOCK_RAW, IPPROTO_TCP);
    int soUDP = socket(res->ai_family, SOCK_RAW, IPPROTO_UDP);
    if (soTCP < 0 || soUDP < 0) {
        pcap_close(handler);
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        cerr << "socket() error\n";
        help();
        return EXIT_FAILURE;
    }

    if (res->ai_family == AF_INET6) {
        close(soTCP);
        close(soUDP);
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        pcap_close(handler);
        cout << "IPv6 is not implemented yet.\n";
        return EXIT_SUCCESS;
    }
    /*
        Next block from https://www.binarytides.com/raw-sockets-c-code-linux/
        by Silver Moon
    */
    //////////////////////////////////////////
    int one = 1;
    if (setsockopt(soTCP, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(soTCP);
        close(soUDP);
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        pcap_close(handler);
        cerr << "setSockpot() TCP error\n";
        help();
        return EXIT_FAILURE;
    }
    if (setsockopt(soUDP, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(soTCP);
        close(soUDP);
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        pcap_close(handler);
        cerr << "setSockpot() UDP error\n";
        help();
        return EXIT_FAILURE;
    }
    //////////////////////////////////////////

    char packet[PCKT_LEN] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    struct pseudo_header psh;
    memset(&psh, 0, sizeof(psh));
    sin.sin_family = res->ai_family;
    sin.sin_port = htons(PORT);
    sin.sin_addr.s_addr = ((struct sockaddr_in *)interface->ifa_addr)->sin_addr.s_addr;

    // IP structure
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(54321);
    ip->frag_off = htons(16384);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = ((struct sockaddr_in *)interface->ifa_addr)->sin_addr.s_addr;
    ip->daddr = inet_addr(addrstr);
    ip->check = csum((unsigned short *)packet, sizeof(struct iphdr));

    // The TCP structure.
    tcp->dest = htons(PORT);
    tcp->th_off = 5;
    tcp->th_flags = TH_SYN;
    tcp->th_win = htonl(65535);
    tcp->syn = 1;
    srand(time(NULL));
    tcp->th_seq = rand();
    tcp->source = htons(PORT);

    // Pseudo header structure
    psh.source_address = ((struct sockaddr_in *)interface->ifa_addr)->sin_addr.s_addr;
    psh.dest_address = inet_addr(addrstr);
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    struct bpf_program pgm;
    if (pcap_compile(handler, &pgm, "dst port 4853", 1, PCAP_NETMASK_UNKNOWN)) {
        pcap_close(handler);
        close(soTCP);
        close(soUDP);
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        pcap_perror(handler, "Compile");
        help();
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handler, &pgm)) {
        pcap_close(handler);
        close(soTCP);
        close(soUDP);
        freeaddrinfo(result);
        freeifaddrs(ifaddr);
        pcap_geterr(handler);
        help();
        return EXIT_FAILURE;
    }

    for (auto port : vecTCP) {
        tcp->dest = htons(port);
        tcp->check = 0;
        memcpy(&psh.tcp, tcp, sizeof(struct tcphdr));
        tcp->th_sum = csum((unsigned short  *)&psh, sizeof(struct  pseudo_header));

        if (sendto(soTCP, packet, ip->tot_len, 0, (struct sockaddr  *)&sin, sizeof(sin)) < 0) {
            pcap_freecode(&pgm);
            pcap_close(handler);
            close(soTCP);
            close(soUDP);
            freeaddrinfo(result);
            freeifaddrs(ifaddr);
            perror("Error on sendto()");
            help();
            return(EXIT_FAILURE);
        }

        for (int i = 0; i <= REPEAT; ++i) {
            alarm(1);
            if (pcap_loop(handler, 0, callback, NULL) != PCAP_ERROR_BREAK) {
                cout << port << "/TCP TODO open vs closed\n";
                break;
            } else if (i == REPEAT) {
                cout << port << "/TCP filtered\n";
            }
        }
    }

    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct udphdr));
    memset(udp, 0, sizeof(*udp));
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip->protocol = IPPROTO_UDP;
    ip->check = csum((unsigned short *)packet, sizeof(struct iphdr));
    udp->source = htons(PORT);
    udp->len = htons(sizeof(struct udphdr));

    for (auto port : vecUDP) {
        udp->dest = htons(port);
        udp->check = 0;

        if (sendto(soUDP, packet, ip->tot_len, 0, (struct sockaddr  *)&sin, sizeof(sin)) < 0) {
            pcap_freecode(&pgm);
            pcap_close(handler);
            close(soTCP);
            close(soUDP);
            freeaddrinfo(result);
            freeifaddrs(ifaddr);
            perror("Error on sendto()");
            help();
            return(EXIT_FAILURE);
        }

        for (int i = 0; i <= REPEAT; ++i) {
            alarm(1);
            if (pcap_loop(handler, 0, callback, NULL) != PCAP_ERROR_BREAK) {
                cout << port << "/UDP TODO open vs closed vs filtered\n";
                break;
            } else if (i == REPEAT){
                cout << port << "/UDP open|filtered\n";
            }
        }
    }

    //Free the resources
    pcap_freecode(&pgm);
    pcap_close(handler);
    close(soTCP);
    close(soUDP);
    freeaddrinfo(result);
    freeifaddrs(ifaddr);

    return EXIT_SUCCESS;
}
