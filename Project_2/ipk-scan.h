/*
    Structure took from https://www.cnblogs.com/rollenholt/articles/2590959.html
    Author: Rollen Holt
*/
struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

//print help
void help(void);

/*
    Source: https://stackoverflow.com/questions/4583386/listening-using-pcap-with-timeout
    Author: lemonsqueeze
    Description: break from waiting on packet
*/
void alarm_handler(int sig);

/*
    Function inspired by https://www.cnblogs.com/rollenholt/articles/2590959.html
    Author: Rollen Holt
    Description: Count checksum
*/
unsigned short csum(unsigned short *ptr, int nbytes);

/*
    Function inspired by example
    Source: http://man7.org/linux/man-pages/man3/getifaddrs.3.html
    Description: Get interface of the family with name (if not NULL)
*/
struct ifaddrs *getInterface(struct ifaddrs **ifaddr, char *name, int family);
