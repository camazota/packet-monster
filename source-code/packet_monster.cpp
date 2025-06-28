#define WIN32_LEAN_AND_MEAN
#include "tools/windivert.h"
#include <winsock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include <unordered_map>
#pragma comment(lib, "tools/WinDivert.lib")
#pragma comment(lib, "ws2_32.lib")


std::string guessProtoc(UINT8 protoc,unsigned short src_port){
    static const std::unordered_map<unsigned short,std::string> tcpPortMap= {
        {80,"HTTP"},
        {443,"HTTPS"},
        {22,"SSH"},
        {25,"SMTP"},
        {110,"POP3"},
        {7,"ECHO"},
        {21,"FTP"},
        {23,"Telnet"},
        {43,"Whois"},
        {53,"DNS"}
    };



    static const std::unordered_map<unsigned short,std::string> udpPortMap= {
        {80,"HTTP"},
        {443,"HTTPS"},
        {53,"DNS"},
        {67,"DHCP"},
        {68,"DHCP"}

    };


    if(protoc==6){
        if(tcpPortMap.count(src_port)){
            return tcpPortMap.at(src_port);
        } else return "TCP";
    } else if(protoc==17){
        if(udpPortMap.count(src_port)){
            return udpPortMap.at(src_port);
        } else return "UDP";
    }

    return "UNKNOWN";

}




int main()
{
    const char *filter = "(ip or ipv6) and (tcp or udp) and inbound";

    HANDLE handle = WinDivertOpen(filter,(WINDIVERT_LAYER)0,0,0);

    if(handle==INVALID_HANDLE_VALUE){
        std::cerr << "WinDivertOpen failed\n";
        return -1;
    }
    unsigned char packet[0xFFFF];
    UINT packetlen = sizeof(packet);
    UINT recvLen;
    WINDIVERT_ADDRESS addr;


    while(true){
        if(!WinDivertRecv(handle,packet,packetlen,&recvLen,&addr)){
            std::cerr << "WinDivertRecv failed\n";
            continue;
        }


        struct ip{
            PWINDIVERT_IPHDR iphdr;
            PWINDIVERT_IPV6HDR ipv6hdr;
            UINT8 protoc;
            PWINDIVERT_TCPHDR tcphdr;
            PWINDIVERT_UDPHDR udphdr;
        }packet_info;



        char src_addr[INET6_ADDRSTRLEN];
        char dst_addr[INET6_ADDRSTRLEN];


        unsigned short src_port;
        unsigned short dst_port;

        if(!WinDivertHelperParsePacket(packet,recvLen,&packet_info.iphdr,&packet_info.ipv6hdr,&packet_info.protoc,nullptr,nullptr,&packet_info.tcphdr,&packet_info.udphdr,nullptr,nullptr,nullptr,nullptr)){
            std::cerr << "WinDivertHelperParsePacket failed\n";
        } else {
            if(packet_info.iphdr){
                inet_ntop(AF_INET,&packet_info.iphdr->SrcAddr,src_addr,sizeof(src_addr));
                inet_ntop(AF_INET,&packet_info.iphdr->DstAddr,dst_addr,sizeof(src_addr));
            }
            else if(packet_info.ipv6hdr){
                inet_ntop(AF_INET,&packet_info.ipv6hdr->SrcAddr,src_addr,sizeof(src_addr));
                inet_ntop(AF_INET,&packet_info.ipv6hdr->DstAddr,dst_addr,sizeof(src_addr));
            } 

            if(packet_info.tcphdr){
                src_port = ntohs(packet_info.tcphdr->SrcPort);
                dst_port = ntohs(packet_info.tcphdr->DstPort);
            }else if(packet_info.udphdr){
                src_port = ntohs(packet_info.udphdr->SrcPort);
                dst_port = ntohs(packet_info.udphdr->DstPort);
            }


            std::cout << src_addr << ":" << src_port << " -> " << dst_addr << ":" << dst_port << "  protoc:" << guessProtoc(packet_info.protoc,src_port) << std::endl;
        }



        if(!WinDivertSend(handle,packet,packetlen,&recvLen,&addr)){
            std::cerr << "WinDivertSend failed\n";
            return -1;
        }
    }

    WinDivertClose(handle);
    return 0;
}