#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <PayloadLayer.h>
#include <sstream>
#include <EthLayer.h>

int main(int argc, char* argv[]){
    unsigned int packet_count = 1;

    // pcap file open
    pcpp::PcapFileReaderDevice reader("sample.pcap");
    if(!reader.open()){
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // read first packet from pcap file
    pcpp::RawPacket rawPacket;
    if(!reader.getNextPacket(rawPacket)){
        std::cerr << "Can't read the first packet in the pcap file" << std::endl;
        return 1;
    }

    while(reader.getNextPacket(rawPacket)){
        pcpp::Packet parsedPacket(&rawPacket);
        std::cout << "----- #" << packet_count <<" Packet -----" << std::endl << std::endl;
        // ethernet header info
        pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        if(ethernetLayer == nullptr)
            continue;
        
        std::cout << "Ethernet Header: "<< std::endl;
        std::cout << "- SRC MAC: " << ethernetLayer->getSourceMac().toString() <<std::endl;
        std::cout << "- DST MAC: " << ethernetLayer->getDestMac().toString() << std::endl << std::endl;

        // ip header info
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if(ipLayer == nullptr)
            continue;
        
        std::cout << "IP Header: " << std::endl;
        std::cout << "- SRC IP: " << ipLayer->getSrcIPAddress().toString() << std::endl;
        std::cout << "- DST IP: " << ipLayer->getDstIPAddress().toString() << std::endl << std::endl;

        // tcp header
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if(tcpLayer == nullptr)
            continue;

        std::cout << "TCP Header: " << std::endl;
        std::cout << "- SRC Port: " << tcpLayer->getSrcPort() << std::endl;
        std::cout << "- DST Port: " << tcpLayer->getDstPort() << std::endl <<std::endl;

        // tcp payload message
        std::string payload(reinterpret_cast<const char*>(tcpLayer->getLayerPayload()), tcpLayer->getLayerPayloadSize());
        if (!payload.empty()) {
            std::string message = payload.substr(0, std::min<size_t>(payload.length(), 1000));
            std::cout << "Message: " << message << std::endl << std::endl;
        }
        packet_count ++;
    
    }

    reader.close();
    return 0;
}