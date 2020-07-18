/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

/**
* IMPLEMENT THIS METHOD
*
* This method is called each time the router receives a packet on
* the interface.  The packet buffer \p packet and the receiving
* interface \p inIface are passed in as parameters. The packet is
* complete with ethernet headers.
*/
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

//pseudocode is on the slide ipintro2018
static const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
void
SimpleRouter::prepare_send_arp_response(const Interface* iface, ethernet_hdr* ehdr, arp_hdr* ahdr){
    if (ahdr->arp_tip != iface->ip) {
      std::cerr << "ARP request packet looking for other node, discarding" << std::endl;
      return;
    }
    std::cerr << "Start APR Response" << std::endl;
    Buffer resPack(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    ethernet_hdr* ethHdr = (ethernet_hdr *) (uint8_t*) resPack.data();
    arp_hdr* arpHdr = (arp_hdr *)((uint8_t *) resPack.data() + sizeof(ethernet_hdr));
    //set ethHdr
    memcpy(ethHdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    ethHdr->ether_type = htons(ethertype_arp);
    //set arpHdr
    arpHdr->arp_hrd = htons(arp_hrd_ethernet);
    arpHdr->arp_pro = htons(ethertype_ip);
    arpHdr->arp_hln = ETHER_ADDR_LEN;
    arpHdr->arp_pln = 4;
    arpHdr->arp_op = htons(arp_op_reply);
    
    memcpy(arpHdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
    arpHdr->arp_sip = iface->ip;
    memcpy(arpHdr->arp_tha, ahdr->arp_sha, ETHER_ADDR_LEN);
    arpHdr->arp_tip = ahdr->arp_sip;

    
    //send arp response
    sendPacket(resPack, iface->name);
    std::cerr << "Print ARP Response Packet headers" << std::endl;
    print_hdrs(resPack);
    std::cerr << "End APR Response" << std::endl;
}
/*
 The ARP reply processing code should move entries from the ARP request
 queue to the ARP cache:
 # When servicing an arp reply that gives us an IP->MAC mapping
 req = cache.insertArpEntry(ip, mac)
 if req != nullptr:
     send all packets on the req->packets linked list
     cache.removeRequest(req)

*/

void
SimpleRouter::sendEnqPack(arp_hdr* ahdr, const Interface* iface){
    if (ahdr->arp_tip != iface->ip) {
      std::cerr << "ARP request packet looking for other node, discarding" << std::endl;
      return;
    }
    Buffer mac(ETHER_ADDR_LEN);
    memcpy(mac.data(), ahdr->arp_sha, ETHER_ADDR_LEN);
    std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac, ahdr->arp_sip);
    
    if (req == nullptr) {
      std::cerr << "ARP entry was not inserted correctly, no ARP request returned" << std::endl;
      return;
    }
    for (std::list<PendingPacket>::iterator it = req->packets.begin(); it != req->packets.end(); it++){
        std::cerr << "Start IP-MAC mapping" << std::endl;
        // Create packet
        Buffer sendPack(it->packet);
        ethernet_hdr* ethHdr = (ethernet_hdr*) (uint8_t*)sendPack.data();
        //ip_hdr* ipHdr = (ip_hdr*)((uint8_t*)sendPack.data() + sizeof(ethernet_hdr));
        std::string oface(it->iface);
        //set ethHdr
        memcpy(ethHdr->ether_dhost, ahdr->arp_sha, ETHER_ADDR_LEN);
        memcpy(ethHdr->ether_shost, ahdr->arp_tha, ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_ip);
        //set ipHdr
        //ipHdr->ip_ttl -= 1;
        //ipHdr->ip_sum = 0;
        //ipHdr->ip_sum = cksum((const void*)ipHdr, sizeof(ip_hdr));
        // Forward IP Packet
        sendPacket(sendPack, oface);
        std::cerr << "Print IP Forwarding Packets" << std::endl;
        print_hdrs(sendPack);
        std::cerr << "End IP-MAC mapping" << std::endl;
        
    }
    m_arp.removeRequest(req);
}

void
SimpleRouter::forwardPacket(const Buffer& packet,ip_hdr* ipH){
    
    //Find out which entry in the routing table has the longest prefix
    //match with the destination IO address
    RoutingTableEntry nextHop = m_routingTable.lookup(ipH->ip_dst);
    
    //decrement ttl by 1, and recompute the packet checksum over the modified header
    ipH->ip_ttl -=1;
    ipH->ip_sum = 0;
    ipH->ip_sum = cksum((const void*)ipH, sizeof(ip_hdr));
    
    //check the ARP cache for the next-hop MAC address corresponding
    //to the next-hop IP. If it's there, send it.
    //Otherwise, send an ARP request for the next-hop IP(if one hasn't
    //been seen within the last second), and add the packet to the queue
    //of packets waiting on this ARP request.
    std::shared_ptr<ArpEntry> aEntry = m_arp.lookup(nextHop.gw);
    if(aEntry != nullptr){
        std::cerr << "Start forward IP packet which is the arp cache" << std::endl;
        // Create packet
        Buffer sendPack(packet.size());
        memcpy(sendPack.data(), packet.data(), packet.size());
        ethernet_hdr* ethHdr = (ethernet_hdr*) (uint8_t*)sendPack.data();
        ip_hdr* ipHdr = (ip_hdr*) ((uint8_t*)sendPack.data() + sizeof(ethernet_hdr));
        //set ethHdr
        const Interface* iface = findIfaceByName(nextHop.ifName);
        memcpy(ethHdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(ethHdr->ether_dhost, aEntry->mac.data(), ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_ip);
        //set ipHdr
        ipHdr->ip_ttl = ipH->ip_ttl;
        ipHdr->ip_sum = ipH->ip_sum;
        
        //forward packet
        sendPacket(sendPack, iface->name);
        std::cerr << "Print IP Forwarding Packet" << std::endl;
        print_hdrs(sendPack);
        std::cerr << "End IP Forwarding Packet in arp cache" << std::endl;
    }
    else{
        std::cerr << "START ip packet not in cache" << std::endl;
        // Queue the received packet
        Buffer queuePack(packet.size());
        memcpy(queuePack.data(), packet.data(), packet.size());
        ip_hdr* ipHdr = (ip_hdr*)((uint8_t*)queuePack.data() + sizeof(ethernet_hdr));
        // Decrement TTL
        ipHdr->ip_ttl =ipH->ip_ttl;
        ipHdr->ip_sum = ipH->ip_sum;
        
        std::shared_ptr<ArpRequest> arpReq = m_arp.queueRequest(nextHop.gw, queuePack, nextHop.ifName);
        // Update info about this req
        auto now = steady_clock::now();
        arpReq->timeSent = now;
        arpReq->nTimesSent += 1;
        
        // Send ARP request to discover the IP-MAC mapping
        // Create packet
        Buffer reqPack(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        ethernet_hdr* ethHdr = (ethernet_hdr*) (uint8_t*)reqPack.data();
        arp_hdr* arpHdr = (arp_hdr*)((uint8_t*)reqPack.data() + sizeof(ethernet_hdr));
        // set ethHdr
        const Interface* iface = findIfaceByName(nextHop.ifName);
        memcpy(ethHdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(ethHdr->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_arp);
        //set arpHdr
        arpHdr->arp_hrd = htons(arp_hrd_ethernet);
        arpHdr->arp_pro = htons(ethertype_ip);
        arpHdr->arp_hln = ETHER_ADDR_LEN;
        arpHdr->arp_pln = 4;
        arpHdr->arp_op = htons(arp_op_request);
        memcpy(arpHdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        arpHdr->arp_sip = iface->ip;
        memcpy(arpHdr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
        arpHdr->arp_tip = ipHdr->ip_dst;
        
        // Send ARP Request Packet
        sendPacket(reqPack, iface->name);
        std::cerr << "Print ARP Request Packet(ip not on the cache)" << std::endl;
        print_hdrs(reqPack);
        std::cerr << "End ip not in cache" << std::endl;
    }
    
}
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
    
    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }
    
    std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN
    //check packet size
    if(packet.size() < sizeof(ethernet_hdr)){
        std::cerr << "Received packet: invalid size, ignoring" << std::endl;
        return;
    }
    
    std::cerr<<"*********The receiving packet is **********" <<std::endl;
    print_hdrs(packet);
    std::cerr<<"********************************************" <<std::endl;

    
    
    //
    ethernet_hdr* ehdr = (ethernet_hdr*) ((uint8_t*)packet.data());
    uint16_t etherType = ntohs(ehdr->ether_type);
    if(etherType == ethertype_arp){
        //check arp packet size
        if(packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)){
            std::cerr << "Received ARP packet: invalid size, ignoring" << std::endl;
            return;
        }
        arp_hdr* ahdr = (arp_hdr*) ((uint8_t *)packet.data() + sizeof(ethernet_hdr));
        unsigned short arpOp = ntohs(ahdr->arp_op);
        
        switch(arpOp){
            case arp_op_request:
                std::cerr << "Receiving packet is a Arp request" << std::endl;
                //Prepare and send ARP response packet
                prepare_send_arp_response(iface, ehdr, ahdr);
                break;
            case arp_op_reply:
                std::cerr << "Receiving packet is a Arp response" << std::endl;
                //record IP-MAC mapping information in ARP cache
                //send out all enqueued packets for ARP entry
                sendEnqPack(ahdr, iface);
                break;
        }
    }
    else if (etherType == ethertype_ip){
        //verify checksum, length, discard invalid packets
        std::cerr << "Receiving packet is ipv4" << std::endl;
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)){
             std::cerr << "Receiving ipv4 packet: invalid size, ignoring" << std::endl;
             return;
        }
        //Extract ip header
        ip_hdr* ipH = (ip_hdr*) ((uint8_t*)packet.data() + sizeof(ethernet_hdr));
        //verify checksum and min length and discard all invalids
        uint16_t check = ipH->ip_sum;
        ipH->ip_sum = 0;
        ipH->ip_sum = cksum((const void*) ipH, sizeof(ip_hdr));
        if(check != ipH->ip_sum) {
          std::cerr << "Invalid checksum." << std::endl;
          return;
        }
        // Check the min packet length
        if (ipH->ip_len < 21) {
            std::cerr << "Packet length too short, ignoring" << std::endl;
            return;
        }
        //if packet is to router
        //if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded.
        const Interface* ipDest = findIfaceByIp(ipH->ip_dst);
        if (ipDest!= nullptr){
            if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)){
                std::cerr << "The ipv4 Packet to the router not contain the icmp payload, discard" << std::endl;
                return;
            }
            icmp_hdr* icmpH = (icmp_hdr*) ((uint8_t*)packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
            if (icmpH->icmp_type == 8){
                std::cerr << "Sending icmp Echo Reply" << std::endl;
                //Echo Request to one of our interface
                Buffer pack(packet.size());
                memcpy(pack.data(), packet.data(), packet.size());
                ethernet_hdr* ethHdr = (ethernet_hdr*) ((uint8_t*)packet.data());
                //ip_hdr* iphdr = (ip_hdr*) ((uint8_t*)packet.data() + sizeof(ethernet_hdr));
                //icmp_hdr* icmphdr = (icmp_hdr*) ((uint8_t*)pack.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
                struct icmp_hdr icmphdr;
                memcpy(&icmphdr, packet.data()+sizeof(ethernet_hdr)+sizeof(ip_hdr), sizeof(icmp_hdr));
                
                //set icmphdr
                icmphdr.icmp_type = 0;
                icmphdr.icmp_code = 0;
                icmphdr.icmp_sum = 0;
                icmphdr.icmp_sum = cksum((const void *)&icmphdr, packet.size()-(sizeof(ethernet_hdr))-(sizeof(ip_hdr)));
                
                //set iphdr
                /*
                iphdr->ip_hl = ipH->ip_hl;
                iphdr->ip_v = ipH->ip_v;
                iphdr->ip_tos = ipH->ip_tos;
                iphdr->ip_len = ipH->ip_len;
                iphdr->ip_id = ipH->ip_id;
                iphdr->ip_off = ipH->ip_off;
                iphdr->ip_ttl = ipH->ip_ttl;
                iphdr->ip_p = ipH->ip_p;
                */
                //iphdr->ip_dst = ipH->ip_src;
                //iphdr->ip_src = ipH->ip_dst;
                //iphdr->ip_sum = 0;
                //iphdr->ip_sum = cksum((const void *)iphdr, sizeof(ip_hdr));
                ipH->ip_len = htons(packet.size()-(sizeof(ethernet_hdr)));
                ipH->ip_ttl = 64;
                ipH->ip_p = 1;
                uint32_t tmp = ipH->ip_dst;
                ipH->ip_dst = ipH->ip_src;
                ipH->ip_src = tmp;
                ipH->ip_sum = 0;
                ipH->ip_sum = cksum((const void *)ipH, sizeof(ip_hdr));
                
                //set ethHdr
                memcpy(ethHdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(ethHdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
                ethHdr->ether_type = ehdr->ether_type;
                
                memcpy(pack.data(), ethHdr, sizeof(ethernet_hdr));
                memcpy(pack.data()+sizeof(ethernet_hdr), ipH, sizeof(ip_hdr));
                memcpy(pack.data()+sizeof(ethernet_hdr)+sizeof(ip_hdr), &icmphdr, sizeof(icmp_hdr));
                
                
                
                /*
                sendPacket(pack, iface->name);
                std::cerr << "Print Echo Reply packet" << std::endl;
                print_hdrs(pack);
                std::cerr << "End ICMP Echo Reply" << std::endl;
                */
                std::cerr << "!!!!!!!!!!!!!Echo Reply packet!!!!!!" << std::endl;
                print_hdrs(pack);
                std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;

                
                RoutingTableEntry nextHop = m_routingTable.lookup(ipH->ip_dst);
                std::shared_ptr<ArpEntry> ptr = m_arp.lookup(nextHop.gw);
                
                
                if (ptr == nullptr) {
                    std::cerr << "arp entry not found,try request" << std::endl;
                    m_arp.queueRequest(ipH->ip_dst, pack, iface->name);
                }
                else{
                    sendPacket(pack, iface->name);
                    std::cerr << "Print Echo Reply packet" << std::endl;
                    print_hdrs(pack);
                    std::cerr << "End ICMP Echo Reply" << std::endl;
                }
                
            }
            else{
                std::cerr << "The icmp type is not 8, discard" << std::endl;
                //forwardPacket(packet, ipH);
                return;
            }
        }
        else{
            forwardPacket(packet, ipH);
        }
    }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
