/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

/*
  This file defines an ARP cache with ARP request queue and ARP cache entries
  The ARP cache entries hold IP->MAC mappings and are timed out every SR_ARPCACHE_TO seconds.
   --
   The handle_arpreq() function is a function you should write, and it should
   handle sending ARP requests if necessary:
   function handle_arpreq(req):
       if now - req->timeSent > seconds(1)
           if req->nTimesSent >= 5:
               cache.removeRequest(req)
           else:
               send arp request
               req->timeSent = now
               req->nTimesSent++
   --
 The ARP reply processing code should move entries from the ARP request
 queue to the ARP cache:
 # When servicing an arp reply that gives us an IP->MAC mapping
 req = cache.insertArpEntry(ip, mac)
   if req != nullptr:
       send all packets on the req->packets linked list
       cache.removeRequest(req)
   --
   To meet the guidelines in the assignment (ARP requests are sent every second
   until we send 5 ARP requests, then remove the corresponding arp request),
   you must fill out the following
   function that is called every second and is defined in sr_arpcache.c:
   void
   ArpCache::periodicCheckArpRequestsAndCacheEntries() {
       for each request on m_arpRequests:
           handle_arpreq(request)
   }
*/
/**
* IMPLEMENT THIS METHOD
*
* This method gets called every second. For each request sent out,
* you should keep checking whether to resend a request or remove it.
*
* Your implementation should follow the following logic
*
*     for each request in queued requests:
*         handleRequest(request)
*
*     for each cache entry in entries:
*         if not entry->isValid
*             record entry for removal
*     remove all entries marked for removal
*/
static const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
    auto now = steady_clock::now();
	for (std::list<std::shared_ptr<ArpRequest>>::const_iterator req = m_arpRequests.begin(); req != m_arpRequests.end(); ) {
        //If your router didn’t receive ARP reply after re-transmitting an ARP request 5 times,
        //it should stop re-transmitting, remove the pending request,
        //and any packets that are queued for the transmission that are associated with the request.
        if ((*req)->nTimesSent >= MAX_SENT_TIME) {
            std::list<std::shared_ptr<ArpRequest>>::const_iterator temp = req;
            temp++;
            removeRequest(*req);
            req = temp;
            std::cerr << "arpReq exceed 5" << std::endl;
        }
        //The router should send an ARP request about once a second
        //until an ARP reply comes back or the request has been sent out at least 5 times.
        else{
            //send arp request
            //create packet
            Buffer packetBuffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
            ethernet_hdr* ethHdr = (ethernet_hdr *) ((uint8_t *) packetBuffer.data());
            arp_hdr* arpHdr = (arp_hdr *)((uint8_t *) packetBuffer.data() + sizeof(ethernet_hdr));
            //set ethHdr
            std::string outIface = (*req)->packets.front().iface;
            const Interface *iface = m_router.findIfaceByName(outIface);
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
            memcpy(arpHdr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);

            arpHdr->arp_sip = iface->ip;
            arpHdr->arp_tip = (*req)->ip;
            //send arp request
            std::cerr << "Sending arp request" << std::endl;
            m_router.sendPacket(packetBuffer, outIface);
            print_hdrs(packetBuffer);
            std::cerr << "End sending arp request" << std::endl;
            
            //Update informaton
            (*req)->timeSent = now;
            (*req)->nTimesSent++;
            req++;
        }
	}
    for(std::list<std::shared_ptr<ArpEntry>>::const_iterator entry = m_cacheEntries.begin(); entry != m_cacheEntries.end(); ){
        if(!(*entry)->isValid){
            entry = m_cacheEntries.erase(entry);
        }
        else{
            entry ++;
        }
    }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
