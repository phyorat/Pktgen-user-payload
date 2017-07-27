/*-
 * Copyright (c) <2010-2016>, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Copyright (c) <2010-2014>, Wind River Systems, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3) Neither the name of Wind River Systems nor the names of its contributors may be
 * used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * 4) The screens displayed by the application must contain the copyright notice as defined
 * above and can not be removed without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Created 2010 by Keith Wiles @ intel.com */

#include <stdint.h>
#include <time.h>

#include "pktgen.h"
#include "pktgen-gre.h"
#include "pktgen-tcp.h"
#include "pktgen-ipv4.h"
#include "pktgen-ipv6.h"
#include "pktgen-udp.h"
#include "pktgen-arp.h"
#include "pktgen-vlan.h"
#include "pktgen-cpu.h"
#include "pktgen-display.h"
#include "pktgen-random.h"
#include "pktgen-log.h"
#include "pktgen-gtpu.h"

#ifdef PKTGEN_PFRING_FORWARD
#include "daq.h"
#endif

#define LOAD_RANDOM_PL_SIZE 1024

/* Allocated the pktgen structure for global use */
pktgen_t pktgen;

//session control
uint32_t c_session = 0;

#ifdef PKTGEN_PFRING_FORWARD
const DAQ_Module_t* daq_mod = NULL;
DAQ_Mode daq_mode = DAQ_MODE_PASSIVE;
void* daq_hand = NULL;
int daq_dlt = -1;
struct rte_mempool_objhdr *pktgen_daq_mp_hdr = NULL;

int pktgen_pfloop_daq_Init(uint8_t lid);
int pkt_gen_daq_WasStarted (void);
int pkt_gen_daq_stop (void);
#endif

/**************************************************************************//**
 *
 * pktgen_wire_size - Calculate the wire size of the data to be sent.
 *
 * DESCRIPTION
 * Calculate the number of bytes/bits in a burst of traffic.
 *
 * RETURNS: Number of bits in burst of packets.
 *
 * SEE ALSO:
 */

uint64_t
pktgen_wire_size(port_info_t *info)
{
	uint64_t i, size = 0;

	if (rte_atomic32_read(&info->port_flags) & SEND_PCAP_PKTS)
		size = info->pcap->pkt_size + PKT_PREAMBLE_SIZE +
		        INTER_FRAME_GAP + FCS_SIZE;
	else {
		if (unlikely(info->seqCnt > 0)) {
			for (i = 0; i < info->seqCnt; i++)
				size += info->seq_pkt[i].pktSize +
				        PKT_PREAMBLE_SIZE + INTER_FRAME_GAP +
				        FCS_SIZE;
			size = size / info->seqCnt;	/* Calculate the average sized packet */
		} else
			size = info->seq_pkt[SINGLE_PKT].pktSize +
			        PKT_PREAMBLE_SIZE + INTER_FRAME_GAP + FCS_SIZE;
	}
	return size;
}

/**************************************************************************//**
 *
 * pktgen_packet_rate - Calculate the transmit rate.
 *
 * DESCRIPTION
 * Calculate the number of cycles to wait between sending bursts of traffic.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_packet_rate(port_info_t *info)
{
	uint64_t wire_size = (pktgen_wire_size(info) * 8);
	uint64_t link = (uint64_t)info->link.link_speed * Million;
	uint64_t pps = ((link / wire_size) * info->tx_rate) / 100;
	uint64_t cpp = (pps > 0) ? (pktgen.hz / pps) : (pktgen.hz / 4);

	info->tx_pps    = pps;
	info->tx_cycles = ((cpp * info->tx_burst) / get_port_txcnt(pktgen.l2p, info->pid));
}

/**************************************************************************//**
 *
 * pktgen_fill_pattern - Create the fill pattern in a packet buffer.
 *
 * DESCRIPTION
 * Create a fill pattern based on the arguments for the packet data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_fill_pattern(uint8_t *p, uint32_t len, uint32_t type, char *user) {
	uint32_t i;

	switch (type) {
	case USER_FILL_PATTERN:
		memset(p, 0, len);
		for (i = 0; i < len; i++)
			p[i] = user[i & (USER_PATTERN_SIZE - 1)];
		break;

	case NO_FILL_PATTERN:
		break;

	case ZERO_FILL_PATTERN:
		memset(p, 0, len);
		break;

	default:
	case ABC_FILL_PATTERN:	/* Byte wide ASCII pattern */
		for (i = 0; i < len; i++)
			p[i] = "abcdefghijklmnopqrstuvwxyz012345"[i & 0x1f];
		break;
	}
}

/**************************************************************************//**
 *
 * pktgen_find_matching_ipsrc - Find the matching IP source address
 *
 * DESCRIPTION
 * locate and return the pkt_seq_t pointer to the match IP address.
 *
 * RETURNS: pkt_seq_t  * or NULL
 *
 * SEE ALSO:
 */

pkt_seq_t *
pktgen_find_matching_ipsrc(port_info_t *info, uint32_t addr)
{
	pkt_seq_t *pkt = NULL;
	int i;

	addr = ntohl(addr);

	/* Search the sequence packets for a match */
	for (i = 0; i < info->seqCnt; i++)
		if (addr == info->seq_pkt[i].ip_src_addr.addr.ipv4.s_addr) {
			pkt = &info->seq_pkt[i];
			break;
		}

	/* Now try to match the single packet address */
	if (pkt == NULL)
		if (addr == info->seq_pkt[SINGLE_PKT].ip_src_addr.addr.ipv4.s_addr)
			pkt = &info->seq_pkt[SINGLE_PKT];

	return pkt;
}

/**************************************************************************//**
 *
 * pktgen_find_matching_ipdst - Find the matching IP destination address
 *
 * DESCRIPTION
 * locate and return the pkt_seq_t pointer to the match IP address.
 *
 * RETURNS: pkt_seq_t  * or NULL
 *
 * SEE ALSO:
 */

pkt_seq_t *
pktgen_find_matching_ipdst(port_info_t *info, uint32_t addr)
{
	pkt_seq_t *pkt = NULL;
	int i;

	addr = ntohl(addr);

	/* Search the sequence packets for a match */
	for (i = 0; i < info->seqCnt; i++)
		if (addr == info->seq_pkt[i].ip_dst_addr.addr.ipv4.s_addr) {
			pkt = &info->seq_pkt[i];
			break;
		}

	/* Now try to match the single packet address */
	if (pkt == NULL)
		if (addr == info->seq_pkt[SINGLE_PKT].ip_dst_addr.addr.ipv4.s_addr)
			pkt = &info->seq_pkt[SINGLE_PKT];

	/* Now try to match the range packet address */
	if (pkt == NULL)
		if (addr == info->seq_pkt[RANGE_PKT].ip_dst_addr.addr.ipv4.s_addr)
			pkt = &info->seq_pkt[RANGE_PKT];

	return pkt;
}

static __inline__ latency_t *
pktgen_latency_pointer(port_info_t *info, struct rte_mbuf *m)
{
	latency_t *latency;
	char *p;

	p = rte_pktmbuf_mtod(m, char *);

	p += sizeof(struct ether_hdr);

	p += (info->seq_pkt[SINGLE_PKT].ethType == ETHER_TYPE_IPv4) ?
		sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr);

	p += (info->seq_pkt[SINGLE_PKT].ipProto == IPPROTO_UDP) ?
		sizeof(struct udp_hdr) : sizeof(struct tcp_hdr);

	/* Force pointer to be aligned correctly */
	p = RTE_PTR_ALIGN_CEIL(p, sizeof(uint64_t));

	latency = (latency_t *)p;

	return latency;
}

static inline void
pktgen_latency_apply(port_info_t *info __rte_unused,
                     struct rte_mbuf **mbufs, int cnt)
{
	latency_t *latency;
	int i;

	for (i = 0; i < cnt; i++) {
		latency = pktgen_latency_pointer(info, mbufs[i]);

		latency->timestamp	= rte_rdtsc_precise();
		latency->magic		= LATENCY_MAGIC;
	}
}

static inline void
pktgen_do_tx_tap(port_info_t *info, struct rte_mbuf **mbufs, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		if (write(info->tx_tapfd, rte_pktmbuf_mtod(mbufs[i], char *), mbufs[i]->pkt_len) < 0) {
			pktgen_log_error("Write failed for tx_tap%d", info->pid);
			break;
		}
	}
}

/**************************************************************************//**
 *
 * _send_burst_fast - Send a burst of packet as fast as possible.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
_send_burst_fast(port_info_t *info, uint16_t qid)
{
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;
	struct rte_mbuf **pkts;
	uint32_t ret, cnt;

	cnt = mtab->len;
	mtab->len = 0;

	pkts    = mtab->m_table;

	if (rte_atomic32_read(&info->port_flags) & PROCESS_TX_TAP_PKTS) {
		while (cnt > 0) {
			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pktgen_do_tx_tap(info, pkts, ret);

			pkts += ret;
			cnt -= ret;
		}
	} else {
		while(cnt > 0) {
			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pkts += ret;
			cnt -= ret;
		}
	}
}

/**************************************************************************//**
 *
 * _send_burst_random - Send a burst of packets with random bits.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
_send_burst_random(port_info_t *info, uint16_t qid)
{
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;
	struct rte_mbuf **pkts;
	uint32_t ret, cnt, flags;

	cnt         = mtab->len;
	mtab->len   = 0;
	pkts        = mtab->m_table;

	flags   = rte_atomic32_read(&info->port_flags);
	if (unlikely(flags & PROCESS_TX_TAP_PKTS))
		while (cnt) {
			pktgen_rnd_bits_apply(info, pkts, cnt, NULL);

			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pktgen_do_tx_tap(info, pkts, ret);

			pkts += ret;
			cnt -= ret;
		}
	else
		while (cnt) {
			pktgen_rnd_bits_apply(info, pkts, cnt, NULL);

			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pkts += ret;
			cnt -= ret;
		}
}

/**************************************************************************//**
 *
 * _send_burst_latency - Send a burst of packets with latency time.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
_send_burst_latency(port_info_t *info, uint16_t qid)
{
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;
	struct rte_mbuf **pkts;
	uint32_t ret, cnt;

	cnt         = mtab->len;
	mtab->len   = 0;
	pkts        = mtab->m_table;
	while (cnt) {
		pktgen_latency_apply(info, pkts, cnt);

		ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

		pkts += ret;
		cnt -= ret;
	}
}

static __inline__ void
pktgen_send_burst(port_info_t *info, uint16_t qid)
{
	uint32_t flags;

	flags = rte_atomic32_read(&info->port_flags);

	if (flags & SEND_RANDOM_PKTS)
		_send_burst_random(info, qid);
	else if (flags & SEND_LATENCY_PKTS)
		_send_burst_latency(info, qid);
	else
		_send_burst_fast(info, qid);
}

static __inline__ void
pktgen_recv_latency(port_info_t *info, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	uint32_t flags;
	uint64_t lat;

	flags = rte_atomic32_read(&info->port_flags);

	if (flags & SEND_LATENCY_PKTS) {
		int i;
		latency_t *latency;

		for(i = 0; i < nb_pkts; i++) {
			latency = pktgen_latency_pointer(info, pkts[i]);

			if (latency->magic == LATENCY_MAGIC) {
				lat = (rte_rdtsc_precise() - latency->timestamp);
				info->avg_latency += lat;
				if (lat > info->jitter_threshold_clks)
					info->jitter_count++;
			} else
				info->magic_errors++;
		}
		info->latency_nb_pkts += nb_pkts;
	}
}

/**************************************************************************//**
 *
 * pktgen_tx_flush - Flush Tx buffers from ring.
 *
 * DESCRIPTION
 * Flush TX buffers from ring.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_tx_flush(port_info_t *info, uint16_t qid)
{
	/* Flush any queued pkts to the driver. */
	pktgen_send_burst(info, qid);

	rte_delay_ms(2);

	pktgen_clr_q_flags(info, qid, DO_TX_FLUSH);
}

/**************************************************************************//**
 *
 * pktgen_exit_cleanup - Clean up the data and other items
 *
 * DESCRIPTION
 * Clean up the data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_exit_cleanup(uint8_t lid)
{
	port_info_t *info;
	uint8_t idx, pid, qid;

	for (idx = 0; idx < get_lcore_txcnt(pktgen.l2p, lid); idx++) {
		pid = get_tx_pid(pktgen.l2p, lid, idx);
		if ( (info = (port_info_t *)get_port_private(pktgen.l2p, pid)) != NULL) {
			qid = get_txque(pktgen.l2p, lid, pid);
			pktgen_tx_flush(info, qid);
		}
	}
}

/**************************************************************************//**
 *
 * pktgen_has_work - Determine if lcore has work to do, if not wait for stop.
 *
 * DESCRIPTION
 * If lcore has work to do then return zero else spin till stopped and return 1.
 *
 * RETURNS: 0 or 1
 *
 * SEE ALSO:
 */

static __inline__ int
pktgen_has_work(void)
{
	if (!get_map(pktgen.l2p, RTE_MAX_ETHPORTS, rte_lcore_id())) {
		pktgen_log_warning("Nothing to do on lcore %d: exiting",
		                   rte_lcore_id());
		return 1;
	}
	return 0;
}

/**************************************************************************//**
 *
 * pktgen_packet_ctor - Construct a complete packet with all headers and data.
 *
 * DESCRIPTION
 * Construct a packet type based on the arguments passed with all headers.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_packet_ctor(port_info_t *info, int32_t seq_idx, int32_t type)
{
	pkt_seq_t         *pkt = &info->seq_pkt[seq_idx];
	struct ether_hdr  *eth = (struct ether_hdr *)&pkt->hdr.eth;
	uint16_t tlen;

	/* Fill in the pattern for data space. */
	pktgen_fill_pattern((uint8_t *)&pkt->hdr,
	                    (sizeof(pkt_hdr_t) + sizeof(pkt->pad)),
	                    info->fill_pattern_type, info->user_pattern);

	char *ether_hdr = pktgen_ether_hdr_ctor(info, pkt, eth);

	/* Add GRE header and adjust ether_hdr pointer if requested */
	if (rte_atomic32_read(&info->port_flags) & SEND_GRE_IPv4_HEADER)
		ether_hdr =
		        pktgen_gre_hdr_ctor(info, pkt, (greIp_t *)ether_hdr);
	else if (rte_atomic32_read(&info->port_flags) & SEND_GRE_ETHER_HEADER)
		ether_hdr = pktgen_gre_ether_hdr_ctor(info,
		                                      pkt,
		                                      (greEther_t *)ether_hdr);

	if (likely(pkt->ethType == ETHER_TYPE_IPv4)) {
		if (likely(pkt->ipProto == PG_IPPROTO_TCP)) {
			if (pkt->dport != PG_IPPROTO_L4_GTPU_PORT) {
				tcpip_t   *tip;

				/* Start from Ethernet header */
				tip = (tcpip_t *)ether_hdr;

				/* Construct the TCP header */
				pktgen_tcp_hdr_ctor(pkt, tip, ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, (ipHdr_t *)tip);

				pkt->tlen = pkt->ether_hdr_size +
				        sizeof(ipHdr_t) + sizeof(tcpHdr_t);
			} else {
				gtpuTcpIp_t     *tcpGtpu;

				/* Start from Ethernet header */
				tcpGtpu = (gtpuTcpIp_t *)ether_hdr;
				/* Construct the GTP-U header */
				pktgen_gtpu_hdr_ctor(pkt,
				                     (gtpuHdr_t *)tcpGtpu,
				                     pkt->ipProto);

				/* Construct the TCP header */
				pktgen_tcp_hdr_ctor(pkt,
				                    (tcpip_t *)tcpGtpu,
				                    ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, (ipHdr_t *)tcpGtpu);

				pkt->tlen = pkt->ether_hdr_size +
				        sizeof(ipHdr_t) + sizeof(tcpHdr_t) +
				        sizeof(gtpuHdr_t);
			}
		} else if (pkt->ipProto == PG_IPPROTO_UDP) {
			if (pkt->dport != PG_IPPROTO_L4_GTPU_PORT) {
				udpip_t   *udp;

				/* Construct the Ethernet header */
				/* udp = (udpip_t *)pktgen_ether_hdr_ctor(info, pkt, eth); */
				udp = (udpip_t *)ether_hdr;

				/* Construct the UDP header */
				pktgen_udp_hdr_ctor(pkt, udp, ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, (ipHdr_t *)udp);

				pkt->tlen = pkt->ether_hdr_size +
				        sizeof(ipHdr_t) + sizeof(udpHdr_t);
			} else {
				gtpuUdpIp_t   *udpGtpu;

				udpGtpu = (gtpuUdpIp_t *)ether_hdr;

				/* Construct the GTP-U header */
				pktgen_gtpu_hdr_ctor(pkt,
				                     (gtpuHdr_t *)udpGtpu,
				                     pkt->ipProto);

				/* Construct the UDP header */
				pktgen_udp_hdr_ctor(pkt,
				                    (udpip_t *)udpGtpu,
				                    ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, (ipHdr_t *)udpGtpu);

				pkt->tlen = pkt->ether_hdr_size +
				        sizeof(ipHdr_t) + sizeof(udpHdr_t) +
				        sizeof(gtpuHdr_t);
			}
		} else if (pkt->ipProto == PG_IPPROTO_ICMP) {
			udpip_t           *uip;
			icmpv4Hdr_t       *icmp;

			/* Start from Ethernet header */
			uip = (udpip_t *)ether_hdr;

			/* Create the ICMP header */
			uip->ip.src         = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
			uip->ip.dst         = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
			tlen                = pkt->pktSize -
			        (pkt->ether_hdr_size + sizeof(ipHdr_t));
			uip->ip.len         = htons(tlen);
			uip->ip.proto       = pkt->ipProto;

			icmp = (icmpv4Hdr_t *)&uip->udp;
			icmp->code                      = 0;
			if ( (type == -1) || (type == ICMP4_TIMESTAMP)) {
				icmp->type                      =
				        ICMP4_TIMESTAMP;
				icmp->data.timestamp.ident      = 0x1234;
				icmp->data.timestamp.seq        = 0x5678;
				icmp->data.timestamp.originate  = 0x80004321;
				icmp->data.timestamp.receive    = 0;
				icmp->data.timestamp.transmit   = 0;
			} else if (type == ICMP4_ECHO) {
				icmp->type                      = ICMP4_ECHO;
				icmp->data.echo.ident           = 0x1234;
				icmp->data.echo.seq             = 0x5678;
				icmp->data.echo.data            = 0;
			}
			icmp->cksum     = 0;
			tlen            = pkt->pktSize -
			        (pkt->ether_hdr_size + sizeof(ipHdr_t));/* ICMP4_TIMESTAMP_SIZE */
			icmp->cksum     = cksum(icmp, tlen, 0);
			if (icmp->cksum == 0)
				icmp->cksum = 0xFFFF;

			/* IPv4 Header constructor */
			pktgen_ipv4_ctor(pkt, (ipHdr_t *)uip);

			pkt->tlen = pkt->ether_hdr_size + sizeof(ipHdr_t) +
			        ICMP4_TIMESTAMP_SIZE;
		}
	} else if (pkt->ethType == ETHER_TYPE_IPv6) {
		if (pkt->ipProto == PG_IPPROTO_TCP) {
			tcpipv6_t         *tip;

			/* Start from Ethernet header */
			tip = (tcpipv6_t *)ether_hdr;

			/* Create the pseudo header and TCP information */
			(void)rte_memcpy(tip->ip.daddr, &pkt->ip_dst_addr.addr.ipv4.s_addr,
			                 sizeof(struct in6_addr));
			(void)rte_memcpy(tip->ip.saddr, &pkt->ip_src_addr.addr.ipv4.s_addr,
			                 sizeof(struct in6_addr));

			tlen                = sizeof(tcpHdr_t) +
			        (pkt->pktSize - pkt->ether_hdr_size -
			         sizeof(ipv6Hdr_t) - sizeof(tcpHdr_t));
			tip->ip.tcp_length  = htonl(tlen);
			tip->ip.next_header = pkt->ipProto;

			tip->tcp.sport      = htons(pkt->sport);
			tip->tcp.dport      = htons(pkt->dport);
			tip->tcp.seq        = htonl(DEFAULT_PKT_NUMBER);
			tip->tcp.ack        = htonl(DEFAULT_ACK_NUMBER);
			tip->tcp.offset     =
			        ((sizeof(tcpHdr_t) / sizeof(uint32_t)) << 4);	/* Offset in words */
			tip->tcp.window     = htons(DEFAULT_WND_SIZE);
			tip->tcp.urgent     = 0;
			tip->tcp.flags      = ACK_FLAG;	/* ACK */

			tlen                = sizeof(tcpipv6_t) +
			        (pkt->pktSize - pkt->ether_hdr_size -
			         sizeof(ipv6Hdr_t) - sizeof(tcpHdr_t));
			tip->tcp.cksum      = cksum(tip, tlen, 0);

			/* IPv6 Header constructor */
			pktgen_ipv6_ctor(pkt, (ipv6Hdr_t *)&tip->ip);

			pkt->tlen = sizeof(tcpHdr_t) + pkt->ether_hdr_size +
			        sizeof(ipv6Hdr_t);
			if (unlikely(pkt->pktSize < pkt->tlen))
				pkt->pktSize = pkt->tlen;
		} else if (pkt->ipProto == PG_IPPROTO_UDP) {
			uint32_t addr;
			udpipv6_t         *uip;

			/* Start from Ethernet header */
			uip = (udpipv6_t *)ether_hdr;

			/* Create the pseudo header and TCP information */
			addr                = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
			(void)rte_memcpy(&uip->ip.daddr[8], &addr,
			                 sizeof(uint32_t));
			addr                = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
			(void)rte_memcpy(&uip->ip.saddr[8], &addr,
			                 sizeof(uint32_t));

			tlen                = sizeof(udpHdr_t) +
			        (pkt->pktSize - pkt->ether_hdr_size -
			         sizeof(ipv6Hdr_t) - sizeof(udpHdr_t));
			uip->ip.tcp_length  = htonl(tlen);
			uip->ip.next_header = pkt->ipProto;

			uip->udp.sport      = htons(pkt->sport);
			uip->udp.dport      = htons(pkt->dport);

			tlen                = sizeof(udpipv6_t) +
			        (pkt->pktSize - pkt->ether_hdr_size -
			         sizeof(ipv6Hdr_t) - sizeof(udpHdr_t));
			uip->udp.cksum      = cksum(uip, tlen, 0);
			if (uip->udp.cksum == 0)
				uip->udp.cksum = 0xFFFF;

			/* IPv6 Header constructor */
			pktgen_ipv6_ctor(pkt, (ipv6Hdr_t *)&uip->ip);

			pkt->tlen = sizeof(udpHdr_t) + pkt->ether_hdr_size +
			        sizeof(ipv6Hdr_t);
			if (unlikely(pkt->pktSize < pkt->tlen))
				pkt->pktSize = pkt->tlen;
		}
	} else if (pkt->ethType == ETHER_TYPE_ARP) {
		/* Start from Ethernet header */
		arpPkt_t *arp = (arpPkt_t *)ether_hdr;

		arp->hrd = htons(1);
		arp->pro = htons(ETHER_TYPE_IPv4);
		arp->hln = ETHER_ADDR_LEN;
		arp->pln = 4;

		/* FIXME make request/reply operation selectable by user */
		arp->op  = htons(2);

		ether_addr_copy(&pkt->eth_src_addr,
		                (struct ether_addr *)&arp->sha);
		arp->spa._32 = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);

		ether_addr_copy(&pkt->eth_dst_addr,
		                (struct ether_addr *)&arp->tha);
		arp->tpa._32 = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
	} else
		pktgen_log_error("Unknown EtherType 0x%04x", pkt->ethType);
}

/**************************************************************************//**
 *
 * pktgen_send_mbuf - Send a single packet to the given port.
 *
 * DESCRIPTION
 * Send a single packet to a given port, but enqueue the packet until we have
 * a given burst count of packets to send.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_send_mbuf(struct rte_mbuf *m, uint8_t pid, uint16_t qid)
{
	port_info_t *info = &pktgen.info[pid];
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;

	/* Add packet to the TX list. */
	mtab->m_table[mtab->len++] = m;

	/* Fill our tx burst requirement */
	if (mtab->len >= info->tx_burst)
		pktgen_send_burst(info, qid);
}

/**************************************************************************//**
 *
 * pktgen_packet_type - Examine a packet and return the type of packet
 *
 * DESCRIPTION
 * Examine a packet and return the type of packet.
 * the packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ pktType_e
pktgen_packet_type(struct rte_mbuf *m)
{
	pktType_e ret;
	struct ether_hdr *eth;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	ret = ntohs(eth->ether_type);

	return ret;
}

/**************************************************************************//**
 *
 * pktgen_packet_classify - Examine a packet and classify it for statistics
 *
 * DESCRIPTION
 * Examine a packet and determine its type along with counting statistics around
 * the packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_packet_classify(struct rte_mbuf *m, int pid)
{
	port_info_t *info = &pktgen.info[pid];
	int plen = (m->pkt_len + FCS_SIZE);
	uint32_t flags;
	pktType_e pType;

	pType = pktgen_packet_type(m);

	flags = rte_atomic32_read(&info->port_flags);
	if (unlikely(flags & (PROCESS_INPUT_PKTS | PROCESS_RX_TAP_PKTS))) {
		if (unlikely(flags & PROCESS_RX_TAP_PKTS))
			if (write(info->rx_tapfd, rte_pktmbuf_mtod(m, char *),
			          m->pkt_len) < 0)
				pktgen_log_error("Write failed for rx_tap%d",
				                 pid);

		switch ((int)pType) {
		case ETHER_TYPE_ARP:    info->stats.arp_pkts++;
			pktgen_process_arp(m, pid, 0);     break;
		case ETHER_TYPE_IPv4:   info->stats.ip_pkts++;
			pktgen_process_ping4(m, pid, 0);   break;
		case ETHER_TYPE_IPv6:   info->stats.ipv6_pkts++;
			pktgen_process_ping6(m, pid, 0);   break;
		case ETHER_TYPE_VLAN:   info->stats.vlan_pkts++;
			pktgen_process_vlan(m, pid);       break;
		case UNKNOWN_PACKET:	/* FALL THRU */
		default:                break;
		}
	} else
		/* Count the type of packets found. */
		switch ((int)pType) {
		case ETHER_TYPE_ARP:        info->stats.arp_pkts++;     break;
		case ETHER_TYPE_IPv4:       info->stats.ip_pkts++;      break;
		case ETHER_TYPE_IPv6:       info->stats.ipv6_pkts++;    break;
		case ETHER_TYPE_VLAN:       info->stats.vlan_pkts++;    break;
		default:                    break;
		}

	/* Count the size of each packet. */
	if (plen == ETHER_MIN_LEN)
		info->sizes._64++;
	else if ( (plen >= (ETHER_MIN_LEN + 1)) && (plen <= 127))
		info->sizes._65_127++;
	else if ( (plen >= 128) && (plen <= 255))
		info->sizes._128_255++;
	else if ( (plen >= 256) && (plen <= 511))
		info->sizes._256_511++;
	else if ( (plen >= 512) && (plen <= 1023))
		info->sizes._512_1023++;
	else if ( (plen >= 1024) && (plen <= ETHER_MAX_LEN))
		info->sizes._1024_1518++;
	else if (plen < ETHER_MIN_LEN)
		info->sizes.runt++;
	else if (plen >= (ETHER_MAX_LEN + 1))
		info->sizes.jumbo++;

	/* Process multicast and broadcast packets. */
	if (unlikely(((uint8_t *)m->buf_addr + m->data_off)[0] == 0xFF)) {
		if ( (((uint64_t *)m->buf_addr + m->data_off)[0] &
		      0xFFFFFFFFFFFF0000LL) == 0xFFFFFFFFFFFF0000LL)
			info->sizes.broadcast++;
		else if ( ((uint8_t *)m->buf_addr + m->data_off)[0] & 1)
			info->sizes.multicast++;
	}
}

/**************************************************************************//**
 *
 * pktgen_packet_classify_buld - Classify a set of packets in one call.
 *
 * DESCRIPTION
 * Classify a list of packets and to improve classify performance.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

#define PREFETCH_OFFSET     3
static __inline__ void
pktgen_packet_classify_bulk(struct rte_mbuf **pkts, int nb_rx, int pid)
{
	int j;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts[j], void *));

	/* Prefetch and handle already prefetched packets */
	for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[j + PREFETCH_OFFSET],
		                               void *));
		pktgen_packet_classify(pkts[j], pid);
	}

	/* Handle remaining prefetched packets */
	for (; j < nb_rx; j++)
		pktgen_packet_classify(pkts[j], pid);
}

/**************************************************************************//**
 *
 * pktgen_send_special - Send a special packet to the given port.
 *
 * DESCRIPTION
 * Create a special packet in the buffer provided.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_send_special(port_info_t *info, uint32_t flags)
{
	uint32_t s;

	/* Send packets attached to the sequence packets. */
	for (s = 0; s < info->seqCnt; s++) {
		if (flags & SEND_GRATUITOUS_ARP)
			pktgen_send_arp(info->pid, GRATUITOUS_ARP, s);
		if (flags & SEND_ARP_REQUEST)
			pktgen_send_arp(info->pid, 0, s);

		if (flags & SEND_PING4_REQUEST)
			pktgen_send_ping4(info->pid, s);
#ifdef INCLUDE_PING6
		if (flags & SEND_PING6_REQUEST)
			pktgen_send_ping6(info->pid, s);
#endif
	}

	/* Send the requests from the Single packet setup. */
	if (flags & SEND_GRATUITOUS_ARP)
		pktgen_send_arp(info->pid, GRATUITOUS_ARP, SINGLE_PKT);
	if (flags & SEND_ARP_REQUEST)
		pktgen_send_arp(info->pid, 0, SINGLE_PKT);

	if (flags & SEND_PING4_REQUEST)
		pktgen_send_ping4(info->pid, SINGLE_PKT);
#ifdef INCLUDE_PING6
	if (flags & SEND_PING6_REQUEST)
		pktgen_send_ping6(info->pid, SINGLE_PKT);
#endif

	pktgen_clr_port_flags(info, SEND_ARP_PING_REQUESTS);
}

int base64_STATIC(const u_char * xdata, int length, char *output, int buf_len)
{
    int count, cols, bits, c, char_count;
    unsigned char alpha[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; /* 64 bytes */
    char * ost = output;

    char_count = 0;
    bits = 0;
    cols = 0;

    if (((length * 1.5) + 4) > buf_len) {
        return -1;
    }

    memset(output, '\0', buf_len);

    for (count = 0; count < length; count++) {
        c = xdata[count];
        if (c > 255) {
            printf(
                    "plugbase.c->base64(): encountered char > 255 (decimal %d)\n "
                    "If you see this error message a char is more than one byte on your machine\n "
                    "This means your base64 results can not be trusted",
                    c);
        }

        bits += c;
        char_count++;

        if (char_count == 3) {
            *output++ = alpha[bits >> 18];
            *output++ = alpha[(bits >> 12) & 0x3f];
            *output++ = alpha[(bits >> 6) & 0x3f];
            *output++ = alpha[bits & 0x3f];
            cols += 4;
            if (cols == 64) {
                *output++ = '\n';
                cols = 0;
            }
            bits = 0;
            char_count = 0;
        }
        else {
            bits <<= 8;
        }
    }

    if (char_count != 0) {
        bits <<= 16 - (8 * char_count);
        *output++ = alpha[bits >> 18];
        *output++ = alpha[(bits >> 12) & 0x3f];
        if (char_count == 1) {
            *output++ = '=';
            *output++ = '=';
        }
        else {
            *output++ = alpha[(bits >> 6) & 0x3f];
            *output++ = '=';
        }
    }
    *output++ = '\n';

    return (output-ost);
}

int pktgen_getrandom_string64(FILE *fp,
        u_char *src_rd,
        uint32_t rd_len,
        char *buf,
        uint32_t buf_len)
{
    size_t nr;

//    u_char src_rd[LOAD_RANDOM_PL_SIZE>>1];

    //fp = fopen("/dev/urandom", "r");
    if ( NULL == fp )
        return -1;

    //fseek(fp, 0, SEEK_SET);
    nr = fread(src_rd, 1, rd_len, fp);
    if ( nr < rd_len ){
        printf("%s: insufficient random data\n", __func__);
        return -1;
    }

    //fclose(fp);

    return base64_STATIC(src_rd, rd_len, buf, buf_len);
}

typedef struct {
	port_info_t *info;
	uint16_t qid;
} pkt_data_t;

typedef enum
{
    IP = 0,
    HOPOPTS = 0,
    ICMPV4 = 1,
    IGMP = 2,
    IPIP = 4,
    TCP = 6,
    UDP = 17,
    IPV6 = 41,
    ROUTING = 43,
    FRAGMENT = 44,
    GRE = 47,
    ESP = 50,
    AUTH = 51, // RFC 4302
    SWIPE = 53,
    MOBILITY = 55,
    ICMPV6 = 58,
    NONEXT = 59,
    DSTOPTS = 60,
    SUN_ND = 77,
    PGM = 113,

    /* Last updated 3/31/2016.
       Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
    MIN_UNASSIGNED_IP_PROTO = 143,

    RESERVED = 255,       // == 0xFF
    PORT_SCAN = 255,
    PROTO_NOT_SET = 255,  // Indicates protocol has not been set.
}IpProtocol;

typedef struct __Pseudoheader
{
    uint32_t sip;
    uint32_t dip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
}Pseudoheader;

typedef struct __PsuedoheaderUnion
{
    union
    {
        Pseudoheader ph4;
        uint16_t ph4_arr[12];
    };
}PsuedoheaderUnion;

static void add_ipv4_pseudoheader(Pseudoheader* ph4, uint32_t *cksum)
{
    /*
     * This mess is necessary to make static analyzers happy.
     * Otherwise they assume we are reading garbage values
     */
    PsuedoheaderUnion* ph4_u = (PsuedoheaderUnion*)ph4;
    //= reinterpret_cast        <const PsuedoheaderUnion*>(ph4);
    uint16_t* h = ph4_u->ph4_arr;

    /* ipv4 pseudo header must have 12 bytes */
    *cksum += h[0];
    *cksum += h[1];
    *cksum += h[2];
    *cksum += h[3];
    *cksum += h[4];
    *cksum += h[5];
}

static void add_tcp_header(uint16_t **d,
    size_t *len,
    uint32_t *cksum)
{
    /* TCP hdr must have 20 hdr bytes */
    *cksum += (*d)[0];
    *cksum += (*d)[1];
    *cksum += (*d)[2];
    *cksum += (*d)[3];
    *cksum += (*d)[4];
    *cksum += (*d)[5];
    *cksum += (*d)[6];
    *cksum += (*d)[7];
    *cksum += (*d)[8];
    *cksum += (*d)[9];
    *d += 10;
    *len -= 20;
}

static void add_udp_header(uint16_t **d,
    size_t *len,
    uint32_t *cksum)
{
    /* UDP must have 8 hdr bytes */
    *cksum += (*d)[0];
    *cksum += (*d)[1];
    *cksum += (*d)[2];
    *cksum += (*d)[3];
    *len -= 8;
    *d += 4;
}

static uint16_t cksum_add(uint16_t* buf, size_t len, uint32_t cksum)
{
    uint16_t* sp = buf;
    size_t n, sn;

    if (len > 1 )
    {
        sn = ((len / 2) & 0xF);  // == len/2 % 16
        n = (((len / 2) + 15) / 16);   // ceiling of (len / 2) / 16

        switch (sn)
        {
        case 0:
            sn = 16;
            cksum += sp[15];
        case 15:
            cksum += sp[14];
        case 14:
            cksum += sp[13];
        case 13:
            cksum += sp[12];
        case 12:
            cksum += sp[11];
        case 11:
            cksum += sp[10];
        case 10:
            cksum += sp[9];
        case 9:
            cksum += sp[8];
        case 8:
            cksum  += sp[7];
        case 7:
            cksum += sp[6];
        case 6:
            cksum += sp[5];
        case 5:
            cksum += sp[4];
        case 4:
            cksum += sp[3];
        case 3:
            cksum += sp[2];
        case 2:
            cksum += sp[1];
        case 1:
            cksum += sp[0];
        }
        sp += sn;

        /* XXX - unroll loop using Duff's device. */
        while (--n > 0)
        {
            cksum += sp[0];
            cksum += sp[1];
            cksum += sp[2];
            cksum += sp[3];
            cksum += sp[4];
            cksum += sp[5];
            cksum += sp[6];
            cksum += sp[7];
            cksum += sp[8];
            cksum += sp[9];
            cksum += sp[10];
            cksum += sp[11];
            cksum += sp[12];
            cksum += sp[13];
            cksum += sp[14];
            cksum += sp[15];
            sp += 16;
        }
    }

    if (len & 1)
        cksum += (*(unsigned char*)sp);

    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

static uint16_t tcp_cksum(uint16_t* h,
    size_t len,
    Pseudoheader* ph)
{
    uint32_t cksum = 0;

    add_ipv4_pseudoheader(ph, &cksum);
    add_tcp_header(&h, &len, &cksum);
    return cksum_add(h, len, cksum);
}

static uint16_t udp_cksum(uint16_t* buf,
    size_t len,
    Pseudoheader* ph)
{
    uint32_t cksum = 0;

    add_ipv4_pseudoheader(ph, &cksum);
    add_udp_header(&buf, &len, &cksum);
    return cksum_add(buf, len, cksum);
}

#define LOAD_RANDOM_IP_ADDR
#define LOAD_RANDOM_PAYLOAD
#define LOAD_CSUM

static __inline__ void
pktgen_setup_cb(struct rte_mempool *mp,
        void *opaque, void *obj, unsigned obj_idx __rte_unused, FILE *fp_rd)
{
    pkt_data_t *data = (pkt_data_t *)opaque;
	struct rte_mbuf *m = (struct rte_mbuf *)obj;
    port_info_t *info;
	pkt_seq_t *pkt;
    uint16_t qid;
#if defined(LOAD_RANDOM_IP_ADDR) || defined(LOAD_RANDOM_PAYLOAD)
    uint16_t rd_len, pl_len;
    int rand_strlen = 0;
    u_char rd_src[LOAD_RANDOM_PL_SIZE];
    char rand_str[LOAD_RANDOM_PL_SIZE<<1];
#endif
#ifdef LOAD_RANDOM_IP_ADDR
    char *prand;
#endif
#ifdef LOAD_CSUM
    Pseudoheader ph;
#endif
    info = data->info;
    qid = data->qid;

	if (mp == info->q[qid].tx_mp)
		pkt = &info->seq_pkt[SINGLE_PKT];
	else if (mp == info->q[qid].range_mp)
		pkt = &info->seq_pkt[RANGE_PKT];
	else if (mp == info->q[qid].seq_mp)
		pkt = &info->seq_pkt[info->seqIdx];
    else
        pkt = NULL;

	/* allocate each mbuf and put them on a list to be freed. */
    if (mp == info->q[qid].tx_mp) {
        pktgen_packet_ctor(info, SINGLE_PKT, -1);

        rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
                   (uint8_t *)&pkt->hdr, pkt->tlen);//MAX_PKT_SIZE);

        m->pkt_len  = pkt->pktSize;
        m->data_len = pkt->pktSize;
    } else if (mp == info->q[qid].range_mp) {
#ifdef LOAD_CSUM
        struct ether_hdr  *eth = (struct ether_hdr *)&pkt->hdr.eth;
        char *ether_hdr = pktgen_ether_hdr_ctor(info, pkt, eth);
        tcpip_t   *tip = (tcpip_t *)ether_hdr;
		udpip_t   *udp = (udpip_t *)ether_hdr;
#endif
#if defined(LOAD_RANDOM_IP_ADDR) || defined(LOAD_RANDOM_PAYLOAD)
        if ( NULL != fp_rd ) {
            //Generate random data
            pl_len = pkt->pktSize - pkt->ether_hdr_size - sizeof(ipHdr_t);
            if ( pl_len <= 128 ) {
                rd_len = 128;
            }
            else if ( pl_len <= 256 ) {
                rd_len = 256;
            }
            else if ( pl_len <= 512 ) {
                rd_len = 512;
            }
            else {// if ( pl_len <= 1024 ) {
                rd_len = 1024;
            }
            rand_strlen = pktgen_getrandom_string64(fp_rd, rd_src, rd_len,
                    rand_str, sizeof(rand_str));
        }
#endif

        if ( 0 == c_session ) {
            pktgen_range_ctor(&info->range, pkt);
#ifdef LOAD_RANDOM_IP_ADDR
            if ( rand_strlen > 0 ) {
                prand = rand_str;
                //pkt->ip_dst_addr.addr.ipv4.s_addr = *((uint32_t *)prand);
                pkt->ip_src_addr.addr.ipv4.s_addr = *((uint32_t *)prand);
            }
#endif
        }

        pktgen_packet_ctor(info, RANGE_PKT, -1);

        if (c_session++ >= (MAX_SESSION_PKTCNT-1)) {
            c_session = 0;
            //pkt->ipProto = PG_IPPROTO_UDP;
        }
        else {
            //pkt->ipProto = PG_IPPROTO_UDP;
        }

#ifdef LOAD_RANDOM_PAYLOAD
        //Fill Checksum
        if ( PG_IPPROTO_TCP == pkt->ipProto ) {
            //File TCP Payload
            if ( rand_strlen > 0 ) {
                pl_len = pkt->pktSize - pkt->ether_hdr_size - sizeof(ipHdr_t);
                if ( rand_strlen > pl_len )
                    rand_strlen = pl_len;
                rte_memcpy((uint8_t *)(tip+1), rand_str, rand_strlen);
                //rte_memcpy((uint8_t *)(tip+1), "xxls1126lisa", 12);
            }
        }
        else {
            //File UDP Payload
        }
#endif

#ifdef LOAD_CSUM
        //Format
        //Checksum calculation ---------------------------------------
        ph.sip = pkt->hdr.u.ipv4.src;
        ph.dip = pkt->hdr.u.ipv4.dst;
        /* setup the pseudo header for checksum calculation */
        ph.zero = 0;
        //ph.protocol = ip4h->proto();
        ph.len = htons((uint16_t)pkt->pktSize-pkt->ether_hdr_size-sizeof(ipHdr_t));

        //Fill Checksum
        if ( PG_IPPROTO_TCP == pkt->ipProto ) {
            ph.protocol = TCP;
            tip->tcp.cksum = 0;
            tip->tcp.cksum = tcp_cksum((uint16_t*)(&(tip->tcp)), ntohs(ph.len), &ph);
            //tip->tcp.cksum = cksum(tip, pkt->pktSize-pkt->ether_hdr_size, 0);
        }
        else {
            ph.protocol = UDP;
			udp->udp.cksum = 0;
			udp->udp.cksum = udp_cksum((uint16_t*)(&(udp->udp)), ntohs(ph.len), &ph);
        }
        //Checksum calculation End---------------------------------------
#endif

        //Payload, Put into m-buffer
        rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
                   (uint8_t *)&pkt->hdr, pkt->pktSize);//MAX_PKT_SIZE

        m->pkt_len  = pkt->pktSize;
        m->data_len = pkt->pktSize;
    } else if (mp == info->q[qid].seq_mp) {
        if (pktgen.is_gui_running) {
            while(info->seqIdx < info->seqCnt) {
                pkt = &info->seq_pkt[info->seqIdx];

                /* Check the sequence and start from the beginning */
                if (++info->seqIdx >= info->seqCnt)
                    info->seqIdx = 0;

                if (pkt->seq_enabled) {
                    /* Call ctor for those sequence which are enabled in the GUI */
                    pktgen_packet_ctor(info, info->seqIdx, -1);

                    rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
                               (uint8_t *)&pkt->hdr, pkt->tlen);//MAX_PKT_SIZE);
                    m->pkt_len  = pkt->pktSize;
                    m->data_len = pkt->pktSize;
                    pkt = &info->seq_pkt[info->seqIdx];
                    break;
                }
            }
        } else {
            pkt = &info->seq_pkt[info->seqIdx];
            pktgen_packet_ctor(info, info->seqIdx, -1);

            rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
                       (uint8_t *)&pkt->hdr, pkt->tlen);//MAX_PKT_SIZE);

            m->pkt_len  = pkt->pktSize;
            m->data_len = pkt->pktSize;

            pkt = &info->seq_pkt[info->seqIdx];

            /* move to the next packet in the sequence. */
            if (unlikely(++info->seqIdx >= info->seqCnt))
                info->seqIdx = 0;
        }
    }
}

/**************************************************************************//**
 *
 * pktgen_setup_packets - Setup the default packets to be sent.
 *
 * DESCRIPTION
 * Construct the default set of packets for a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_setup_packets(port_info_t *info, struct rte_mempool *mp, uint16_t qid)
{
    pkt_data_t pkt_data;

    pktgen_clr_q_flags(info, qid, CLEAR_FAST_ALLOC_FLAG);

    if (mp == info->q[qid].pcap_mp)
        return;

    rte_spinlock_lock(&info->port_lock);

    pkt_data.info = info;
    pkt_data.qid = qid;

    c_session = 0;
    printf("%s in, c_session %d\n", __func__, c_session);

#if RTE_VERSION >= RTE_VERSION_NUM(16, 7, 0, 0)
    rte_mempool_obj_iter_ex(mp, pktgen_setup_cb, &pkt_data);
#else
    {
    struct rte_mbuf *m, *mm;

    mm  = NULL;

    printf("%s in, ver %x\n", __func__, RTE_VERSION);

    /* allocate each mbuf and put them on a list to be freed. */
    for (;; ) {
        if ((m = rte_pktmbuf_alloc(mp)) == NULL)
            break;

        /* Put the allocated mbuf into a list to be freed later */
        m->next = mm;
        mm = m;

        pktgen_setup_cb(mp, &pkt_data, m, 0);
    }
    if (mm != NULL)
        rte_pktmbuf_free(mm);
    }
#endif
    rte_spinlock_unlock(&info->port_lock);
}

/**************************************************************************//**
 *
 * pktgen_send_pkts - Send a set of packet buffers to a given port.
 *
 * DESCRIPTION
 * Transmit a set of packets mbufs to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_send_pkts(port_info_t *info, uint16_t qid, struct rte_mempool *mp)
{
	uint32_t flags;
	int rc = 0;

	flags = rte_atomic32_read(&info->port_flags);

	if (flags & SEND_FOREVER) {
		rc = pg_pktmbuf_alloc_bulk(mp,
		                           info->q[qid].tx_mbufs.m_table,
		                           info->tx_burst);
		if (rc == 0) {
			info->q[qid].tx_mbufs.len = info->tx_burst;
			info->q[qid].tx_cnt += info->tx_burst;

			pktgen_send_burst(info, qid);
		}
	} else {
		int64_t txCnt;

		txCnt = pkt_atomic64_tx_count(&info->current_tx_count, info->tx_burst);
		if (txCnt > 0) {
			rc = pg_pktmbuf_alloc_bulk(mp,
			                           info->q[qid].tx_mbufs.m_table,
			                           txCnt);
			if (rc == 0) {
				info->q[qid].tx_mbufs.len = txCnt;
				pktgen_send_burst(info, qid);
			}
		} else
			pktgen_clr_port_flags(info, (SENDING_PACKETS | SEND_FOREVER));
	}
}

/**************************************************************************//**
 *
 * pktgen_main_transmit - Determine the next packet format to transmit.
 *
 * DESCRIPTION
 * Determine the next packet format to transmit for a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_main_transmit(port_info_t *info, uint16_t qid)
{
	struct rte_mempool *mp = NULL;
	uint32_t flags;

	flags = rte_atomic32_read(&info->port_flags);

	/*
	 * Transmit ARP/Ping packets if needed
	 */
	if ((flags & SEND_ARP_PING_REQUESTS))
		pktgen_send_special(info, flags);

	/* When not transmitting on this port then continue. */
	if (flags & SENDING_PACKETS) {
		mp = info->q[qid].tx_mp;

		if (flags & (SEND_RANGE_PKTS | SEND_PCAP_PKTS | SEND_SEQ_PKTS)) {
			if (flags & SEND_RANGE_PKTS)
				mp = info->q[qid].range_mp;
			else if (flags & SEND_SEQ_PKTS)
				mp = info->q[qid].seq_mp;
			else if (flags & SEND_PCAP_PKTS)
				mp = info->q[qid].pcap_mp;
		}

		if (rte_atomic32_read(&info->q[qid].flags) & CLEAR_FAST_ALLOC_FLAG) {
            //|| (0x3FFFFF <= (info->q[qid].tx_total_cnt))) {
			pktgen_setup_packets(info, mp, qid);
			info->q[qid].tx_total_cnt = 0;
        }

		pktgen_send_pkts(info, qid, mp);
	}

	flags = rte_atomic32_read(&info->q[qid].flags);
	if (flags & DO_TX_FLUSH)
		pktgen_tx_flush(info, qid);
}

/**************************************************************************//**
 *
 * pktgen_main_receive - Main receive routine for packets of a port.
 *
 * DESCRIPTION
 * Handle the main receive set of packets on a given port plus handle all of the
 * input processing if required.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_main_receive(port_info_t *info,
                    uint8_t lid,
                    struct rte_mbuf *pkts_burst[])
{
	uint8_t pid;
	uint16_t qid, nb_rx;
	capture_t *capture;

	pid = info->pid;
	qid = get_rxque(pktgen.l2p, lid, pid);

	/*
	 * Read packet from RX queues and free the mbufs
	 */
	if ( (nb_rx = rte_eth_rx_burst(pid, qid, pkts_burst, info->tx_burst)) == 0)
		return;

	info->q[qid].rx_cnt += nb_rx;

	pktgen_recv_latency(info, pkts_burst, nb_rx);

	/* packets are not freed in the next call. */
	pktgen_packet_classify_bulk(pkts_burst, nb_rx, pid);

	if (unlikely(info->dump_count > 0))
		pktgen_packet_dump_bulk(pkts_burst, nb_rx, pid);

	if (unlikely(rte_atomic32_read(&info->port_flags) & CAPTURE_PKTS)) {
		capture = &pktgen.capture[pktgen.core_info[lid].s.socket_id];
		if (unlikely((capture->port == pid) &&
		             (capture->lcore == lid)))
			pktgen_packet_capture_bulk(pkts_burst, nb_rx, capture);
	}

	rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
}

static void
port_map_info(uint8_t lid, port_info_t **infos, uint8_t *qids,
	      uint8_t *txcnt, uint8_t *rxcnt, const char *msg)
{
	uint8_t idx, pid, cnt = 0;
	uint8_t rx, tx;
	char buf[256];

	rx = get_lcore_rxcnt(pktgen.l2p, lid);
	tx = get_lcore_txcnt(pktgen.l2p, lid);

	if (txcnt && rxcnt) {
		*rxcnt = rx;
		*txcnt = tx;
		cnt = tx;
	} else if (rxcnt) {
		*rxcnt = rx;
		cnt = rx;
	} else if (txcnt) {
		*txcnt = tx;
		cnt = tx;
	}

	snprintf(buf, sizeof(buf), "  %s processing lcore: %3d rx: %2d tx: %2d",
		msg, lid, rx, tx);

	for (idx = 0; idx < cnt; idx++) {
		if (rxcnt)
			pid = get_rx_pid(pktgen.l2p, lid, idx);
		else
			pid = get_tx_pid(pktgen.l2p, lid, idx);

		if ((infos[idx] = get_port_private(pktgen.l2p, pid)) == NULL)
			continue;

		if (qids)
			qids[idx] = get_txque(pktgen.l2p, lid, pid);
	}

	pktgen_log_info("%s", buf);
}

#ifdef PKTGEN_PFRING_FORWARD
static void
port_rft_map_info(uint8_t lid, port_info_t **infos, uint8_t *qids,
          uint8_t *rftcnt, const char *msg)
{
    uint8_t idx, pid, cnt = 0;
    uint8_t rft;
    char buf[256];

    rft = get_lcore_rftcnt(pktgen.l2p, lid);

    if (rftcnt) {
        *rftcnt = rft;
        cnt = rft;
    }

    snprintf(buf, sizeof(buf), "  %s processing lcore: %3d rft: %2d",
        msg, lid, rft);

    for (idx = 0; idx < cnt; idx++) {
        pid = get_rft_pid(pktgen.l2p, lid, idx);
        pktgen_log_info("%s: pid %d\n", __func__, pid);

        if ((infos[idx] = get_port_private(pktgen.l2p, pid)) == NULL)
            continue;

        pktgen_log_info("%s: infos[idx] %d\n", __func__, infos[idx]);

        if (qids) {
            qids[idx] = get_rftque(pktgen.l2p, lid, pid);

            pktgen_log_info("%s: qids[idx] %d\n", __func__, qids[idx]);
        }
    }

    pktgen_log_info("%s", buf);
}
#endif

/**************************************************************************//**
 *
 * pktgen_main_rxtx_loop - Single thread loop for tx/rx packets
 *
 * DESCRIPTION
 * Handle sending and receiving packets from a given set of ports. This is the
 * main loop or thread started on a single core.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_main_rxtx_loop(uint8_t lid)
{
	struct rte_mbuf *pkts_burst[DEFAULT_PKT_BURST];
	port_info_t   *infos[RTE_MAX_ETHPORTS];
	uint8_t qids[RTE_MAX_ETHPORTS];
	uint8_t idx, txcnt, rxcnt;
	uint64_t curr_tsc;
	uint64_t tx_next_cycle;	/**< Next cycle to send a burst of traffic */

	memset(infos, '\0', sizeof(infos));
	memset(qids, '\0', sizeof(qids));

	port_map_info(lid, infos, qids, &txcnt, &rxcnt, "RX/TX");

	tx_next_cycle   = rte_rdtsc() + infos[0]->tx_cycles;

	pg_start_lcore(pktgen.l2p, lid);

	while(pg_lcore_is_running(pktgen.l2p, lid)) {
		for (idx = 0; idx < rxcnt; idx++) /* Read Packets */
			pktgen_main_receive(infos[idx], lid, pkts_burst);

		curr_tsc = rte_rdtsc();

		/* Determine when is the next time to send packets */
		if (curr_tsc >= tx_next_cycle) {
			tx_next_cycle = curr_tsc + infos[0]->tx_cycles;

			for (idx = 0; idx < txcnt; idx++) /* Transmit packets */
				pktgen_main_transmit(infos[idx], qids[idx]);
		} else if (curr_tsc >= (tx_next_cycle /8)) {
			for (idx = 0; idx < txcnt; idx++) /* Transmit packets */
				rte_eth_tx_burst(infos[idx]->pid, qids[idx], NULL, 0);
		}
	}

	pktgen_log_debug("Exit %d", lid);

	pktgen_exit_cleanup(lid);
}

/**************************************************************************//**
 *
 * pktgen_main_tx_loop - Main transmit loop for a core, no receive packet handling
 *
 * DESCRIPTION
 * When Tx and Rx are split across two cores this routing handles the tx packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_main_tx_loop(uint8_t lid)
{
	uint8_t idx, txcnt;
	port_info_t *infos[RTE_MAX_ETHPORTS];
	uint8_t qids[RTE_MAX_ETHPORTS];
	uint64_t curr_tsc;
	uint64_t tx_next_cycle;	/**< Next cycle to send a burst of traffic */

	memset(infos, '\0', sizeof(infos));
	memset(qids, '\0', sizeof(qids));
	port_map_info(lid, infos, qids, &txcnt, NULL, "TX");

	tx_next_cycle   = rte_rdtsc() + infos[0]->tx_cycles;

	pg_start_lcore(pktgen.l2p, lid);

	for (idx = 0; idx < txcnt; idx++) /* Transmit packets */
	    pktgen_log_info("%s: txcnt %d, qid %d\n", __func__, txcnt, qids[idx]);

	idx = 0;
	while(pg_lcore_is_running(pktgen.l2p, lid)) {
		curr_tsc = rte_rdtsc();

		/* Determine when is the next time to send packets */
		if (curr_tsc >= tx_next_cycle) {
			tx_next_cycle = curr_tsc + infos[0]->tx_cycles;

			for (idx = 0; idx < txcnt; idx++) /* Transmit packets */
				pktgen_main_transmit(infos[idx], qids[idx]);
		} else if (curr_tsc >= (tx_next_cycle /8)) {
			for (idx = 0; idx < txcnt; idx++) /* Transmit packets */
				rte_eth_tx_burst(infos[idx]->pid, qids[idx], NULL, 0);
		}
	}

	pktgen_log_debug("Exit %d", lid);

	pktgen_exit_cleanup(lid);
}

/**************************************************************************//**
 *
 * pktgen_main_rx_loop - Handle only the rx packets for a set of ports.
 *
 * DESCRIPTION
 * When Tx and Rx processing is split between two ports this routine handles
 * only the receive packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_main_rx_loop(uint8_t lid)
{
	struct rte_mbuf *pkts_burst[DEFAULT_PKT_BURST];
	uint8_t idx, rxcnt;
	port_info_t   *infos[RTE_MAX_ETHPORTS];

	memset(infos, '\0', sizeof(infos));
	port_map_info(lid, infos, NULL, NULL, &rxcnt, "RX");

	pg_start_lcore(pktgen.l2p, lid);

	while(pg_lcore_is_running(pktgen.l2p, lid)) {
		for (idx = 0; idx < rxcnt; idx++) /* Read packet */
			pktgen_main_receive(infos[idx], lid, pkts_burst);
	}

	pktgen_log_debug("Exit %d", lid);

	pktgen_exit_cleanup(lid);
}

#ifdef PKTGEN_PFRING_FORWARD
/**************************************************************************//**
 *
 * pktgen_main_rx_tx_pfloop - reseive from linux interface using pfring, and send
 *
 * DESCRIPTION
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
#define PKT_TIMEOUT  1000
#define PKT_SNAPLEN  1514

int pkt_gen_daq_WasStarted (void)
{
    DAQ_State s;

    if ( !daq_mod || !daq_hand )
        return 0;

    s = daq_check_status(daq_mod, daq_hand);

    return ( DAQ_STATE_STARTED == s );
}

int pkt_gen_daq_stop (void)
{
    int err = daq_stop(daq_mod, daq_hand);

    if ( err ) {
        pktgen_log_info("Can't stop DAQ (%d) - %s!\n",
            err, daq_get_error(daq_mod, daq_hand));
    }

    if ( daq_hand )
    {
        daq_shutdown(daq_mod, daq_hand);
        daq_hand = NULL;
    }

    daq_unload_modules();
    daq_mod = NULL;

    return err;
}

int pktgen_pfloop_daq_Init(uint8_t lid)
{
    int err;
    DAQ_Config_t cfg;
    char buf[256] = "";
    char type[32];
    char intf[32];
    char dir[64] = {0};
    const char * pdirs[2];

    rte_memcpy(type, "pfring", 7);
    rte_memcpy(intf, "pmo0", 5);
    rte_memcpy(dir, "/usr/local/lib/daq", 19);

    pktgen_log_info("%s: lid %d\n", __func__, lid);

    //lOAD Modules
    pdirs[0] = dir;
    pdirs[1] = NULL;
    err = daq_load_modules(pdirs);
    if ( err ) {
        pktgen_log_info("Can't load DAQ modules = %d\n", err);
        return -1;
    }

    //Module
    daq_mod = daq_find_module(type);
    if ( !daq_mod ) {
        pktgen_log_info("Can't find %s DAQ!\n", type);
        return -1;
    }

    //Mode
    daq_mode = DAQ_MODE_PASSIVE;

    //Config
    memset(&cfg, 0, sizeof(cfg));
    cfg.name = intf;
    cfg.snaplen = PKT_SNAPLEN;
    cfg.timeout = PKT_TIMEOUT;
    cfg.mode = daq_mode;
    cfg.extra = NULL;
    cfg.flags = 0;

    daq_config_set_value(&cfg, NULL, NULL);

    cfg.flags |= DAQ_CFG_PROMISC;

    err = daq_initialize(daq_mod, &cfg, &daq_hand, buf, sizeof(buf));
    if ( err ) {
        pktgen_log_info("Can't initialize DAQ %s (%d) - %s\n",
            type, err, buf);
        return -1;
    }

    if ( daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_UNPRIV_START ) {
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);
    }

    //Filter
/*    err = daq_set_filter(daq_mod, daq_hand, bpf);
    if ( err ) {
        pktgen_log_info("Can't set DAQ BPF filter to '%s' (%s)!\n",
                bpf, daq_get_error(daq_mod, daq_hand));
    }*/

    daq_config_clear_values(&cfg);

    //Start
    err = daq_start(daq_mod, daq_hand);
    if ( err ) {
        pktgen_log_info("Can't start DAQ (%d) - %s!\n",
                err, daq_get_error(daq_mod, daq_hand));
    }
    else if ( !(daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_UNPRIV_START) ) {
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);
    }

    return 0;
}

typedef struct __pkt_gen_daq_cb_user_data
{
    port_info_t *info;
    uint16_t qid;
}pkt_gen_daq_cb_user_data;

static void
pktgen_pfloop_send_sigle_pkt(port_info_t *info,
		uint16_t qid,
		const DAQ_PktHdr_t* pkthdr,
		const uint8_t* pkt)//pkt_seq_t *pkt)
{
    uint32_t plen;
    void *obj;
    struct rte_mbuf *m;
    struct rte_mempool *mp;

    //printf("%s: start format packages, qid %d\n", __func__, qid);

/*    if ( pkthdr->pktlen > (MAX_PKT_SIZE-34) )
        plen = MAX_PKT_SIZE-34;
    else
        plen = pkthdr->pktlen;*/
    plen = pkthdr->caplen;

    mp = info->q[qid].tx_mp;

    if ( NULL == pktgen_daq_mp_hdr )
        pktgen_daq_mp_hdr = (&mp->elt_list)->stqh_first;

    /*printf("%s: pktgen_daq_mp_hdr %lx, pkt %lx, plen %u(%u, %u)\n", __func__,
            (unsigned long)pktgen_daq_mp_hdr, (unsigned long)pkt,
            plen, pkthdr->pktlen, pkthdr->caplen);*/

    if ( NULL != pktgen_daq_mp_hdr ) {
        obj = (char *)pktgen_daq_mp_hdr + sizeof(*pktgen_daq_mp_hdr);
        m = (struct rte_mbuf *)obj;

        rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
                   (const uint8_t *)pkt/*&pkt->hdr*/, plen);
        m->pkt_len  = plen;//pkthdr->pktlen;//pkt->pktSize;
        m->data_len = plen;//pkthdr->pktlen;//pkt->pktSize;

        rte_eth_tx_burst(info->pid, qid, &m, 1);
    }

    pktgen_daq_mp_hdr = pktgen_daq_mp_hdr->next.stqe_next;

    return;
}

static DAQ_Verdict PacketCallback(void* user, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    pkt_gen_daq_cb_user_data *dc_data = (pkt_gen_daq_cb_user_data*)user;
    DAQ_Verdict verdict = DAQ_VERDICT_PASS;
    //pkt_seq_t pkt2mbuf;
    //static uint32_t pkt_cnt = 0;

    //printf("%s: call back in\n", __func__);

    if ( NULL == user ) {
        //return verdict;
    }

    if ( NULL == pkthdr ) {
        return verdict;
    }

    if ( NULL == pkt ) {
        return verdict;
    }

    /*printf("%s: qid %d--get pkt, pkt_cnt %d, size %d, ts_seconds %ld\n", __func__,
            dc_data->qid, pkt_cnt++, pkthdr->pktlen, (long int)pkthdr->ts.tv_sec);*/

    //pkt2mbuf.pktSize = pkthdr->pktlen;
    //rte_memcpy(&pkt2mbuf.hdr, pkt, pkt2mbuf.pktSize);

    pktgen_pfloop_send_sigle_pkt(dc_data->info, dc_data->qid, pkthdr, pkt);//&pkt2mbuf);

    return verdict;
}

static void
pktgen_main_rx_tx_pfloop(uint8_t lid)
{
    uint8_t idx, rftcnt;
    uint16_t qid;
    int err;
    port_info_t   *infos[RTE_MAX_ETHPORTS];
    uint8_t qids[RTE_MAX_ETHPORTS];
//    pkt_seq_t pkt;
    pkt_gen_daq_cb_user_data dcb_data;

    if ( pktgen_pfloop_daq_Init(lid) < 0 )
        return;

    pktgen_log_info("Start Aquiring\n");

    memset(infos, '\0', sizeof(infos));
    memset(qids, '\0', sizeof(qids));
    port_rft_map_info(lid, infos, qids, &rftcnt, "RFT");

    qid = qids[0];

    //Test, Send one first
/*    pkt.dport = 1199;
    pkt.ip_src_addr.addr.ipv4.s_addr = 0x2345;
    pkt.pktSize = 64;
    pktgen_pfloop_send_sigle_pkt(infos[0], qid, &pkt);*/

    dcb_data.info = infos[0];
    dcb_data.qid = qid;

    pg_start_lcore(pktgen.l2p, lid);

    //Aquire
    while ( pg_lcore_is_running(pktgen.l2p, lid) ) {
        for (idx = 0; idx < rftcnt; idx++) { /* Transmit packets */
            err = daq_acquire(daq_mod, daq_hand, 1, PacketCallback, &dcb_data);
            if ( err && err != DAQ_READFILE_EOF ) {
                pktgen_log_info("Can't acquire (%d) - %s!\n",
                        err, daq_get_error(daq_mod, daq_hand));
            }
            usleep(10);
        }
    }

    pkt_gen_daq_stop();
}

#endif

/**************************************************************************//**
 *
 * pktgen_launch_one_lcore - Launch a single logical core thread.
 *
 * DESCRIPTION
 * Help launch a single thread on one logical core.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

int
pktgen_launch_one_lcore(void *arg __rte_unused)
{
	uint8_t lid = rte_lcore_id();
	uint8_t ltype;

	if (pktgen_has_work())
		return 0;

	rte_delay_ms((lid + 1) * 21);

	ltype = get_type(pktgen.l2p, lid);

	pktgen_log_info("%s: lid %d, ltype %x\n", __func__, lid, ltype);

	switch (ltype) {
	case RX_TYPE:               pktgen_main_rx_loop(lid);       break;
	case TX_TYPE:               pktgen_main_tx_loop(lid);       break;
	case (RX_TYPE | TX_TYPE):   pktgen_main_rxtx_loop(lid);     break;
#ifdef PKTGEN_PFRING_FORWARD
	case RXFWTX_TYPE:            pktgen_main_rx_tx_pfloop(lid);  break;
#endif
	}
	return 0;
}

/**************************************************************************//**
 *
 * pktgen_page_config - Show the configuration page for pktgen.
 *
 * DESCRIPTION
 * Display the pktgen configuration page. (Not used)
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_page_config(void)
{
	display_topline("<Config Page>");

	scrn_center(20,
	               pktgen.scrn->ncols,
	               "Need to add the configuration stuff here");
	display_dashline(22);
}

static void
_page_display(void)
{
    static unsigned int counter = 0;

    pktgen_display_set_color("top.spinner");
    scrn_printf(1, 1, "%c", "-\\|/"[(counter++ & 3)]);
    pktgen_display_set_color(NULL);

    if (pktgen.flags & CPU_PAGE_FLAG)
        pktgen_page_cpu();
    else if (pktgen.flags & PCAP_PAGE_FLAG)
        pktgen_page_pcap(pktgen.portNum);
    else if (pktgen.flags & RANGE_PAGE_FLAG)
        pktgen_page_range();
    else if (pktgen.flags & CONFIG_PAGE_FLAG)
        pktgen_page_config();
    else if (pktgen.flags & SEQUENCE_PAGE_FLAG)
        pktgen_page_seq(pktgen.portNum);
    else if (pktgen.flags & RND_BITFIELD_PAGE_FLAG)
        pktgen_page_random_bitfields(pktgen.flags & PRINT_LABELS_FLAG,
                                     pktgen.portNum,
                                     pktgen.info[pktgen.portNum].rnd_bitfields);
    else if (pktgen.flags & LOG_PAGE_FLAG)
        pktgen_page_log(pktgen.flags & PRINT_LABELS_FLAG);
    else if (pktgen.flags & LATENCY_PAGE_FLAG)
        pktgen_page_latency();
        else if (pktgen.flags & STATS_PAGE_FLAG)
                pktgen_page_phys_stats();
    else
        pktgen_page_stats();
}

/**************************************************************************//**
 *
 * pktgen_page_display - Display the correct page based on timer0 callback.
 *
 * DESCRIPTION
 * When timer0 is active update or display the correct page of data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_page_display(struct rte_timer *tim __rte_unused, void *arg __rte_unused)
{
    static unsigned int update_display = 1;

	/* Leave if the screen is paused */
	if (scrn_is_paused())
		return;

	scrn_save();

    if (pktgen.flags & UPDATE_DISPLAY_FLAG) {
        pktgen.flags &= ~UPDATE_DISPLAY_FLAG;
        update_display = 1;
    }

    update_display--;
    if (update_display == 0) {
        update_display = UPDATE_DISPLAY_TICK_INTERVAL;
        _page_display();

        if (pktgen.flags & PRINT_LABELS_FLAG)
            pktgen.flags &= ~PRINT_LABELS_FLAG;
    }

	scrn_restore();

    pktgen_print_packet_dump();
}

static struct rte_timer timer0;
static struct rte_timer timer1;

/**************************************************************************//**
 *
 * pktgen_timer_setup - Set up the timer callback routines.
 *
 * DESCRIPTION
 * Setup the two timers to be used for display and calculating statistics.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
rte_timer_setup(void)
{
	int lcore_id = rte_get_master_lcore();

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* init timer structures */
	rte_timer_init(&timer0);
	rte_timer_init(&timer1);

	/* load timer0, every 1/2 seconds, on Display lcore, reloaded automatically */
	rte_timer_reset(&timer0,
                    UPDATE_DISPLAY_TICK_RATE,
	                PERIODICAL,
	                lcore_id,
	                pktgen_page_display,
	                NULL);

	/* load timer1, every second, on timer lcore, reloaded automatically */
	rte_timer_reset(&timer1,
	                pktgen.hz,
	                PERIODICAL,
	                lcore_id,
	                pktgen_process_stats,
	                NULL);
}
