/*-
 * Copyright (c) <2010>, Intel Corporation
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

#include "pktgen.h"

#include "pktgen-tcp.h"

extern uint32_t c_session;

/**************************************************************************//**
 *
 * pktgen_tcp_hdr_ctor - TCP header constructor routine.
 *
 * DESCRIPTION
 * Construct a TCP header in the packet buffer provided.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void pkt_gen_tcp_hdr_swap(tcpip_t *tip)
{
	uint16_t t_port;
	uint32_t t_ip;

    //Switch port tuple
    t_port = tip->tcp.sport;
    tip->tcp.sport = tip->tcp.dport;
    tip->tcp.dport = t_port;
    //Switch ip tuple
    t_ip = tip->ip.src;
    tip->ip.src = tip->ip.dst;
    tip->ip.dst = t_ip;
}

void
pktgen_tcp_hdr_ctor(pkt_seq_t *pkt, tcpip_t *tip, int type __rte_unused)
{
	uint16_t tlen;

	/* Zero out the header space */
	memset((char *)tip, 0, sizeof(tcpip_t));

	/* Create the TCP header */
	tip->ip.src         = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
	tip->ip.dst         = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
	tlen                = pkt->pktSize -
	        (pkt->ether_hdr_size + sizeof(ipHdr_t));

	tip->ip.len         = htons(tlen);
	tip->ip.proto       = pkt->ipProto;

	tip->tcp.sport      = htons(pkt->sport);
	tip->tcp.dport      = htons(pkt->dport);
	tip->tcp.seq        = htonl(DEFAULT_PKT_NUMBER);
	tip->tcp.ack        = htonl(DEFAULT_ACK_NUMBER);
	tip->tcp.offset     = ((sizeof(tcpHdr_t) / sizeof(uint32_t)) << 4);	/* Offset in words */
	tip->tcp.flags      = ACK_FLAG;						/* ACK */
	tip->tcp.window     = htons(DEFAULT_WND_SIZE);
	tip->tcp.urgent     = 0;

	tlen                = pkt->pktSize - pkt->ether_hdr_size;

	tip->tcp.cksum      = cksum(tip, tlen, 0);

    switch (c_session) {
    case 0:
        tip->tcp.flags = SYN_FLAG;
        break;
    case 1:
        tip->tcp.flags = SYN_FLAG|ACK_FLAG;
        pkt_gen_tcp_hdr_swap(tip);
        break;
    case 2:
        tip->tcp.flags = ACK_FLAG;
        break;
    case MAX_SESSION_LAST_4:
        tip->tcp.flags = FIN_FLAG;							//Client fin
        break;
    case MAX_SESSION_LAST_3:
        tip->tcp.flags = ACK_FLAG;							//Server ack
        pkt_gen_tcp_hdr_swap(tip);
        break;
    case MAX_SESSION_LAST_2:
        tip->tcp.flags = FIN_FLAG;							//Server fin
        pkt_gen_tcp_hdr_swap(tip);
        break;
    case MAX_SESSION_LAST_1:
        tip->tcp.flags = ACK_FLAG;							//Client ack
        break;
    default:
        tip->tcp.flags = PSH_FLAG|ACK_FLAG;
        if ( 0x03 == (c_session&0x3) ) {
            pkt_gen_tcp_hdr_swap(tip);
        }
        break;
    }
}
