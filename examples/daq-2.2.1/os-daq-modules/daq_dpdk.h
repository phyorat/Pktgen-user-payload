#ifndef __DAQ_DPDK_H__
#define __DAQ_DPDK_H__

/*
** Copyright (C) 2016
**     University of Science and Technology of China.  All rights reserved.
** Author: Tiwei Bie <btw () mail ustc edu cn>
**         Jiaxin Liu <jiaxin10 () mail ustc edu cn>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#define DAQ_DPDK_VERSION 2

#define NUMA_MAX_SOC_NUM        2
#define NUMA_MAX_LCORE_NUM      12

#define NUM_MBUFS        	    65536
#define MBUF_CACHE_SIZE     	512
#define BURST_SIZE          	256

#define DEFAULT_RING_RX_SIZE    1024
#define RING_MAX_NUM            16

#define MAX_ARGS 64

#define RX_RING_NUM 1
#define TX_RING_NUM 1

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

//#define DEFAULT_BURST_SIZE_IO_RX_READ       BURST_SIZE
#define DEFAULT_BURST_SIZE_IO_RX_WRITE      (BURST_SIZE>>1)

#define DEFAULT_SIZE_AQUIRE_READ            (BURST_SIZE>>2)

#define MBUF_ARRAY_SIZE   512

#define IO_RX_PREFETCH_ENABLE   1
#if IO_RX_PREFETCH_ENABLE
#define DPDK_RX_PREFETCH0(p)       rte_prefetch0(p)
#define DPDK_RX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define DPDK_RX_PREFETCH0(p)
#define DPDK_RX_PREFETCH1(p)
#endif

struct dpdk_mbuf_array {
    struct rte_mbuf *array[MBUF_ARRAY_SIZE];
    uint32_t n_mbufs;
};

typedef struct _dpdk_instance
{
    struct _dpdk_instance *next;
    struct _dpdk_instance *peer;
#define DPDKINST_STARTED       0x1
    uint32_t flags;

    /* I/O RX */
    struct {
    	int queue;
        struct rte_ring *ring_in;
    } rx;

    /* I/O TX */
    struct {
        int start;
        int end;

        struct rte_ring *ring_out;
        struct rte_mbuf *burst[BURST_SIZE * RX_RING_NUM];
    } tx;

    DAQ_Stats_t stats;
    unsigned lcore_id;
    int index;
    int isMaster;
    uint64_t show_cnt;
    time_t cts;
} DpdkInstance;

typedef struct _sur_mbuf
{
    struct rte_mbuf *mbuf;
    struct timeval ts;
}Sur_Mbuf;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    int debug;
    DpdkInstance *instances;
    DpdkInstance *inst[RING_MAX_NUM];
    DAQ_State state[RING_MAX_NUM];
    uint32_t inst_stat;
    unsigned socket_io;
    unsigned lcore_id;

    /* I/O RX */
    struct {
        int queue_num;
        int queue_s;
        int queue_e;

        // Rings
        pthread_t ring_tid_map[RING_MAX_NUM];
        struct rte_ring *rings[RING_MAX_NUM];
        uint32_t n_ring;

/*        // NIC
        struct {
            uint8_t port;
            uint8_t queue;
        } nic_queues[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t n_nic_queues;

        // Internal buffers
        struct app_mbuf_array mbuf_in;*/
        uint64_t qc_flush[RING_MAX_NUM];
        struct dpdk_mbuf_array mbuf_in[RING_MAX_NUM];
        //struct dpdk_mbuf_array mbuf_aquire[RING_MAX_NUM];
        /*uint8_t mbuf_out_flush[APP_MAX_WORKER_LCORES];

        // Stats
        uint32_t nic_queues_count[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t nic_queues_iters[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t rings_count[APP_MAX_WORKER_LCORES];
        uint32_t rings_iters[APP_MAX_WORKER_LCORES];*/
    } rx;

    /* I/O TX */
    struct {
        int queue_num;
        int queue_s;
        int queue_e;

        /*// Rings
        struct rte_ring *rings[RING_NUM];
        uint32_t n_rings;

        // NIC
        uint8_t nic_ports[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint32_t n_nic_ports;

        // Internal buffers
        struct app_mbuf_array mbuf_out[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint8_t mbuf_out_flush[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];

        //Stats
        uint32_t rings_count[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];
        uint32_t rings_iters[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];
        uint32_t nic_ports_count[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint32_t nic_ports_iters[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];*/
    } tx;

    int port;
    enum rte_proc_type_t proc_type;
    struct rte_mempool *mbuf_pool;
    struct rte_mempool *mbuf_pools[NUMA_MAX_SOC_NUM];

    int intf_count;
    struct sfbpf_program fcode;
    volatile int break_loop;
    int promisc_flag;
    DAQ_Stats_t stats;
    char errbuf[256];
} Dpdk_Context_t;


struct rss_type_info {
    char str[32];
    uint64_t rss_type;
};

typedef uint8_t  portid_t;
#define RTE_PORT_ALL            (~(portid_t)0x0)

#define RX_CNT_TRACK


#endif /* End of __DAQ_DPDK_H__ */
