#ifndef __DAQ_DPDK_H__
#define __DAQ_DPDK_H__



#ifdef HAVE_CONFIG_H
#include "config.h"
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

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>


#define DAQ_DPDK_VERSION 2

//MBUF configuration
#define NUM_MBUFS           8192//0x10000
#define MBUF_CACHE_SIZE     512
#define BURST_SIZE          256

#define MAX_ARGS            64

#define MAX_QUEUE_NUM       16

#define RX_RING_NUM 1
#define TX_RING_NUM 1

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

#define DPDKINST_STARTED       0x1

#define DAQ_DPDK_SECONDARY_EPFD_RETRY       5

#define DAQ_DPDK_SECONDARY_INIT_DELAY       5   //Seconds

//#define RX_CNT_TRACK
//#define RX_CSUM_TRACK

#define DAQ_DPDK_RING_MSG_TOLERATE              8
#define DAQ_DPDK_RING_MSG_QUEUE_SIZE            DAQ_DPDK_RING_MSG_TOLERATE
#define DAQ_DPDK_RING_MSG_DATA_LEN              256     //Message maximum data size, change this accordingly
#define DAQ_DPDK_RING_MSG_PRIVATE_DATA_LEN      0
#define DAQ_DPDK_RING_MSG_POOL_SIZE             1024
#define DAQ_DPDK_RING_MSG_POOL_CACHE            32

#define DAQ_DPDK_POWER_CTL
//#define DAQ_DPDK_POWER_FREQ_CTL

typedef enum _DAQ_DPDK_MBUF_NAME_TYPE
{
    PKT_MBUF_POOL,
    IPC_MSG_RING,
    IPC_MSG_MBUF_POOL,
    IPC_MSG_RING_PC_RSP,
    IPC_MSG_RING_PC_REQ
}DAQ_DPDK_MBUF_NAME_TYPE;

typedef struct _EtherHdr
{
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;

} EtherHdr;

typedef enum __dpdk_port_work_mode
{
	DPDK_PORT_RX,
	DPDK_PORT_TX,
	DPDK_PORT_RXTX,
}dpdk_port_work_mode;

typedef struct __Dpdk_Power_Heuristic
{
    int intr_en;
    uint64_t prev_tsc_power;
}Dpdk_Power_Heuristic;

typedef struct _dpdk_instance
{
    struct _dpdk_instance *next;
    struct _dpdk_instance *peer;
    uint8_t rx_queue_s;
    uint8_t tx_queue_s;
    uint8_t rx_queue_e;
    uint8_t tx_queue_e;
    uint8_t rx_queue_h;
    uint8_t tx_queue_h;
    uint8_t n_rx_queue;
    uint8_t n_tx_queue;
    uint32_t flags;
    uint32_t port_mode;
    int port;
    int index;
    int tx_start;
    int tx_end;
    int sigfd;
    int epfd;
    unsigned lcore_id;
    volatile int break_loop;
    pthread_t tid;
    struct rte_mempool *mbuf_pool;
    struct rte_mempool *mbuf_pools[MAX_QUEUE_NUM];
    struct rte_mempool *msg_pool;
    struct rte_mempool *ipc_msg_pools[MAX_QUEUE_NUM];
    struct rte_ring *rsvmsg_ring;
    struct rte_ring *ipc_msg_rings[MAX_QUEUE_NUM];
    struct rte_ring *msg_ring_pc_rsp;
    struct rte_ring *msg_ring_pc_req;
    struct rte_mbuf *tx_burst[BURST_SIZE * RX_RING_NUM];
} DpdkInstance;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    int debug;
    int epfds[MAX_QUEUE_NUM];
    int socfds[MAX_QUEUE_NUM];
    enum rte_proc_type_t proc_type;
    int mulp_sync_count;
    DpdkInstance *instances;
    DpdkInstance *rx_ins;
    Dpdk_Power_Heuristic *power_heurs;
    int intf_count;
    struct sfbpf_program fcode;
    volatile int break_loop;
    int promisc_flag;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} Dpdk_Context_t;

typedef uint8_t  portid_t;
#define RTE_PORT_ALL            (~(portid_t)0x0)
#define RSS_HASH_KEY_LENGTH 64

struct rss_type_info {
    char str[32];
    uint64_t rss_type;
};

typedef struct __pktcnt_msg
{
    int rtn;
    daq_pc_filter_req_type msg_type;
    void *msg_ptr;
}pktcnt_msg;

#define STD_BUF  1024

extern char log_buf[STD_BUF+1];
extern int daq_dpdk_log_daemon;

static inline void DAQ_RTE_LOG(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if ( daq_dpdk_log_daemon ) {
        vsnprintf(log_buf, STD_BUF, format, ap);
        log_buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", log_buf);
    }
    else {
        vfprintf(stderr, format, ap);
    }

    va_end(ap);
}

#ifdef LOG_DEEP
#define DAQ_RTE_LOG_DEEP(fmt, ...)        DAQ_RTE_LOG(fmt, ##__VA_ARGS__)
#else
#define DAQ_RTE_LOG_DEEP(fmt, ...)
#endif

#endif  /*End of __DAQ_DPDK_H__*/
