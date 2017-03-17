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

#include "daq_dpdk.h"
#include "daq_dpdk_statsop.h"
#include "daq_dpdk_epfd_ipc.h"
#ifdef DAQ_DPDK_POWER_CTL
#include "daq_dpdk_power.h"
#endif

static DpdkInstance *create_instance(Dpdk_Context_t *dpdkc, const char *device, char *errbuf, size_t errlen);
static int create_bridge(Dpdk_Context_t *dpdkc, const int port1, const int port2);

char log_buf[STD_BUF+1];
int daq_dpdk_log_daemon = 0;

static uint8_t rss_intel_key[40] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
            .mq_mode    = ETH_MQ_RX_RSS,
            .split_hdr_size = 0,
            .header_split   = 0, /**< Header Split disabled */
            .hw_ip_checksum = 1, /**< IP checksum offload enabled */
            .hw_vlan_filter = 0, /**< VLAN filtering disabled */
            .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
            .hw_strip_crc   = 0, /**< CRC stripped by hardware */
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = rss_intel_key,
                .rss_hf = ETH_RSS_PROTO_MASK,
            },
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
#ifdef DAQ_DPDK_POWER_CTL
        .intr_conf = {
            .lsc = 1,
            .rxq = 1,
        },
#endif
};

static const struct rss_type_info rss_type_table[] = {
    { "ipv4", ETH_RSS_IPV4 },
    { "ipv4-frag", ETH_RSS_FRAG_IPV4 },
    { "ipv4-tcp", ETH_RSS_NONFRAG_IPV4_TCP },
    { "ipv4-udp", ETH_RSS_NONFRAG_IPV4_UDP },
    { "ipv4-sctp", ETH_RSS_NONFRAG_IPV4_SCTP },
    { "ipv4-other", ETH_RSS_NONFRAG_IPV4_OTHER },
    { "ipv6", ETH_RSS_IPV6 },
    { "ipv6-frag", ETH_RSS_FRAG_IPV6 },
    { "ipv6-tcp", ETH_RSS_NONFRAG_IPV6_TCP },
    { "ipv6-udp", ETH_RSS_NONFRAG_IPV6_UDP },
    { "ipv6-sctp", ETH_RSS_NONFRAG_IPV6_SCTP },
    { "ipv6-other", ETH_RSS_NONFRAG_IPV6_OTHER },
    { "l2-payload", ETH_RSS_L2_PAYLOAD },
    { "ipv6-ex", ETH_RSS_IPV6_EX },
    { "ipv6-tcp-ex", ETH_RSS_IPV6_TCP_EX },
    { "ipv6-udp-ex", ETH_RSS_IPV6_UDP_EX },
    { "port", ETH_RSS_PORT },
    { "vxlan", ETH_RSS_VXLAN },
    { "geneve", ETH_RSS_GENEVE },
    { "nvgre", ETH_RSS_NVGRE },
};

DpdkInstance *Send_Instance = NULL;
DAQ_PktHdr_t daqhdr;

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};


#ifdef RX_CNT_TRACK
static void
nic_stats_display(uint8_t port_id)
{
    struct rte_eth_stats stats;
    uint8_t i;

    static const char *nic_stats_border = "########################";

    rte_eth_stats_get(port_id, &stats);
    printf("\n  %s NIC statistics for port %-2d %s\n",
           nic_stats_border, port_id, nic_stats_border);

    printf("  RX-packets: %-10"PRIu64"  RX-errors:  %-10"PRIu64
           "  RX-bytes:  %-10"PRIu64"\n", stats.ipackets, stats.ierrors,
           stats.ibytes);
    printf("  RX-nombuf:  %-10"PRIu64"\n", stats.rx_nombuf);
    printf("  TX-packets: %-10"PRIu64"  TX-errors:  %-10"PRIu64
           "  TX-bytes:  %-10"PRIu64"\n", stats.opackets, stats.oerrors,
           stats.obytes);

    printf("\n");
    for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
        printf("  Stats reg %2d RX-packets: %-10"PRIu64
               "  RX-errors: %-10"PRIu64
               "  RX-bytes: %-10"PRIu64"\n",
               i, stats.q_ipackets[i], stats.q_errors[i], stats.q_ibytes[i]);
    }

    printf("\n");
    for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
        printf("  Stats reg %2d TX-packets: %-10"PRIu64
               "  TX-bytes: %-10"PRIu64"\n",
               i, stats.q_opackets[i], stats.q_obytes[i]);
    }

    printf("  %s############################%s\n",
           nic_stats_border, nic_stats_border);
}

static void
nic_xstats_display(uint8_t port_id)
{
    struct rte_eth_xstat_name *xstats_names;
    struct rte_eth_xstat *xstats;
    int len, ret, i;
    static const char *nic_stats_border = "########################";

    len = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (len < 0) {
        printf("Cannot get xstats count\n");
        return;
    }
    xstats = malloc(sizeof(xstats[0]) * len);
    if (xstats == NULL) {
        printf("Cannot allocate memory for xstats\n");
        return;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
    if (xstats_names == NULL) {
        printf("Cannot allocate memory for xstat names\n");
        free(xstats);
        return;
    }
    if (len != rte_eth_xstats_get_names(
            port_id, xstats_names, len)) {
        printf("Cannot get xstat names\n");
        goto err;
    }

    printf("###### NIC extended statistics for port %-2d #########\n",
               port_id);
    printf("%s############################\n",
               nic_stats_border);
    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        printf("Cannot get xstats\n");
        goto err;
    }

    //len = len>23 ? 23:len;

    printf("\n");
    for (i = 0; i < len; i++) {
        if ( !strcmp("rx_good_packets", xstats_names[i].name)
                || !strcmp("rx_good_bytes", xstats_names[i].name) ) {
            printf("port %d--%s: %"PRIu64"\n", port_id, xstats_names[i].name, xstats[i].value);
        }
    }

    printf("%s############################\n",
               nic_stats_border);
err:
    free(xstats);
    free(xstats_names);
}
#endif

void
port_rss_hash_conf_show(portid_t port_id, const char rss_info[], int show_rss_key)
{
    struct rte_eth_rss_conf rss_conf;
    uint8_t rss_key[RSS_HASH_KEY_LENGTH];
    uint64_t rss_hf;
    uint8_t i;
    int diag;
    struct rte_eth_dev_info dev_info;
    uint8_t hash_key_size;

    if (0)//port_id_is_invalid(port_id, ENABLED_WARN))
        return;

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    if (dev_info.hash_key_size > 0 &&
            dev_info.hash_key_size <= sizeof(rss_key))
        hash_key_size = dev_info.hash_key_size;
    else {
        RTE_LOG(ERR, EAL, "dev_info did not provide a valid hash key size\n");
        return;
    }

    rss_conf.rss_hf = 0;
    for (i = 0; i < RTE_DIM(rss_type_table); i++) {
        if (!strcmp(rss_info, rss_type_table[i].str))
            rss_conf.rss_hf = rss_type_table[i].rss_type;
    }

    /* Get RSS hash key if asked to display it */
    rss_conf.rss_key = (show_rss_key) ? rss_key : NULL;
    rss_conf.rss_key_len = hash_key_size;
    diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
    if (diag != 0) {
        switch (diag) {
        case -ENODEV:
            RTE_LOG(ERR, EAL, "port index %d invalid\n", port_id);
            break;
        case -ENOTSUP:
            RTE_LOG(ERR, EAL, "operation not supported by device\n");
            break;
        default:
            RTE_LOG(ERR, EAL, "operation failed - diag=%d\n", diag);
            break;
        }
        return;
    }
    rss_hf = rss_conf.rss_hf;
    if (rss_hf == 0) {
        RTE_LOG(ERR, EAL, "RSS disabled\n");
        return;
    }
    DAQ_RTE_LOG("RSS functions:\n ");
    for (i = 0; i < RTE_DIM(rss_type_table); i++) {
        if (rss_hf & rss_type_table[i].rss_type)
            DAQ_RTE_LOG("%s ", rss_type_table[i].str);
    }
    DAQ_RTE_LOG("\n");
    if (!show_rss_key)
        return;
    DAQ_RTE_LOG("RSS key:\n");
    for (i = 0; i < hash_key_size; i++)
        DAQ_RTE_LOG("%02X", rss_key[i]);
    DAQ_RTE_LOG("\n\n");
}

static int parse_args(char *inputstring, char **argv)
{
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;)
    {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}

static int parse_interface(const DAQ_Config_t *config, Dpdk_Context_t *dpdkc, char *errbuf, size_t errlen)
{
    size_t len;
    int num_intfs = 0;
    int port1, port2;
    char intf[IFNAMSIZ];
	char *dev;
    DpdkInstance *instance;

    dev = dpdkc->device;
    if ( *dev == ':' ) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification1: '%s'!", __FUNCTION__, dpdkc->device);
        return -1;
    }

    if (((len = strlen(dev)) > 0 && *(dev + len - 1) == ':')) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification2: '%s'!", __FUNCTION__, dpdkc->device);
        return -1;
    }

    if ((config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::"))) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification3: '%s'!", __FUNCTION__, dpdkc->device);
        return -1;
    }

    while (*dev != '\0') {
        len = strcspn(dev, ":");
        if (len >= sizeof(intf)) {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            return -1;
        }

        if (len != 0) {
            dpdkc->intf_count++;
            snprintf(intf, len + 1, "%s", dev);
            instance = create_instance(dpdkc, intf, errbuf, errlen);
            if (!instance)
            	return -1;

            instance->next = dpdkc->instances;
            dpdkc->instances = instance;
            num_intfs++;
            if (config->mode != DAQ_MODE_PASSIVE) {
                if (num_intfs == 2) {
                    port1 = dpdkc->instances->next->port;
                    port2 = dpdkc->instances->port;

                    if (create_bridge(dpdkc, port1, port2) != DAQ_SUCCESS) {
                        snprintf(errbuf, errlen, "%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                                 __FUNCTION__, port1, port2);
                        return -1;
                    }
                    num_intfs = 0;
                }
                else if (num_intfs > 2)
                    break;
            }
        }
        else {
            len = 1;
        }

        dev += len;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!dpdkc->instances || (config->mode != DAQ_MODE_PASSIVE && num_intfs != 0)) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                __FUNCTION__, dpdkc->device);
        return -1;
    }

    return 0;
}

#ifdef DAQ_DPDK_POWER_CTL
static int epfd_wait_get(Dpdk_Context_t *dpdkc)
{
    int epfd_retry = DAQ_DPDK_SECONDARY_EPFD_RETRY;

    //epfd
    while ( epfd_retry -- ) {
        dpdkc->rx_ins->epfd = epfd_client(dpdkc);
        if ( dpdkc->rx_ins->epfd >= 0 ) {
            break;
        }
        sleep(1);
    }
    if ( dpdkc->rx_ins->epfd < 0 ) {
        return DAQ_ERROR;
    }

    DAQ_RTE_LOG("%s: got epfd-%d\n", __func__, dpdkc->rx_ins->epfd);

    return 0;
}
#endif

static void destroy_instance(DpdkInstance *instance)
{
    int i;

    if (instance)
    {
        if (instance->flags & DPDKINST_STARTED)
        {
            for (i = instance->tx_start; i < instance->tx_end; i++)
                rte_pktmbuf_free(instance->tx_burst[i]);

            rte_eth_dev_stop(instance->port);
            instance->flags &= ~DPDKINST_STARTED;
        }

        free(instance);
    }
}

static int destroy_dpdkc(Dpdk_Context_t *dpdkc)
{
    DpdkInstance *instance;

    if (!dpdkc)
        return -1;

    if ( RTE_PROC_PRIMARY == dpdkc->proc_type ) {
        RTE_LOG(INFO, EAL, "%s: Remove all epfd ipc fd\n", __func__);
        epfd_unlink_all(dpdkc->rx_ins);
    }

    /* Free all of the device instances. */
    while ((instance = dpdkc->instances) != NULL)
    {
        dpdkc->instances = instance->next;
        destroy_instance(instance);
    }

    sfbpf_freecode(&dpdkc->fcode);

    dpdkc->state = DAQ_STATE_STOPPED;

    return 0;
}

static DpdkInstance *create_instance(Dpdk_Context_t *dpdkc, const char *device, char *errbuf, size_t errlen)
{
    DpdkInstance *instance;
    int port, queue = 0, q_step = 1, queue_cnt = 1;
    int qn_strlen;
    static int index = 0;

    instance = calloc(1, sizeof(DpdkInstance));
    if (!instance)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate a new instance structure.", __FUNCTION__);
        goto err;
    }

    instance->index = index;
    index++;

    if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, device);
        goto err;
    }

    instance->port = port;

    if ( strlen(device) > 8 )
    {
        if ( '#' == *(device+5) && 0 < sscanf(device+6, "%d", &queue_cnt) ) {
            //printf("%s: Use Rx Queue on Port %d, Total %d...\n", __FUNCTION__, port, queue_cnt);
        }
        else {
            snprintf(errbuf, errlen, "%s: Invalid interface queue_cnt specification: '%s'!", __FUNCTION__, device);
            goto err;
        }

        if ( queue_cnt > 9 )
            qn_strlen = 8;
        else
            qn_strlen = 7;

        if ( '@' == *(device+qn_strlen) && 0 < sscanf(device+qn_strlen+1, "%d", &queue) ) {
        	//printf("%s: Use Rx Queue %d on Port %d, Total %d...\n", __FUNCTION__, queue, port, queue_cnt);
            q_step = 1;
        }
        else {
            snprintf(errbuf, errlen, "%s: Invalid interface queue_idx specification: '%s'!", __FUNCTION__, device);
            goto err;
        }
    }

    if (  0 == instance->index ) {
        instance->rx_queue_s = queue;
        instance->rx_queue_e = queue+q_step;
        instance->rx_queue_h = q_step;
        instance->n_rx_queue = queue_cnt;

        instance->tx_queue_s = 0;//queue;
        instance->tx_queue_e = 0;//queue+q_step;
        instance->tx_queue_h = 0;
        instance->n_tx_queue = 0;//queue_cnt;

        instance->port_mode = DPDK_PORT_RX;
        dpdkc->rx_ins = instance;
    }
    else {
        instance->rx_queue_s = 0;
        instance->rx_queue_e = 0;
        instance->rx_queue_h = 0;
        instance->n_rx_queue = 0;

        instance->tx_queue_s = queue;
        instance->tx_queue_e = queue+q_step;
        instance->tx_queue_h = q_step;
        instance->n_tx_queue = queue_cnt;

        instance->port_mode = DPDK_PORT_TX;
        Send_Instance = instance;

        return instance;
    }

    instance->tid = pthread_self();

    return instance;

err:
    //destroy_instance(instance);
    free(instance);
    return NULL;
}

static int create_bridge(Dpdk_Context_t *dpdkc, const int port1, const int port2)
{
    DpdkInstance *instance, *peer1, *peer2;

    peer1 = peer2 = NULL;
    for (instance = dpdkc->instances; instance; instance = instance->next) {
        if (instance->port == port1)
            peer1 = instance;
        else if (instance->port == port2)
            peer2 = instance;
    }

    if (!peer1 || !peer2)
        return DAQ_ERROR_NODEV;

    peer1->peer = peer2;
    peer2->peer = peer1;

    return DAQ_SUCCESS;
}

static int mbuf_lcore_getname(char *buf, int buflen,
        DpdkInstance *instance, unsigned sock_id, uint8_t qid, uint8_t type)
{
    switch (type) {
    case PKT_MBUF_POOL:
        if ( DPDK_PORT_TX == instance->port_mode ) {
            snprintf(buf, buflen, "MBUF_TX_POOL_S%dP%dQ%d",
                    sock_id, instance->port, qid);
        }
        else if ( DPDK_PORT_RX == instance->port_mode ) {
            snprintf(buf, buflen, "MBUF_RX_POOL_S%dP%dQ%d",
                    sock_id, instance->port, qid);
        }
        else {
            return -1;
        }
        break;
    case IPC_MSG_RING:
        snprintf(buf, buflen, "IPC_RING_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_MSG_MBUF_POOL:
        snprintf(buf, buflen, "IPC_MPOOL_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_MSG_RING_PC_RSP:
        snprintf(buf, buflen, "IPC_RING_PCRSP_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    case IPC_MSG_RING_PC_REQ:
        snprintf(buf, buflen, "IPC_RING_PCREQ_S%dP%dQ%d",
                sock_id, instance->port, qid);
        break;
    default:
        break;
    }

    return 0;
}

static int mbuf_lcore_init(Dpdk_Context_t *dpdkc, char *errbuf, size_t errlen)
{
	uint8_t i;
    unsigned sock_id = rte_socket_id();
    DpdkInstance *instance;
    char namebuf[64];

    for (instance = dpdkc->instances; instance; instance = instance->next) {
        instance->lcore_id = rte_lcore_id();

        if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
            DAQ_RTE_LOG("%s: Secondary Process\n", __func__);

            //RTE MBUF pool
            mbuf_lcore_getname(namebuf, sizeof(namebuf),
                    instance, sock_id,
                    instance->rx_queue_s, PKT_MBUF_POOL);
        	DAQ_RTE_LOG("%s: MBUFS 0x%x, CACHE_SIZE 0x%x, sock_mp %s\n",
                    __func__, NUM_MBUFS, MBUF_CACHE_SIZE, namebuf);
        	instance->mbuf_pool = rte_mempool_lookup(namebuf);
            if ( NULL == instance->mbuf_pool ) {
                snprintf(errbuf, errlen, "%s: Couldn't find pkt-mbuf pool!\n", __FUNCTION__);
                return -1;
            }

            //Internal-MSG mbuf_pool
            mbuf_lcore_getname(namebuf, sizeof(namebuf),
                    instance, sock_id,
                    instance->rx_queue_s, IPC_MSG_MBUF_POOL);
            instance->msg_pool = rte_mempool_lookup(namebuf);
            if ( NULL == instance->msg_pool ) {
                snprintf(errbuf, errlen, "%s: Couldn't find ipc-mbuf pool!\n", __FUNCTION__);
                return -1;
            }

            //Internal-MSG Ring
            mbuf_lcore_getname(namebuf, sizeof(namebuf),
                    instance, sock_id,
                    instance->rx_queue_s, IPC_MSG_RING);
            instance->rsvmsg_ring = rte_ring_lookup(namebuf);
            if ( NULL == instance->rsvmsg_ring ) {
                snprintf(errbuf, errlen, "%s: Couldn't find ipc-ring!\n", __FUNCTION__);
                return -1;
            }

            //Internal-MSG Ring-to packet count
            mbuf_lcore_getname(namebuf, sizeof(namebuf),
                    instance, sock_id,
                    instance->rx_queue_s, IPC_MSG_RING_PC_REQ);
            instance->msg_ring_pc_req = rte_ring_lookup(namebuf);
            if ( NULL == instance->msg_ring_pc_req ) {
                snprintf(errbuf, errlen, "%s: Couldn't find ipc-mbuf pool!\n", __FUNCTION__);
                return -1;
            }

            //Internal-MSG Ring-to count handler
            mbuf_lcore_getname(namebuf, sizeof(namebuf),
                    instance, sock_id,
                    instance->rx_queue_s, IPC_MSG_RING_PC_RSP);
            instance->msg_ring_pc_rsp = rte_ring_lookup(namebuf);
            if ( NULL == instance->msg_ring_pc_rsp ) {
                snprintf(errbuf, errlen, "%s: Couldn't find ipc-mbuf pool!\n", __FUNCTION__);
                return -1;
            }
        }
        else {
            DAQ_RTE_LOG("%s: Primary Process\n", __func__);

            for (i=0; i<instance->n_rx_queue; i++) {
                sock_id = rte_lcore_to_socket_id(i);

                //RTE MBUF pool
                mbuf_lcore_getname(namebuf, sizeof(namebuf),
                        instance, sock_id,
                        i, PKT_MBUF_POOL);
                DAQ_RTE_LOG("%s: MBUFS 0x%x, CACHE_SIZE 0x%x, sock_mp %s\n",
                        __func__, NUM_MBUFS, MBUF_CACHE_SIZE, namebuf);
                instance->mbuf_pools[i] = rte_pktmbuf_pool_create(namebuf, NUM_MBUFS,
                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, sock_id);//rte_socket_id());
                if ( NULL == instance->mbuf_pools[i] ) {
                    snprintf(errbuf, errlen, "%s: Couldn't create pkt-mbuf pool!\n", __FUNCTION__);
                    return -1;
                }

                //Internal-MSG mbuf_pool
                mbuf_lcore_getname(namebuf, sizeof(namebuf),
                        instance, sock_id,
                        i, IPC_MSG_MBUF_POOL);
                instance->ipc_msg_pools[i] = rte_mempool_create(namebuf,
                        DAQ_DPDK_RING_MSG_POOL_SIZE,
                        DAQ_DPDK_RING_MSG_DATA_LEN,
                        DAQ_DPDK_RING_MSG_POOL_CACHE,
                        DAQ_DPDK_RING_MSG_PRIVATE_DATA_LEN,
                        NULL, NULL, NULL, NULL,
                        sock_id, 0);
                if ( NULL == instance->ipc_msg_pools[i] ) {
                    snprintf(errbuf, errlen, "%s: Couldn't create ipc-mbuf pool!\n", __FUNCTION__);
                    return -1;
                }

                if ( i == instance->rx_queue_s ) {
                    instance->mbuf_pool = instance->mbuf_pools[i];
                    instance->msg_pool = instance->ipc_msg_pools[i];
                }
                else {
                    //Internal-MSG Ring
                    mbuf_lcore_getname(namebuf, sizeof(namebuf),
                            instance, sock_id,
                            i, IPC_MSG_RING);
                    instance->ipc_msg_rings[i] = rte_ring_create(namebuf,
                            DAQ_DPDK_RING_MSG_QUEUE_SIZE,
                            sock_id,
                            RING_F_SP_ENQ | RING_F_SC_DEQ);
                    if ( NULL == instance->ipc_msg_rings[i] ) {
                        snprintf(errbuf, errlen, "%s: Couldn't create ipc-ring!\n", __FUNCTION__);
                        return -1;
                    }
                }

                //Internal-MSG Ring-to packet count
                mbuf_lcore_getname(namebuf, sizeof(namebuf),
                        instance, sock_id,
                        i, IPC_MSG_RING_PC_REQ);
                instance->msg_ring_pc_req = rte_ring_create(namebuf,
                        DAQ_DPDK_RING_MSG_QUEUE_SIZE,
                        sock_id,
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
                if ( NULL == instance->msg_ring_pc_req ) {
                    snprintf(errbuf, errlen, "%s: Couldn't create ipc-ring!\n", __FUNCTION__);
                    return -1;
                }

                //Internal-MSG Ring-to count handler
                mbuf_lcore_getname(namebuf, sizeof(namebuf),
                        instance, sock_id,
                        i, IPC_MSG_RING_PC_RSP);
                instance->msg_ring_pc_rsp = rte_ring_create(namebuf,
                        DAQ_DPDK_RING_MSG_QUEUE_SIZE,
                        sock_id,
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
                if ( NULL == instance->msg_ring_pc_rsp ) {
                    snprintf(errbuf, errlen, "%s: Couldn't create ipc-ring!\n", __FUNCTION__);
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int start_instance(Dpdk_Context_t *dpdkc, DpdkInstance *instance)
{
    unsigned sock_id;
    int rx_rings = RX_RING_NUM, tx_rings = TX_RING_NUM;
    int port, queue, ret;
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info info;

    port = instance->port;
    rx_rings = instance->n_rx_queue;
    tx_rings = instance->n_tx_queue;

    DAQ_RTE_LOG("%s: port %d, RX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
    		__func__, port, instance->rx_queue_s, instance->rx_queue_e,
    		rx_rings, RX_RING_SIZE);
    DAQ_RTE_LOG("%s: port %d, TX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
    		__func__, port, instance->tx_queue_s, instance->tx_queue_e,
    		tx_rings, RX_RING_SIZE);

    if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
        DAQ_RTE_LOG("%s: Secondary process, No Configuration of RTE_ETH\n",
                __func__);
        return DAQ_SUCCESS;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        DPE(dpdkc->errbuf, "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    rte_eth_dev_info_get(port, &info);
    info.default_rxconf.rx_drop_en = 1;
    info.default_rxconf.rx_thresh.pthresh = 16;
    info.default_rxconf.rx_thresh.hthresh = 16;
    DAQ_RTE_LOG("%s: RX-- Initialing port %d with config: rx_thresh.pthresh %d, "
            "rx_thresh.hthresh %d, rx_thresh.wthresh %d, "
            "rx_free_thresh %d, rx_deferred_start %d\n", __func__, port,
            info.default_rxconf.rx_thresh.pthresh,
            info.default_rxconf.rx_thresh.hthresh,
            info.default_rxconf.rx_thresh.wthresh,
            info.default_rxconf.rx_free_thresh,
            info.default_rxconf.rx_deferred_start);
    for (queue = 0; queue < rx_rings; queue++) {
        sock_id = rte_lcore_to_socket_id(queue);
        DAQ_RTE_LOG("%s: queue %d, ring_size %d, sock_id %d\n",
                __func__, queue, RX_RING_SIZE, sock_id);
        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                &info.default_rxconf,
                instance->mbuf_pools[queue]);
        if (ret != 0) {
            DPE(dpdkc->errbuf, "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    for (queue = 0; queue < tx_rings; queue++) {
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                NULL);
        if (ret != 0) {
            DPE(dpdkc->errbuf, "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    ret = rte_eth_dev_start(instance->port);
    if (ret != 0) {
        DPE(dpdkc->errbuf, "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    //port_rss_hash_conf_show(instance->port, "ipv4", 1);

    instance->flags |= DPDKINST_STARTED;

    if (dpdkc->promisc_flag)
        rte_eth_promiscuous_enable(instance->port);

    return DAQ_SUCCESS;
}

static int dpdk_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    Dpdk_Context_t *dpdkc;
    DAQ_Dict *entry;
    int ports;
    int ret, rval = DAQ_ERROR;
    char *dpdk_args = NULL;
    char *dpdk_c_args = NULL;
    char *argv[MAX_ARGS + 1];
    int argc;
    char argv0[] = "surveyor";
    char dpdk_args_cap[64];

    //RTE LOG LEVEL
    if ( config->flags & DAQ_CFG_SYSLOG ) {
        daq_dpdk_log_daemon = 1;
    }

    dpdkc = calloc(1, sizeof(Dpdk_Context_t));
    if (!dpdkc) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->device = strdup(config->name);
    if (!dpdkc->device) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->snaplen = config->snaplen;
    dpdkc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    dpdkc->promisc_flag = (config->flags & DAQ_CFG_PROMISC);

    dpdkc->proc_type = RTE_PROC_INVALID;

#ifdef DAQ_DPDK_POWER_CTL
    dpdkc->power_heurs = &power_track;
#endif

    /* Interface */
    if ( parse_interface(config, dpdkc, errbuf, errlen) ) {
        goto err;
    }

    /* definitely set queue 0 as primary lcore */
    if ( dpdkc->rx_ins->rx_queue_s > 0 ) {
#ifdef DAQ_DPDK_POWER_CTL
        sleep(DAQ_DPDK_SECONDARY_INIT_DELAY);
        if ( epfd_wait_get(dpdkc) ) {
        	snprintf(errbuf, errlen, "%s: Get epfd from primary lcore failed!", __FUNCTION__);
            goto err;
        }
#else
        sleep(DAQ_DPDK_SECONDARY_INIT_DELAY+((dpdkc->rx_ins->rx_queue_s)<<1));
#endif
    }
    else {
    	//epfd ipc communication
    	epfd_unlink_all(dpdkc->rx_ins);
    }

    /* Import the DPDK arguments */
    for (entry = config->values; entry; entry = entry->next) {
        if ( !strcmp(entry->key, "dpdk_args") )
            dpdk_args = entry->value;
        else if ( !strcmp(entry->key, "dpdk_c_args") )
            dpdk_c_args = entry->value;
    }

    if (!dpdk_args || !dpdk_c_args) {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    snprintf(dpdk_args_cap, sizeof(dpdk_args_cap), "-c %s %s", dpdk_c_args, dpdk_args);
    argv[0] = argv0;
    argc = parse_args(dpdk_args_cap, &argv[1]) + 1;
    optind = 1;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    ports = rte_eth_dev_count();
    if (ports == 0) {
        snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
        rval = DAQ_ERROR_NODEV;
        goto err;
    }

    if (dpdkc->intf_count > ports) {
        snprintf(errbuf, errlen, "%s: Using more than %d interfaces is not valid!",
                 __FUNCTION__, ports);
        goto err;
    }

    RTE_LOG(INFO, EAL, "%s: Processing port %d queue %d\n",
    		__func__, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);

    //RTE LOG LEVEL
    if ( config->flags & DAQ_CFG_SYSLOG ) {
    	rte_set_log_level(RTE_LOG_NOTICE);
    }

    //DPDK proc-type
    dpdkc->proc_type = rte_eal_process_type();

    //DPDK mbuf initialize
    if ( mbuf_lcore_init(dpdkc, errbuf, errlen) ){
        goto err;
    }

    /* Initialize other default configuration values. */
    dpdkc->debug = 0;

    /* Import the configuration dictionary requests. */
    for (entry = config->values; entry; entry = entry->next) {
        if (!strcmp(entry->key, "debug"))
            dpdkc->debug = 1;
    }

    dpdkc->state = DAQ_STATE_INITIALIZED;

    //DAQ HEADER Struct
    daqhdr.cts = 0;
    daqhdr.egress_index = DAQ_PKTHDR_UNKNOWN;
    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.flags = 0;
    daqhdr.opaque = 0;
    daqhdr.priv_ptr = NULL;
    daqhdr.address_space_id = 0;

    *ctxt_ptr = dpdkc;
    return DAQ_SUCCESS;

err:
    if (dpdkc) {
    	destroy_dpdkc(dpdkc);
        if (dpdkc->device)
            free(dpdkc->device);
        free(dpdkc);
    }
    return rval;
}

static void dpdk_daq_reset_stats(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    memset(&dpdkc->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdk_daq_set_filter(void *handle, const char *filter)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    struct sfbpf_program fcode;

    if (dpdkc->filter)
        free(dpdkc->filter);

    dpdkc->filter = strdup(filter);
    if (!dpdkc->filter)
    {
        DPE(dpdkc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dpdkc->snaplen, DLT_EN10MB, &fcode, dpdkc->filter, 1, 0) < 0)
    {
        DPE(dpdkc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dpdkc->fcode);
    dpdkc->fcode.bf_len = fcode.bf_len;
    dpdkc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

//Response Pkt Count Filter
static int dpdk_daq_pc_filter_rsp(void *handle, const void *pc_data, int datalen, DAQ_Set_PktCnt_Filter filter_cb)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance = dpdkc->rx_ins;
    void *msg;
    pktcnt_msg *pc_msg;
    pktcnt_msg pc_msg_rsp;
    int ret, ret_type;

    ret_type = DAQ_PKTCNT_OP_NONE;

    //Get retrieve data msg
    if (rte_ring_dequeue(instance->msg_ring_pc_req, &msg) < 0) {
        return ret_type;
    }

    pc_msg = (pktcnt_msg*)msg;

    DAQ_RTE_LOG_DEEP("%s: Get pc req(%d) in queue[%d] process...\n",
            __func__, pc_msg->msg_type, instance->rx_queue_s);

    switch (pc_msg->msg_type) {
    case DAQ_PC_GET_DATA:
        //Transfer Data
        rte_memcpy(pc_msg->msg_ptr, pc_data, datalen);
        pc_msg_rsp.rtn = 0;
        pc_msg_rsp.msg_type = DAQ_PC_GET_DATA_RTN;
        ret_type = DAQ_PKTCNT_OP_DATA;
        break;
    case DAQ_PC_SET_FILTER:
        //Save Config
        pc_msg_rsp.rtn = filter_cb(pc_msg->msg_ptr);
        pc_msg_rsp.msg_type = DAQ_PC_SET_FILTER_RTN;
        ret_type = DAQ_PKTCNT_OP_SET;
        break;
    default:
        pc_msg_rsp.rtn = 0;
        pc_msg_rsp.msg_type = DAQ_PC_FILTER_INVALID_RTN;
        ret_type = DAQ_PKTCNT_OP_NONE;
        break;
    }

    rte_mempool_put(instance->msg_pool, msg);

    //Send data
    if ( DAQ_PC_GET_DATA_RTN == pc_msg_rsp.msg_type ) {
        DAQ_RTE_LOG_DEEP("%s: pc req done in queue[%d] process, send rsp--(%d)\n",
                __func__, instance->rx_queue_s, pc_msg_rsp.msg_type);

        //Send confirm msg to handler
        if (rte_mempool_get(instance->msg_pool, &msg) < 0)
            rte_panic("Failed to get message buffer\n");
        rte_memcpy(msg, &pc_msg_rsp, sizeof(pc_msg_rsp));

        ret = rte_ring_enqueue(instance->msg_ring_pc_rsp, msg);
        if ( -ENOBUFS == ret ) {
            DAQ_RTE_LOG("%s: ring full for msg in queue[%d] process\n", __func__, instance->rx_queue_s);
            rte_mempool_put(instance->msg_pool, msg);
        }
        else if ( -EDQUOT == ret ) {
            DAQ_RTE_LOG("%s: Quota exceeded msg in queue[%d] process\n", __func__, instance->rx_queue_s);
        }
    }

    return ret_type;
}

//Request Pkt Count Filter
static int dpdk_daq_pc_filter_req(void *handle, void *filter_ptr, daq_pc_filter_req_type req_type)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance = dpdkc->rx_ins;
    void *msg;
    pktcnt_msg *pc_msg;
    DAQ_Filter_Config *df_cfg;
    int ret;

    if ( DAQ_STATE_STARTED != dpdkc->state )
        return DAQ_PKTCNT_OP_NONE;

    //Preparing Message
    if (rte_mempool_get(instance->msg_pool, &msg) < 0)
        rte_panic("Failed to get message buffer\n");

    pc_msg = (pktcnt_msg*)msg;

    switch ( req_type ) {
    case DAQ_PC_GET_DATA:
        pc_msg->msg_type = req_type;
        pc_msg->msg_ptr = filter_ptr;
        break;
    case DAQ_PC_SET_FILTER:
        pc_msg->msg_type = req_type;
        pc_msg->msg_ptr = msg + sizeof(pktcnt_msg);

        df_cfg = (DAQ_Filter_Config*)filter_ptr;
        rte_memcpy(pc_msg->msg_ptr, filter_ptr,
                (long)offsetof(DAQ_Filter_Config, content)+df_cfg->config_size);//, sizeof(DAQ_Filter_Config));
        DAQ_RTE_LOG_DEEP("%s: save filter config, len %d\n", __func__,
                (long)offsetof(DAQ_Filter_Config, content)+df_cfg->config_size);
        break;
    default:
        return DAQ_PKTCNT_OP_NONE;
        break;
    }

    DAQ_RTE_LOG_DEEP("%s: send pc req(%d) in queue[%d] process\n",
            __func__, pc_msg->msg_type, instance->rx_queue_s);

    ret = rte_ring_enqueue(instance->msg_ring_pc_req, msg);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG("%s: ring full for msg in queue[%d] process\n", __func__, instance->rx_queue_s);
        rte_mempool_put(instance->msg_pool, msg);
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG("%s: Quota exceeded msg in queue[%d] process\n", __func__, instance->rx_queue_s);
    }

    //Signal to main thread
    pthread_kill(instance->tid, SIGCONT);

    ret = 0;
    if ( DAQ_PC_GET_DATA == req_type ) {
        //Wait data back
        do {
            if (rte_ring_dequeue(instance->msg_ring_pc_rsp, &msg) < 0){
                usleep(100);
            }
            else{
                DAQ_RTE_LOG_DEEP("%s: get pc rsp--(%d) in queue[%d] process\n",
                        __func__, ((pktcnt_msg*)msg)->msg_type, instance->rx_queue_s);
                ret = ((pktcnt_msg*)msg)->rtn;
                rte_mempool_put(instance->msg_pool, msg);
                break;
            }
        } while(1);
    }

    return ret;
}

static int dpdk_daq_start(void *handle)
{
    int ret;
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;

    for (instance = dpdkc->instances; instance; instance = instance->next) {
        if (start_instance(dpdkc, instance) != DAQ_SUCCESS)
            return DAQ_ERROR;
    }

    if ( NULL != dpdkc->rx_ins ) {
        //port stats lcore available
        if ( rte_lcore_count()>0 ) {
            unsigned slaveid = rte_get_next_lcore(dpdkc->rx_ins->lcore_id, 0, 0);
            if ( RTE_MAX_LCORE != slaveid ) {
                ret = rte_eal_remote_launch(sys_ifinfo, dpdkc, slaveid);
                if (ret != 0) {
                    RTE_LOG(ERR, EAL, "Failed to start lcore %d, return %d",
                            slaveid, ret);
                }
                else {
                    DAQ_RTE_LOG("sys_info_if_stats lunched on lcore %d\n", slaveid);
                }
            }
        }

#ifdef DAQ_DPDK_POWER_CTL
        if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
        }
        else {
            //DAQ Power/EPFD Heuristic Initialize
            if ( (ret=daq_dpdk_power_heuristic_init(dpdkc)) ) {
            	if ( 4 == ret )
            		return DAQ_HALF_EXIT;
            	return DAQ_ERROR;
            }
        }

        //Signal FD
        signalfd_register(dpdkc->rx_ins);
#endif
    }

    dpdk_daq_reset_stats(handle);

    dpdkc->state = DAQ_STATE_STARTED;

    DAQ_RTE_LOG("%s: port %d queue %d started!\n",
    		__func__, dpdkc->rx_ins->port, dpdkc->rx_ins->rx_queue_s);

    return DAQ_SUCCESS;
}

static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    EtherHdr *eh_hdr;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint8_t ether_dst[6] = {0xc8, 0x1f, 0x66, 0xdb, 0xcb, 0xd8};
    uint16_t len;
    int c = 0;//, burst_size;
    int i;
    uint32_t queue;
    struct timeval ts;
#ifdef RX_CNT_TRACK
    static uint64_t queue_cnt = 0;
    static uint64_t show_cnt = 0;
    static uint64_t fw_cnt = 0;
    struct rte_eth_link rte_link;
#endif

//    while (c < cnt || cnt <= 0)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
//        struct rte_mbuf *m_send;
//        uint16_t nb_tx;

#ifdef DAQ_DPDK_POWER_CTL
        daq_dpdk_power_preheuris(rte_rdtsc());
#endif

        for (instance = dpdkc->instances; instance; instance = instance->next) {
            /* Has breakloop() been called? */
            if ( unlikely( dpdkc->break_loop ) ) {
                RTE_LOG(INFO, EAL, "Exiting from Dpdk Context\n");
                dpdkc->break_loop = 0;
                return 0;
            }

            if ( unlikely( instance->break_loop ) ) {
                RTE_LOG(INFO, EAL, "Exiting from Instance\n");
                instance->break_loop = 0;
                return DAQ_READFILE_EOF;//DAQ_USER_INT_EXIT;
            }

            for (queue = instance->rx_queue_s; queue < instance->rx_queue_e; queue++) {
                //gettimeofday(&ts, NULL);
                ts.tv_sec = time(NULL);//daqhdr.cts
                ts.tv_usec = 0;

                //burst_size = BURST_SIZE;

                const uint16_t nb_rx =
                    rte_eth_rx_burst(instance->port, queue,
                            bufs, BURST_SIZE);

#ifdef RX_CNT_TRACK
                if ( unlikely(show_cnt++ & 0x1000000) ) {
                    nic_xstats_display(instance->port);
                    //nic_stats_display(instance->port);
                    show_cnt = 0;
                    rte_eth_link_get_nowait(instance->port, &rte_link);
                    printf("Queue %d Rx Counts: %"PRIu64", link state %d\n",
                            queue, queue_cnt, rte_link.link_status);
                }
#endif

#ifdef DAQ_DPDK_POWER_CTL
                //tag queue state, busy/little/idle
                daq_dpdk_power_heuris(dpdkc->rx_ins, queue, nb_rx);
#endif

                if (unlikely(nb_rx == 0))
                    continue;

#ifdef RX_CNT_TRACK
                queue_cnt += nb_rx;
#endif

                rte_prefetch0(rte_pktmbuf_mtod(bufs[0], void *));

                for (i = 0; i < nb_rx; i++) {
                    verdict = DAQ_VERDICT_PASS;

                    if ((bufs[i]->ol_flags & PKT_RX_IP_CKSUM_BAD) != 0) {
#ifdef RX_CSUM_TRACK
                        printf("%s: ip cksum error\n", __func__);
#endif
                        rte_pktmbuf_free(bufs[i]);
                        continue;
                    }
                    else if ((bufs[i]->ol_flags & PKT_RX_L4_CKSUM_BAD) != 0){
#ifdef RX_CSUM_TRACK
                        printf("%s: tcp cksum error\n", __func__);
#endif
                        rte_pktmbuf_free(bufs[i]);
                        continue;
                    }

                    data = rte_pktmbuf_mtod(bufs[i], void *);
                    len = rte_pktmbuf_data_len(bufs[i]);

                    dpdkc->stats.hw_packets_received++;
                    daqhdr.ts = ts;
                    daqhdr.caplen = len;
                    daqhdr.pktlen = len;
                    daqhdr.ingress_index = instance->index;

#ifdef RX_CNT_TRACK_HASH
                    printf("p_toeplitz_hash 0x%x\n", bufs[i]->hash.rss);
#endif

                    if (likely(i < nb_rx - 1)) {
                        rte_prefetch0(rte_pktmbuf_mtod(bufs[i+1], void *));
                    }

                    if ( likely(NULL!=callback) ) {
                        verdict = callback(user, &daqhdr, data);
                        if (verdict >= MAX_DAQ_VERDICT)
                            verdict = DAQ_VERDICT_PASS;
                        dpdkc->stats.verdicts[verdict]++;
                        verdict = verdict_translation_table[verdict];
                    }
                    dpdkc->stats.packets_received++;
                    c++;

                    //dst_mac:c8:1f:66:db:cb:d8
                    if ( unlikely(NULL != Send_Instance) ) {
                        eh_hdr = (EtherHdr *)data;
                        if ( memcmp(eh_hdr->ether_dst, ether_dst, 6) ) {
                        /*    m_send = rte_pktmbuf_alloc(Send_Instance->mbuf_pool);
                            if (!m_send) {
                                printf("%s: Couldn't allocate memory for packet.",
                                        __FUNCTION__);
                            }
                            else {
                                rte_memcpy(rte_pktmbuf_mtod(m_send, void *), data, len);
                                m_send->pkt_len  = len;
                                m_send->data_len = len;
                                nb_tx = rte_eth_tx_burst(Send_Instance->port, 0, &m_send, 1);
                                if (unlikely(nb_tx == 0)) {
                                    printf("%s: Couldn't send packet. Try again.", __FUNCTION__);
                                    rte_pktmbuf_free(m_send);
                                }
                                fw_cnt++;
                            }*/

                            //printf("%s: dirty pkt, fw_cnt %"PRIu64"\n", __func__, ++fw_cnt);
                            rte_eth_tx_burst(Send_Instance->port, 0, &bufs[i], 1);
                        }
                    }

                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }

#ifdef DAQ_DPDK_POWER_CTL
        daq_dpdk_power_heurissum(dpdkc->rx_ins);
#endif

        if ( RTE_PROC_SECONDARY == dpdkc->proc_type ) {
            if ( unlikely( ts.tv_sec > (daqhdr.cts+1) ) ) {
                daqhdr.cts = ts.tv_sec;
                if ( daq_dpdk_secondary_recv(dpdkc->rx_ins) ) {
                    if ( dpdkc->mulp_sync_count++ > DAQ_DPDK_RING_MSG_TOLERATE ) {
                        DAQ_RTE_LOG("%s: primary msg lost touch, exit daq_aquire!\n",
                                __func__);
                        return DAQ_READFILE_EOF;
                    }
                }

                DAQ_RTE_LOG_DEEP("%s: check primary msg: cts %lu, loss count %d\n", __func__,
                        daqhdr.cts, dpdkc->mulp_sync_count);
            }
        }

        return 0;
    }

    return 0;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;

    struct rte_mbuf *m;

    /* Find the instance that the packet was received on. */
    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (instance->index == hdr->ingress_index)
            break;
    }

    if (!instance)
    {
        DPE(dpdkc->errbuf, "%s: Unrecognized ingress interface specified: %u",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    if (!reverse && !(instance = instance->peer))
    {
        DPE(dpdkc->errbuf, "%s: Specified ingress interface (%u) has no peer for forward injection.",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    m = rte_pktmbuf_alloc(instance->mbuf_pool);
    if (!m)
    {
        DPE(dpdkc->errbuf, "%s: Couldn't allocate memory for packet.",
                __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }

    rte_memcpy(rte_pktmbuf_mtod(m, void *), packet_data, len);

    const uint16_t nb_tx = rte_eth_tx_burst(instance->port, 0, &m, 1);

    if (unlikely(nb_tx == 0))
    {
        DPE(dpdkc->errbuf, "%s: Couldn't send packet. Try again.", __FUNCTION__);
        rte_pktmbuf_free(m);
        return DAQ_ERROR_AGAIN;
    }

    return DAQ_SUCCESS;
}

static int dpdk_daq_breakloop(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    dpdkc->break_loop = 1;

    return DAQ_SUCCESS;
}

static int dpdk_daq_stop(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    destroy_dpdkc(dpdkc);

    return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    destroy_dpdkc(dpdkc);
    if (dpdkc->device)
        free(dpdkc->device);
    if (dpdkc->filter)
        free(dpdkc->filter);
    free(dpdkc);
}

static DAQ_State dpdk_daq_check_status(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    return dpdkc->state;
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    rte_memcpy(stats, &dpdkc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static int dpdk_daq_get_snaplen(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    return dpdkc->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
        DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
        DAQ_CAPA_DEVICE_INDEX;
}

static int dpdk_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *dpdk_daq_get_errbuf(void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    return dpdkc->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

    if (!string)
        return;

    DPE(dpdkc->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *device)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    int port;

    if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
        return DAQ_ERROR_NODEV;

    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (instance->port == port)
            return instance->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_API_VERSION,
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */ dpdk_daq_initialize,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .rsp_pc_filter = */ dpdk_daq_pc_filter_rsp,
    /* .req_pc_filter = */ dpdk_daq_pc_filter_req,
    /* .start = */ dpdk_daq_start,
    /* .acquire = */ dpdk_daq_acquire,
    /* .inject = */ dpdk_daq_inject,
    /* .breakloop = */ dpdk_daq_breakloop,
    /* .stop = */ dpdk_daq_stop,
    /* .shutdown = */ dpdk_daq_shutdown,
    /* .check_status = */ dpdk_daq_check_status,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .get_errbuf = */ dpdk_daq_get_errbuf,
    /* .set_errbuf = */ dpdk_daq_set_errbuf,
    /* .get_device_index = */ dpdk_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL
};

