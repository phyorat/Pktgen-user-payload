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

static uint8_t rss_intel_key[40] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
        0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
        0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
        0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, };

static const struct rte_eth_conf port_conf_default = { .rxmode = { .mq_mode =
        ETH_MQ_RX_RSS, .split_hdr_size = 0, .header_split = 0, /**< Header Split disabled */
.hw_ip_checksum = 1, /**< IP checksum offload enabled */
.hw_vlan_filter = 0, /**< VLAN filtering disabled */
.jumbo_frame = 0, /**< Jumbo Frame Support disabled */
.hw_strip_crc = 0, /**< CRC stripped by hardware */
}, .rx_adv_conf = { .rss_conf = { .rss_key = rss_intel_key, .rss_hf =
        ETH_RSS_PROTO_MASK, }, }, .txmode = { .mq_mode = ETH_MQ_TX_NONE, }, };

pthread_mutex_t g_Dpdk_mutex;
Dpdk_Context_t *g_Dpdk_Ctx;

static int dpdk_init_rings_rx(Dpdk_Context_t *);
static void dpdk_daq_reset_stats(void *handle);
static int dpdk_daq_acquire(__attribute__((unused)) void *arg);

#ifdef RX_CNT_TRACK_PRINT
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

    for (i = 0; i < len; i++)
    printf("%s: %"PRIu64"\n",
            xstats_names[i].name,
            xstats[i].value);

    printf("%s############################\n",
            nic_stats_border);
    err:
    free(xstats);
    free(xstats_names);
}
#endif

static const struct rss_type_info rss_type_table[] = { { "ipv4", ETH_RSS_IPV4 },
        { "ipv4-frag", ETH_RSS_FRAG_IPV4 }, { "ipv4-tcp",
                ETH_RSS_NONFRAG_IPV4_TCP }, { "ipv4-udp",
                ETH_RSS_NONFRAG_IPV4_UDP }, { "ipv4-sctp",
                ETH_RSS_NONFRAG_IPV4_SCTP }, { "ipv4-other",
                ETH_RSS_NONFRAG_IPV4_OTHER }, { "ipv6", ETH_RSS_IPV6 }, {
                "ipv6-frag", ETH_RSS_FRAG_IPV6 }, { "ipv6-tcp",
                ETH_RSS_NONFRAG_IPV6_TCP }, { "ipv6-udp",
                ETH_RSS_NONFRAG_IPV6_UDP }, { "ipv6-sctp",
                ETH_RSS_NONFRAG_IPV6_SCTP }, { "ipv6-other",
                ETH_RSS_NONFRAG_IPV6_OTHER },
        { "l2-payload", ETH_RSS_L2_PAYLOAD }, { "ipv6-ex", ETH_RSS_IPV6_EX }, {
                "ipv6-tcp-ex", ETH_RSS_IPV6_TCP_EX }, { "ipv6-udp-ex",
                ETH_RSS_IPV6_UDP_EX }, { "port", ETH_RSS_PORT }, { "vxlan",
                ETH_RSS_VXLAN }, { "geneve", ETH_RSS_GENEVE }, { "nvgre",
                ETH_RSS_NVGRE }, };

void port_rss_hash_conf_show(portid_t port_id, const char rss_info[],
        int show_rss_key) {
#define RSS_HASH_KEY_LENGTH 64
    struct rte_eth_rss_conf rss_conf;
    uint8_t rss_key[RSS_HASH_KEY_LENGTH];
    uint64_t rss_hf;
    uint8_t i;
    int diag;
    struct rte_eth_dev_info dev_info;
    uint8_t hash_key_size;

    if (0) //port_id_is_invalid(port_id, ENABLED_WARN))
        return;

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    if (dev_info.hash_key_size > 0 && dev_info.hash_key_size <= sizeof(rss_key))
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
    RTE_LOG(INFO, EAL, "RSS functions:\n ");
    for (i = 0; i < RTE_DIM(rss_type_table); i++) {
        if (rss_hf & rss_type_table[i].rss_type)
            printf("%s ", rss_type_table[i].str);
    }
    printf("\n");
    if (!show_rss_key)
        return;
    RTE_LOG(INFO, EAL, "RSS key:\n");
    for (i = 0; i < hash_key_size; i++)
        printf("%02X", rss_key[i]);
    printf("\n\n");
}

static int get_numa_node_num(void)
{
    char buf[128];
    int i = 0;

    do {
        snprintf(buf, sizeof(buf), "/sys/devices/system/node/node%d/hugepages/"
                "hugepages-2048kB/nr_hugepages", i);
        if( access( buf, F_OK ) != -1 ) {
            printf ("%s: node%d exists\n", __func__, i);
        }
        else {
            printf ("%s: node%d not exists\n", __func__, i);
            break;
        }

        i++;
    }while(1);

    return i;
}

static int start_instance(Dpdk_Context_t *dpdkc, DpdkInstance *instance) {
    unsigned sock_id, sock_num;
    int rx_rings = RX_RING_NUM, tx_rings = TX_RING_NUM;
    struct rte_eth_conf port_conf = port_conf_default;
    int port, queue, ret;
    struct rte_eth_dev_info info;
    static rte_atomic32_t run_once = RTE_ATOMIC32_INIT(0);

    instance->flags |= DPDKINST_STARTED;
    if (!rte_atomic32_test_and_set(&run_once)) {
        printf("%s: slave thread(%d), port already started\n", __func__,
                instance->index);
        return DAQ_SUCCESS;
    }

    port = dpdkc->port;
    rx_rings = dpdkc->rx.queue_num;
    tx_rings = dpdkc->tx.queue_num;

    RTE_LOG(INFO, EAL,
            "%s: RX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n", __func__, dpdkc->rx.queue_s, dpdkc->rx.queue_e, dpdkc->rx.queue_num, RX_RING_SIZE);
    /*    RTE_LOG(INFO, EAL, "%s: TX-- q_start %d, q_end %d, q_all %d, ring_sizes %d\n",
     __func__, dpdkc->tx.queue_s, dpdkc->tx.queue_e,
     dpdkc->tx.queue_num, RX_RING_SIZE);*/

    if (RTE_PROC_SECONDARY == dpdkc->proc_type) {
        RTE_LOG(INFO, EAL,
                "%s: Secondary process, No Configuration of RTE_ETH\n", __func__);
        return DAQ_SUCCESS;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        DPE(dpdkc->errbuf,
                "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    sock_num = get_numa_node_num();
    if ( !sock_num )
        return DAQ_ERROR;
    else if ( sock_num > NUMA_MAX_SOC_NUM )
        sock_num = NUMA_MAX_SOC_NUM;

    rte_eth_dev_info_get(port, &info);
    info.default_rxconf.rx_drop_en = 1;
    RTE_LOG(INFO, EAL,
            "%s: RX-- Initialing port %d with config: rx_thresh.pthresh %d, "
            "rx_thresh.hthresh %d, rx_thresh.wthresh %d, "
            "rx_free_thresh %d, rx_deferred_start %d\n", __func__, port, info.default_rxconf.rx_thresh.pthresh, info.default_rxconf.rx_thresh.pthresh, info.default_rxconf.rx_thresh.pthresh, info.default_rxconf.rx_free_thresh, info.default_rxconf.rx_deferred_start);
    for (queue = 0; queue < rx_rings; queue++) {
        sock_id = (queue & (sock_num - 1));

        RTE_LOG(INFO, EAL,
                "%s: queue %d, ring_size %d, sock_id %d\n", __func__, queue, RX_RING_SIZE, sock_id);

        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,
                rte_eth_dev_socket_id(port), &info.default_rxconf,
                dpdkc->mbuf_pools[sock_id]);
        if (ret != 0) {
            DPE(dpdkc->errbuf,
                    "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    for (queue = 0; queue < tx_rings; queue++) {
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (ret != 0) {
            DPE(dpdkc->errbuf,
                    "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    ret = rte_eth_dev_start(dpdkc->port);
    if (ret != 0) {
        DPE(dpdkc->errbuf,
                "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }

    port_rss_hash_conf_show(dpdkc->port, "ipv4", 1);

    if (dpdkc->promisc_flag)
        rte_eth_promiscuous_enable(dpdkc->port);

    return DAQ_SUCCESS;
}

static void destroy_instance(DpdkInstance *instance) {
    int i;

    if (instance) {
        if (instance->flags & DPDKINST_STARTED) {
            for (i = instance->tx.start; i < instance->tx.end; i++)
                rte_pktmbuf_free(instance->tx.burst[i]);

            instance->flags &= ~DPDKINST_STARTED;
        }

        free(instance);
    }
}

static DpdkInstance *dpdk_instance_new(Dpdk_Context_t *dpdkc, char *errbuf,
        size_t errlen) {
    int ring_idx;
    DpdkInstance *instance;

    instance = calloc(1, sizeof(DpdkInstance));
    if (!instance) {
        snprintf(errbuf, errlen,
                "%s: Couldn't allocate a new instance structure.",
                __FUNCTION__);
        goto err;
    }

    memset(instance, 0, sizeof(DpdkInstance));

    //Initialize Ring For This thread
    ring_idx = dpdk_init_rings_rx(dpdkc);
    dpdkc->rx.ring_tid_map[ring_idx] = pthread_self();
    instance->index = ring_idx;
    instance->rx.ring_in = dpdkc->rx.rings[ring_idx];
    instance->rx.queue = dpdkc->rx.queue_s;

    return instance;
    err: destroy_instance(instance);
    return NULL;
}

static int dpdk_intf_init(const char *device, Dpdk_Context_t *dpdkc,
        char *errbuf, size_t errlen) {

    int port, queue = 0, q_step = 1, queue_cnt = 1;

    if (strncmp(device, "dpdk", 4) != 0
            || sscanf(&device[4], "%d", &port) != 1) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                __FUNCTION__, device);
        return DAQ_ERROR;
    }

    dpdkc->port = port;

    if (strlen(device) > 8) {
        if ('#' == *(device + 5) && 0 < sscanf(device + 6, "%d", &queue_cnt)) {
            RTE_LOG(INFO, EAL,
                    "%s: Use Rx Queue on Port %d, Total %d...\n", __FUNCTION__, port, queue_cnt);
        } else {
            snprintf(errbuf, errlen,
                    "%s: Invalid interface queue_cnt specification: '%s'!",
                    __FUNCTION__, device);
            return DAQ_ERROR;
        }

        if ('@' == *(device + 7) && 0 < sscanf(device + 8, "%d", &queue)) {
            RTE_LOG(INFO, EAL,
                    "%s: Use Rx Queue %d on Port %d, Total %d...\n", __FUNCTION__, queue, port, queue_cnt);
            q_step = 1;
        } else {
            snprintf(errbuf, errlen,
                    "%s: Invalid interface queue_cnt specification: '%s'!",
                    __FUNCTION__, device);
            return DAQ_ERROR;
        }
    }

    dpdkc->rx.queue_s = queue;
    dpdkc->rx.queue_e = queue + q_step;
    dpdkc->rx.queue_num = queue_cnt;

    return DAQ_SUCCESS;
}

/*static int create_bridge(Dpdk_Context_t *dpdkc, const int port1, const int port2)
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
 }*/

static int dpdk_inst_close(DpdkInstance *instance) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;
    /*if (!dpdkc)
     return -1;*/

    /* Free all of the device instances. */
    //while ((instance = dpdkc->instances) != NULL) {
    //dpdkc->instances = instance->next;
    dpdkc->state[instance->index] = DAQ_STATE_STOPPED;
    destroy_instance(instance);
    dpdkc->inst_stat &= ~(0x01 << instance->index);

    //}

    //sfbpf_freecode(&dpdkc->fcode);

    //rte_eth_dev_stop(dpdkc->port);
    //dpdkc->state = DAQ_STATE_STOPPED;

    return 0;
}

static int parse_args(char *inputstring, char **argv) {
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;) {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}

static int dpdk_init_rings_rx(Dpdk_Context_t *dpdkc) {
    //unsigned lcore;
    int ring_idx = dpdkc->rx.n_ring;
    char name[32];
    struct rte_ring *ring = NULL;

    /* Initialize the rings for the RX side */

    if (ring_idx >= RING_MAX_NUM) {
        rte_panic("Cannot create more ring of snort_%d-%d\n", 0, ring_idx);
    }

    snprintf(name, sizeof(name), "snort_ring_rx_s%d_q%u_t%u", dpdkc->socket_io,
            dpdkc->rx.queue_s, ring_idx);
    printf("Creating ring to connect thread of %s\n", name);
    ring = rte_ring_create(name, DEFAULT_RING_RX_SIZE, dpdkc->socket_io,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ring == NULL) {
        rte_panic("Cannot create ring to connect thread of %s\n", name);
    }

    dpdkc->rx.rings[dpdkc->rx.n_ring] = ring;
    dpdkc->rx.n_ring++;

    return ring_idx;
}

static int dpdk_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr,
        char *errbuf, size_t errlen) {
    DpdkInstance *instance;
    DAQ_Dict *entry;
    char intf[IFNAMSIZ];
    int num_intfs = 0;
    //int port1, port2,
    int ports;
    size_t len;
    char *dev;
    int ret, rval = DAQ_ERROR;
    char *dpdk_args = NULL;
    char argv0[] = "surveyor";
    char *argv[MAX_ARGS + 1];
    int argc;
    char poolname[64];
    static rte_atomic32_t run_once = RTE_ATOMIC32_INIT(0);

    if (!rte_atomic32_test_and_set(&run_once)) {
        pthread_mutex_lock(&g_Dpdk_mutex);
        cpu_set_t cpuset;

        printf("%s: slave thread, acquire packet from rte_ring\n", __func__);

        instance = dpdk_instance_new(g_Dpdk_Ctx, errbuf, errlen);
        if (!instance)
            return DAQ_ERROR;

        instance->next = g_Dpdk_Ctx->instances;
        g_Dpdk_Ctx->instances = instance;
        g_Dpdk_Ctx->inst[instance->index] = instance;

        g_Dpdk_Ctx->state[instance->index] = DAQ_STATE_INITIALIZED;
        *ctxt_ptr = instance;

        instance->lcore_id = g_Dpdk_Ctx->lcore_id + (instance->index << 1);
        CPU_ZERO(&cpuset);
        CPU_SET(instance->lcore_id, &cpuset);
        RTE_LOG(INFO, EAL,
                "%s: Set slave thread %d as cpuset %d\n", __func__, instance->index, instance->lcore_id);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

        pthread_mutex_unlock(&g_Dpdk_mutex);
        return DAQ_SUCCESS;
    }

    //Mutex Lock
    pthread_mutex_init(&g_Dpdk_mutex, NULL);
    pthread_mutex_lock(&g_Dpdk_mutex);

    //Global DPDK Context
    g_Dpdk_Ctx = calloc(1, sizeof(Dpdk_Context_t));
    if (!g_Dpdk_Ctx) {
        snprintf(errbuf, errlen,
                "%s: Couldn't allocate memory for the new DPDK context!",
                __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    //Device Name
    g_Dpdk_Ctx->device = strdup(config->name);
    if (!g_Dpdk_Ctx->device) {
        snprintf(errbuf, errlen,
                "%s: Couldn't allocate memory for the device string!",
                __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    //Other DAQ Config
    g_Dpdk_Ctx->snaplen = config->snaplen;
    g_Dpdk_Ctx->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    g_Dpdk_Ctx->promisc_flag = (config->flags & DAQ_CFG_PROMISC);

    /* Import the DPDK arguments */
    for (entry = config->values; entry; entry = entry->next) {
        if (!strcmp(entry->key, "dpdk_args"))
            dpdk_args = entry->value;
    }

    if (!dpdk_args) {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    //Parse DPDK arguments
    argv[0] = argv0;
    argc = parse_args(dpdk_args, &argv[1]) + 1;
    optind = 1;

    // As EAL Parameters
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    // Ports Check
    ports = rte_eth_dev_count();
    if (ports == 0) {
        snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
        rval = DAQ_ERROR_NODEV;
        goto err;
    }

    // Interface Check
    dev = g_Dpdk_Ctx->device;
    if (*dev == ':') {
        snprintf(errbuf, errlen, "%s: Invalid interface specification1: '%s'!",
                __FUNCTION__, g_Dpdk_Ctx->device);
        goto err;
    }

    if (((len = strlen(dev)) > 0 && *(dev + len - 1) == ':')) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification2: '%s'!",
                __FUNCTION__, g_Dpdk_Ctx->device);
        goto err;
    }

    if ((config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::"))) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification3: '%s'!",
                __FUNCTION__, g_Dpdk_Ctx->device);
        goto err;
    }

    //Basic Info
    g_Dpdk_Ctx->socket_io = rte_socket_id();
    g_Dpdk_Ctx->lcore_id = rte_lcore_id();

    // Create Instance for threads
    while (*dev != '\0') {
        len = strcspn(dev, ":");
        if (len >= sizeof(intf)) {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)",
                    __FUNCTION__, len);
            goto err;
        }

        if (len != 0) {
            g_Dpdk_Ctx->intf_count++;
            if (g_Dpdk_Ctx->intf_count > ports) {
                snprintf(errbuf, errlen,
                        "%s: Using more than %d interfaces is not valid!",
                        __FUNCTION__, ports);
                goto err;
            }

            snprintf(intf, len + 1, "%s", dev);
            if (DAQ_SUCCESS
                    != dpdk_intf_init(intf, g_Dpdk_Ctx, errbuf, errlen)) {
                goto err;
            }

            instance = dpdk_instance_new(g_Dpdk_Ctx, errbuf, errlen);
            if (!instance)
                goto err;

            //Master Instance lcore_id
            instance->lcore_id = g_Dpdk_Ctx->lcore_id;

            instance->isMaster = 1;
            instance->next = g_Dpdk_Ctx->instances;
            g_Dpdk_Ctx->instances = instance;
            g_Dpdk_Ctx->inst[instance->index] = instance;
            num_intfs++;

            // Peer Mode
            if (config->mode != DAQ_MODE_PASSIVE) {
                /*                if (num_intfs == 2) {
                 port1 = g_Dpdk_Ctx->instances->next->port;
                 port2 = g_Dpdk_Ctx->instances->port;
                 if (create_bridge(g_Dpdk_Ctx, port1, port2) != DAQ_SUCCESS) {
                 snprintf(errbuf, errlen, "%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                 __FUNCTION__, port1, port2);
                 goto err;
                 }
                 num_intfs = 0;
                 }
                 else if (num_intfs > 2)
                 break;*/
            }
        } else
            len = 1;
        dev += len;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!g_Dpdk_Ctx->instances
            || (config->mode != DAQ_MODE_PASSIVE && num_intfs != 0)) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                __FUNCTION__, g_Dpdk_Ctx->device);
        goto err;
    }



    //Mem-pool Initialize, Multi-Process??
    g_Dpdk_Ctx->proc_type = rte_eal_process_type();

    //MEMBUF Initial
    if (RTE_PROC_SECONDARY == g_Dpdk_Ctx->proc_type) {
        RTE_LOG(INFO, EAL,
                "%s: Secondary Processock_id %d, lcore %d\n", __func__, g_Dpdk_Ctx->socket_io, g_Dpdk_Ctx->lcore_id);

        snprintf(poolname, sizeof(poolname), "MBUF_POOL_SOC%d",
                g_Dpdk_Ctx->socket_io);
        RTE_LOG(INFO, EAL,
                "%s: MBUFS 0x%x, CACHE_SIZE 0x%x, sock_mp %s\n", __func__, NUM_MBUFS, MBUF_CACHE_SIZE, poolname);

        g_Dpdk_Ctx->mbuf_pool = rte_mempool_lookup(poolname);

        if (NULL == g_Dpdk_Ctx->mbuf_pool) {
            snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n",
                    __FUNCTION__);
            goto err;
        }
    } else {
        unsigned sock_id;
        unsigned sock_num = get_numa_node_num();

        if ( !sock_num ) {
            snprintf(errbuf, errlen, "%s: NUMA NODE Invalid!\n", __FUNCTION__);
            goto err;
        }
        else if ( sock_num > NUMA_MAX_SOC_NUM ) {
            sock_num = NUMA_MAX_SOC_NUM;
        }

        RTE_LOG(INFO, EAL,
                "%s: Primary Process, sock_id %d, lcore %d\n", __func__, g_Dpdk_Ctx->socket_io, g_Dpdk_Ctx->lcore_id);

        for (sock_id = 0; sock_id < sock_num; sock_id++) {
            snprintf(poolname, sizeof(poolname), "MBUF_POOL_SOC%d",
                    sock_id);
            RTE_LOG(INFO, EAL,
                    "%s: MBUFS 0x%x, CACHE_SIZE 0x%x, sock_mp %s\n",
                    __func__, NUM_MBUFS, MBUF_CACHE_SIZE, poolname);

            g_Dpdk_Ctx->mbuf_pools[sock_id] = rte_pktmbuf_pool_create(poolname,
                    NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                    sock_id);

            if (NULL == g_Dpdk_Ctx->mbuf_pools[sock_id]) {
                snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n",
                        __FUNCTION__);
                goto err;
            }
        }

        g_Dpdk_Ctx->mbuf_pool = g_Dpdk_Ctx->mbuf_pools[g_Dpdk_Ctx->socket_io];
    }

    /* Initialize other default configuration values. */
    g_Dpdk_Ctx->debug = 0;

    /* Import the configuration dictionary requests. */
    for (entry = config->values; entry; entry = entry->next) {
        if (!strcmp(entry->key, "debug"))
            g_Dpdk_Ctx->debug = 1;
    }

    g_Dpdk_Ctx->state[g_Dpdk_Ctx->instances->index] = DAQ_STATE_INITIALIZED;
    *ctxt_ptr = g_Dpdk_Ctx->instances;
    pthread_mutex_unlock(&g_Dpdk_mutex);

    return DAQ_SUCCESS;

    err: if (g_Dpdk_Ctx) {
        dpdk_inst_close(g_Dpdk_Ctx->instances);
        if (g_Dpdk_Ctx->device)
            free(g_Dpdk_Ctx->device);
        free(g_Dpdk_Ctx);
    }

    pthread_mutex_unlock(&g_Dpdk_mutex);
    return rval;
}

static int dpdk_daq_set_filter(void *handle, const char *filter) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx; //(Dpdk_Context_t *) handle;
    struct sfbpf_program fcode;

    if (dpdkc->filter)
        free(dpdkc->filter);

    dpdkc->filter = strdup(filter);
    if (!dpdkc->filter) {
        DPE(dpdkc->errbuf,
                "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dpdkc->snaplen, DLT_EN10MB, &fcode, dpdkc->filter, 1, 0)
            < 0) {
        DPE(dpdkc->errbuf,
                "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dpdkc->fcode);
    dpdkc->fcode.bf_len = fcode.bf_len;
    dpdkc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int dpdk_daq_start(void *handle) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;
    DpdkInstance *instance = (DpdkInstance *) handle;

    //for (instance = dpdkc->instances; instance; instance = instance->next) {
    if (start_instance(dpdkc, instance) != DAQ_SUCCESS)
        return DAQ_ERROR;
    //}

    dpdk_daq_reset_stats(dpdkc);

    dpdkc->state[instance->index] = DAQ_STATE_STARTED;
    dpdkc->inst_stat |= (0x01 << instance->index);

    printf("%s: aquiring pkt from NIC, rss_idx %d\n", __func__,
            instance->index);

    rte_eal_mp_remote_launch(dpdk_daq_acquire, dpdkc, SKIP_MASTER);

    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
        DAQ_VERDICT_PASS, /* DAQ_VERDICT_PASS */
        DAQ_VERDICT_BLOCK, /* DAQ_VERDICT_BLOCK */
        DAQ_VERDICT_PASS, /* DAQ_VERDICT_REPLACE */
        DAQ_VERDICT_PASS, /* DAQ_VERDICT_WHITELIST */
        DAQ_VERDICT_BLOCK, /* DAQ_VERDICT_BLACKLIST */
        DAQ_VERDICT_PASS, /* DAQ_VERDICT_IGNORE */
        DAQ_VERDICT_BLOCK /* DAQ_VERDICT_RETRY */
};

static inline uint32_t dpdk_rx_buffer_to_send(Dpdk_Context_t *dpdkc,
        uint32_t ring_idx, struct rte_mbuf *mbuf, uint32_t bsz) {
    uint32_t pos;
    int ret;

    pos = dpdkc->rx.mbuf_in[ring_idx].n_mbufs;
    dpdkc->rx.mbuf_in[ring_idx].array[pos++] = mbuf;
    if (likely(pos < bsz)) {
        dpdkc->rx.mbuf_in[ring_idx].n_mbufs = pos;
        return 0;
    }

    ret = rte_ring_sp_enqueue_bulk(dpdkc->rx.rings[ring_idx],
            (void **) dpdkc->rx.mbuf_in[ring_idx].array, bsz);

    if (unlikely(ret == -ENOBUFS)) {
        uint32_t k;
        for (k = 0; k < bsz; k++) {
            struct rte_mbuf *m = dpdkc->rx.mbuf_in[ring_idx].array[k];
            rte_pktmbuf_free(m);
        }
        dpdkc->stats.hw_packets_dropped += bsz;
    }

    dpdkc->rx.mbuf_in[ring_idx].n_mbufs = 0;

    return 1;
}

static inline void dpdk_rx_buffer_flush(Dpdk_Context_t *dpdkc,
        uint32_t ring_idx) {
    uint32_t pos;
    unsigned ret;

    printf("%s: ring_idx %d\n", __func__, ring_idx);

    pos = dpdkc->rx.mbuf_in[ring_idx].n_mbufs;
    ret = rte_ring_sp_enqueue_burst(dpdkc->rx.rings[ring_idx],
            (void **) dpdkc->rx.mbuf_in[ring_idx].array, pos);

    if (unlikely(ret < pos)) {
        uint32_t k;
        for (k = ret; k < pos; k++) {
            struct rte_mbuf *m = dpdkc->rx.mbuf_in[ring_idx].array[k];
            rte_pktmbuf_free(m);
        }
        dpdkc->stats.hw_packets_dropped += (pos - ret);
    }

    dpdkc->rx.mbuf_in[ring_idx].n_mbufs = 0;
}

static int dpdk_daq_acquire(__attribute__((unused)) void *arg) {
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) arg;
//    DpdkInstance *instance = NULL;
    uint32_t i, ret;
    int queue;
    struct rte_mbuf *mbuf_1_0, *mbuf_1_1, *mbuf_2_0, *mbuf_2_1;
    //uint8_t *data_1_0, *data_1_1 = NULL;
    //struct ipv4_hdr *ipv4_hdr;
    //uint32_t ipv4_src,

    struct rte_mbuf *mbuf_0_0, *mbuf_0_1;
    struct rte_mbuf *mbuf;
    uint32_t ring_idx1, ring_idx2;
    uint32_t ring_idx;

#ifdef RX_CNT_TRACK
    uint64_t queue_cnt = 0;
    uint64_t show_cnt = 0;
#endif

    struct rte_mbuf *bufs[BURST_SIZE];

    printf("%s: in, ring_num %d\n", __func__, dpdkc->rx.n_ring);

    for (;;) {
        /*        if ( NULL == instance )
         instance = dpdkc->instances;*/

        /* Has breakloop() been called? */
        if (unlikely(dpdkc->break_loop))
            break;

        for (queue = dpdkc->rx.queue_s; queue < dpdkc->rx.queue_e; queue++) {
            const uint32_t n_mbufs = rte_eth_rx_burst(dpdkc->port, queue, bufs,
                    BURST_SIZE);
#ifdef RX_CNT_TRACK
            if (unlikely(show_cnt++ > 0x1000000)) {
                //nic_xstats_display(instance->port);
                //nic_stats_display(instance->port);
                show_cnt = 0;
                //syslog(LOG_DAEMON | LOG_INFO,
                printf("Queue %d Rx Counts: %"PRIu64", Drop %"PRIu64"\n", queue,
                        queue_cnt, dpdkc->stats.hw_packets_dropped);
            }
#endif

            for (i = 0; i < dpdkc->rx.n_ring; i++) {
                if (unlikely(dpdkc->rx.qc_flush[i]++ > 0x1000000)) {
                    dpdkc->rx.qc_flush[i] = 0;
                    if ( likely(dpdkc->rx.mbuf_in[i].n_mbufs > 0) )
                        dpdk_rx_buffer_flush(dpdkc, i);
                }
            }

            if (unlikely(n_mbufs == 0))
                continue;

#ifdef RX_CNT_TRACK
            queue_cnt += n_mbufs;
#endif

            mbuf_1_0 = bufs[0];
            mbuf_1_1 = bufs[1];
            //data_1_0 = rte_pktmbuf_mtod(mbuf_1_0, uint8_t *);
            //if (likely(n_mbufs > 1)) {
            //data_1_1 = rte_pktmbuf_mtod(mbuf_1_1, uint8_t *);
            //}

            mbuf_2_0 = bufs[2];
            mbuf_2_1 = bufs[3];
            DPDK_RX_PREFETCH0(mbuf_2_0);
            DPDK_RX_PREFETCH0(mbuf_2_1);

            for (i = 0; i + 3 < n_mbufs; i += 2) {
                //uint8_t *data_0_0, *data_0_1;

                mbuf_0_0 = mbuf_1_0;
                mbuf_0_1 = mbuf_1_1;
                //data_0_0 = data_1_0;
                //data_0_1 = data_1_1;

                mbuf_1_0 = mbuf_2_0;
                mbuf_1_1 = mbuf_2_1;
                //data_1_0 = rte_pktmbuf_mtod(mbuf_2_0, uint8_t *);
                //data_1_1 = rte_pktmbuf_mtod(mbuf_2_1, uint8_t *);
                //IO_RX_PREFETCH0(data_1_0);
                //IO_RX_PREFETCH0(data_1_1);

                mbuf_2_0 = bufs[i + 4];
                mbuf_2_1 = bufs[i + 5];
                DPDK_RX_PREFETCH0(mbuf_2_0);
                DPDK_RX_PREFETCH0(mbuf_2_1);

                //Soft-RSS, Put Into Ring
                /*ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf_0_0,
                 struct ipv4_hdr *,
                 sizeof(struct ether_hdr));
                 ipv4_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
                 ring_idx1 = (ipv4_src) & (dpdkc->rx.n_ring - 1);

                 ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf_0_1,
                 struct ipv4_hdr *,
                 sizeof(struct ether_hdr));
                 ipv4_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
                 ring_idx2 = (ipv4_src) & (dpdkc->rx.n_ring - 1);*/

                ring_idx1 = ((mbuf_0_0->hash.rss) >> 7)
                        & (dpdkc->rx.n_ring - 1);
                ring_idx2 = ((mbuf_0_1->hash.rss) >> 7)
                        & (dpdkc->rx.n_ring - 1);

#ifdef RX_CNT_TRACK
                //printf("p_toeplitz_hash 0x%x\n", bufs[i]->hash.rss);
#endif

                ret = dpdk_rx_buffer_to_send(dpdkc, ring_idx1, mbuf_0_0,
                        DEFAULT_BURST_SIZE_IO_RX_WRITE);
                if (1 == ret) {
                    dpdkc->rx.qc_flush[ring_idx1] = 0;
                }

                ret = dpdk_rx_buffer_to_send(dpdkc, ring_idx2, mbuf_0_1,
                        DEFAULT_BURST_SIZE_IO_RX_WRITE);
                if (1 == ret) {
                    dpdkc->rx.qc_flush[ring_idx2] = 0;
                }
            }

            /* Handle the last 1, 2 (when n_mbufs is even) or 3 (when n_mbufs is odd) packets  */
            for (; i < n_mbufs; i += 1) {
                //uint8_t *data;

                mbuf = mbuf_1_0;
                mbuf_1_0 = mbuf_1_1;
                mbuf_1_1 = mbuf_2_0;
                mbuf_2_0 = mbuf_2_1;

                //data = rte_pktmbuf_mtod(mbuf, uint8_t *);

                DPDK_RX_PREFETCH0(mbuf_1_0);

                /*ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
                 struct ipv4_hdr *,
                 sizeof(struct ether_hdr));
                 ipv4_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
                 ring_idx = (ipv4_src) & (dpdkc->rx.n_ring - 1);*/
                ring_idx = ((mbuf->hash.rss) >> 7) & (dpdkc->rx.n_ring - 1);

                dpdk_rx_buffer_to_send(dpdkc, ring_idx, mbuf,
                        DEFAULT_BURST_SIZE_IO_RX_WRITE);
            }
        }

        //instance = instance->next;
    }

    while (dpdkc->inst_stat)
        usleep(1);

    if (dpdkc->device)
        free(dpdkc->device);
    if (dpdkc->filter)
        free(dpdkc->filter);
    free(dpdkc);

    return 0;
}

static int dpdk_daq_acquire_ring(void *handle, int cnt,
        DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user) {
    DpdkInstance *instance = (DpdkInstance *) handle;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint16_t ring_idx, len, j;
    int c = 0;
    struct rte_mbuf *aq_mbufs[DEFAULT_SIZE_AQUIRE_READ];
    int ret;
    uint32_t bsz_rd;

    /*daqhdr.caplen = len;
     daqhdr.pktlen = len;
     daqhdr.ingress_index = instance->index;*/
    daqhdr.egress_index = DAQ_PKTHDR_UNKNOWN;
    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.flags = 0;
    daqhdr.opaque = 0;
    daqhdr.priv_ptr = NULL;
    daqhdr.address_space_id = 0;

//#define PURE_TEST

    do {
        ring_idx = instance->index;
        daqhdr.ingress_index = ring_idx;
        //gettimeofday(&daqhdr.ts, NULL);
        daqhdr.cts = time(NULL);

        //Aquire from RING
        ret = rte_ring_sc_dequeue_bulk(instance->rx.ring_in, (void **) aq_mbufs,
                DEFAULT_SIZE_AQUIRE_READ);

#ifdef RX_CNT_TRACK
        if (unlikely(daqhdr.cts > (instance->cts+1))) {
//        if (unlikely(instance->show_cnt++ > 0x1000000)) {
            //nic_xstats_display(instance->port);
            //nic_stats_display(instance->port);
            //instance->show_cnt = 0;
            instance->cts = daqhdr.cts;
            //syslog(LOG_DAEMON | LOG_INFO,
            printf("%s: queue %d, rss_%d got pkts: %lu, tsm %ld\n",
                    __func__, instance->rx.queue, ring_idx,
                    instance->stats.hw_packets_received, (long int)daqhdr.cts);
        }
#endif

        if (unlikely(ret == -ENOENT)) {
            ret = rte_ring_sc_dequeue_burst(instance->rx.ring_in,
                    (void **) aq_mbufs, DEFAULT_SIZE_AQUIRE_READ);
            if (ret <= 0)
                return 0;
            bsz_rd = ret;
        } else {
            bsz_rd = DEFAULT_SIZE_AQUIRE_READ;
        }

        //DPDK_RX_PREFETCH1(rte_pktmbuf_mtod(aq_mbufs[0], unsigned char *));
        DPDK_RX_PREFETCH1(aq_mbufs[0]);
        DPDK_RX_PREFETCH0(aq_mbufs[1]);

        for (j = 0; j < bsz_rd; j++) {
            if (likely(j < bsz_rd - 1)) {
                //DPDK_RX_PREFETCH1(rte_pktmbuf_mtod(aq_mbufs[j+1], unsigned char *));
                DPDK_RX_PREFETCH0(aq_mbufs[j+1]);
            }
            if (likely(j < bsz_rd - 2)) {
                DPDK_RX_PREFETCH0(aq_mbufs[j+2]);
            }

#ifndef PURE_TEST
            data = rte_pktmbuf_mtod(aq_mbufs[j], void *);
            len = rte_pktmbuf_data_len(aq_mbufs[j]);
#endif
            verdict = DAQ_VERDICT_PASS;

            daqhdr.caplen = len;
            daqhdr.pktlen = len;

            instance->stats.hw_packets_received++;

            if (likely(NULL != callback)) {
#ifndef PURE_TEST
                verdict = callback(user, &daqhdr, data);
                if (verdict >= MAX_DAQ_VERDICT)
                    verdict = DAQ_VERDICT_PASS;
#endif
                instance->stats.verdicts[verdict]++;
                verdict = verdict_translation_table[verdict];
            }

            instance->stats.packets_received++;
            c++;

            rte_pktmbuf_free(aq_mbufs[j]);
        }
    } while (0);

    return 0;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr,
        const uint8_t *packet_data, uint32_t len, int reverse) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;
    DpdkInstance *instance = (DpdkInstance *) handle;

    struct rte_mbuf *m;

    /* Find the instance that the packet was received on. */
    //for (instance = dpdkc->instances; instance; instance = instance->next)
    //{
    if (instance->index != hdr->ingress_index)
        return DAQ_ERROR_INVAL; //break;
    //}

    if (!instance) {
        DPE(dpdkc->errbuf,
                "%s: Unrecognized ingress interface specified: %u", __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    if (!reverse && !(instance == instance->peer)) {
        DPE(dpdkc->errbuf,
                "%s: Specified ingress interface (%u) has no peer for forward injection.", __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    m = rte_pktmbuf_alloc(dpdkc->mbuf_pool);
    if (!m) {
        DPE(dpdkc->errbuf,
                "%s: Couldn't allocate memory for packet.", __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }

    rte_memcpy(rte_pktmbuf_mtod(m, void *), packet_data, len);

    const uint16_t nb_tx = rte_eth_tx_burst(dpdkc->port, 0, &m, 1);

    if (unlikely(nb_tx == 0)) {
        DPE(dpdkc->errbuf,
                "%s: Couldn't send packet. Try again.", __FUNCTION__);
        rte_pktmbuf_free(m);
        return DAQ_ERROR_AGAIN;
    }

    return DAQ_SUCCESS;
}

static int dpdk_daq_breakloop(void *handle) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;

    dpdkc->break_loop = 1;

    return DAQ_SUCCESS;

}

static int dpdk_daq_stop(void *handle) {
    //DpdkInstance *instance = (DpdkInstance *)handle;

    printf("%s: stoping instance\n", __func__);

    dpdk_inst_close(handle);

    return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle) {
    int isMaster;
    DpdkInstance *instance = (DpdkInstance *) handle;
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;

    isMaster = instance->isMaster;
    if (isMaster)
        dpdkc->break_loop = 1;

    /*    if ( DAQ_STATE_STOPPED != dpdkc->state[instance->index] )
     dpdk_inst_close(instance);*/

    printf("%s: shutting dpdkc down, isMaster %d\n", __func__, isMaster);
}

static DAQ_State dpdk_daq_check_status(void *handle) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;
    DpdkInstance *instance = (DpdkInstance *) handle;

    return dpdkc->state[instance->index];
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    //Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;
    DpdkInstance *instance = (DpdkInstance *) handle;

    rte_memcpy(stats, &instance->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void dpdk_daq_reset_stats(void *handle) {
    //Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;
    DpdkInstance *instance = (DpdkInstance *) handle;

    memset(&instance->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdk_daq_get_snaplen(void *handle) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;

    return dpdkc->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT
            | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF
            | DAQ_CAPA_DEVICE_INDEX;
}

static int dpdk_daq_get_datalink_type(void *handle) {
    return DLT_EN10MB;
}

static const char *dpdk_daq_get_errbuf(void *handle) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;

    return dpdkc->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string) {
    Dpdk_Context_t *dpdkc = g_Dpdk_Ctx;

    if (!string)
        return;

    DPE(dpdkc->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *device) {
    DpdkInstance *instance = (DpdkInstance *) handle;

    return instance->index;

    /*    int port, i;
     pthread_t tid;

     if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
     return DAQ_ERROR_NODEV;

     tid = pthread_self();
     for (i=0; i<RING_MAX_NUM; i++) {
     if ( tid == dpdkc->rx.ring_tid_map[i] ) {
     return i;
     }
     }

     for (instance = dpdkc->instances; instance; instance = instance->next)
     {
     if (dpdkc->port == port)
     return instance->index;
     }

     return DAQ_ERROR_NODEV;*/
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
        { /* .api_version = */DAQ_API_VERSION,
                /* .module_version = */DAQ_DPDK_VERSION,
                /* .name = */"dpdk", /* .type = */DAQ_TYPE_INLINE_CAPABLE
                        | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
                /* .initialize = */dpdk_daq_initialize,
                /* .set_filter = */dpdk_daq_set_filter,
                /* .start = */dpdk_daq_start,
                /* .acquire = */dpdk_daq_acquire_ring,
                /* .inject = */dpdk_daq_inject,
                /* .breakloop = */dpdk_daq_breakloop,
                /* .stop = */dpdk_daq_stop,
                /* .shutdown = */dpdk_daq_shutdown,
                /* .check_status = */dpdk_daq_check_status,
                /* .get_stats = */dpdk_daq_get_stats,
                /* .reset_stats = */dpdk_daq_reset_stats,
                /* .get_snaplen = */dpdk_daq_get_snaplen,
                /* .get_capabilities = */dpdk_daq_get_capabilities,
                /* .get_datalink_type = */dpdk_daq_get_datalink_type,
                /* .get_errbuf = */dpdk_daq_get_errbuf,
                /* .set_errbuf = */dpdk_daq_set_errbuf,
                /* .get_device_index = */dpdk_daq_get_device_index,
                /* .modify_flow = */NULL, /* .hup_prep = */NULL,
                /* .hup_apply = */NULL, /* .hup_post = */NULL,
                /* .dp_add_dc = */NULL, /* .query_flow */NULL, };

