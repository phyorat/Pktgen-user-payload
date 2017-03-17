/*
 *
 *
 * */

#include "daq_dpdk.h"
#include "sqlin.h"
#include "daq_dpdk_epfd_ipc.h"
#include "daq_dpdk_statsop.h"

const char *server = "localhost";
const char *database = "surveyor";
const char *user = "root";
const char *password = "13246";

static int sys_initMysqlDatabase(const char *server, const char *database, const char *user, const char *password)
{
    if(MysqlInit(server,database,user,password))
    {
        DAQ_RTE_LOG("%s: MysqlInit error\n",__func__);
        return 1;
    }

    if(MysqlConnect())
    {
        DAQ_RTE_LOG("%s: MysqlConnect error\n",__func__);
        return 1;
    }
    return 0;
}

static void nic_xstats_get(uint8_t port_id, Ifaceinfo *pinf)
{
    struct rte_eth_xstat_name *xstats_names;
    struct rte_eth_xstat *xstats;
    int len, ret, i;

    len = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (len < 0) {
        syslog(LOG_ERR, "%s: Cannot get xstats count: port %d\n", __func__, port_id);
        return;
    }

    xstats = rte_malloc("pkt stats", sizeof(xstats[0]) * len, 0);
    if (xstats == NULL) {
        syslog(LOG_ERR, "%s: Cannot allocate memory for xstats\n", __func__);
        return;
    }

    xstats_names = rte_malloc("pkt stats", sizeof(struct rte_eth_xstat_name) * len, 0);
    if (xstats_names == NULL) {
        syslog(LOG_ERR, "%s: Cannot allocate memory for xstat names\n", __func__);
        free(xstats);
        return;
    }

    if (len != rte_eth_xstats_get_names(
            port_id, xstats_names, len)) {
        syslog(LOG_ERR, "%s: Cannot get xstat names\n", __func__);
        goto err;
    }

    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        syslog(LOG_ERR, "%s: Cannot get xstats\n", __func__);
        goto err;
    }

    for (i = 0; i < len; i++) {
        if ( !strcmp("rx_good_packets", xstats_names[i].name) ) {
            pinf->uRxPrcnt = xstats[i].value;
        }
        else if ( !strcmp("rx_good_bytes", xstats_names[i].name) ) {
            pinf->uRxPrbyte = xstats[i].value;
        }
        else if ( !strcmp("tx_good_packets", xstats_names[i].name) ) {
            pinf->uTxPrcnt = xstats[i].value;
        }
        else if ( !strcmp("tx_good_bytes", xstats_names[i].name) ) {
            pinf->uTxPrbyte = xstats[i].value;
        }
        else {
            //DAQ_RTE_LOG("port %d--%s: %"PRIu64"\n", port_id, xstats_names[i].name, xstats[i].value);
        }
    }

err:
    rte_free(xstats);
    rte_free(xstats_names);
}

static void daq_dpdk_master_send(DpdkInstance *instance, uint8_t qid)
{
    int ret;
    void *msg = NULL;

    if (rte_mempool_get(instance->ipc_msg_pools[qid], &msg) < 0)
        rte_panic("Failed to get message buffer\n");

    *(int *)msg = qid;
    ret = rte_ring_enqueue(instance->ipc_msg_rings[qid], msg);
    if ( -ENOBUFS == ret ) {
        DAQ_RTE_LOG_DEEP("%s: ring full for msg to queue(%d) process\n", __func__, qid);
        rte_mempool_put(instance->ipc_msg_pools[qid], msg);
    }
    else if ( -EDQUOT == ret ) {
        DAQ_RTE_LOG("%s: Quota exceeded msg to queue(%d) process\n", __func__, qid);
    }
}

int sys_ifinfo(void *args)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t*)args;
    DpdkInstance *instance = dpdkc->rx_ins;
    uint8_t i, qid;
    int ret;
    uint32_t s_cnt;
    char sql_str[1024] = "";
    Ifaceinfo if_info;
    Ifaceinfo sPinfo[1];
    struct rte_eth_link rte_link;

    if(sys_initMysqlDatabase(server, database, user, password))
    {
        DAQ_RTE_LOG("InitMysqlDatabase error\n");
        return 1;
    }

    memset(&sPinfo, 0, sizeof(sPinfo));
    strncpy(if_info.if_name, "psi_d0", 7);

    i = 0;
    while (1) {
        nic_xstats_get(instance->port, &if_info);
        rte_eth_link_get_nowait(instance->port, &rte_link);
        if ( ETH_LINK_UP == rte_link.link_status )
            if_info.cIfup = 1;
        else
            if_info.cIfup = 0;

        //Update SQL
        if ( '\0' == sPinfo[i].if_name[0] ) {
            sPinfo[i].uRxPrbyte = if_info.uRxPrbyte;
            sPinfo[i].uTxPrbyte = if_info.uTxPrbyte;
        }

        snprintf(sql_str, sizeof(sql_str), SQL_SELECT_IFINFO, if_info.if_name);
        ret = MysqlSelectAsUInt(sql_str, &s_cnt);
        //SYSI_DEBUG_LOG("%s:MysqlSelectAsUInt ret %d, s_cnt %u\n",__func__, ret, s_cnt);
        if(ret > 0 ){//&& s_cnt >= 0) {
            //RTE_LOG(INFO, EAL, "%s: updating\n", __func__);
            snprintf(sql_str, sizeof(sql_str), SQL_UPDATE_IFINFO,
                    if_info.cIfup, if_info.uRxPrcnt, if_info.uRxPrbyte,
                    if_info.uTxPrcnt, if_info.uTxPrbyte,
                    if_info.uRxPrbyte - sPinfo[i].uRxPrbyte,
                    if_info.uTxPrbyte - sPinfo[i].uTxPrbyte,
                    if_info.if_name);
        }
        else {
            //RTE_LOG(INFO, EAL, "%s: inserting\n", __func__);
            snprintf(sql_str, sizeof(sql_str), SQL_INSERT_IFINFO,
                    if_info.if_name, if_info.cIfup,
                    if_info.uRxPrcnt, if_info.uRxPrbyte,
                    if_info.uTxPrcnt, if_info.uTxPrbyte,
                    if_info.uRxPrbyte - sPinfo[i].uRxPrbyte,
                    if_info.uTxPrbyte - sPinfo[i].uTxPrbyte);
        }
        MysqlInsert(sql_str, NULL);

        memcpy(&sPinfo[i], &if_info, sizeof(if_info));

        //IPC for primary process monitoring
        for (qid=0; qid<instance->n_rx_queue; qid++) {
            if ( qid == instance->rx_queue_s )
                continue;
            daq_dpdk_master_send(instance, qid);
        }

#ifdef DAQ_DPDK_POWER_CTL
        if ( dpdkc->power_heurs->intr_en ) {
            epfd_server_loop(dpdkc);
        }
        else {
            sleep(1);
        }
#else
        sleep(1);
#endif
    }

    return 0;
}
