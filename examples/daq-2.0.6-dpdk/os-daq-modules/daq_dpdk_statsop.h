#ifndef __DAQ_DPDK_STATSOP_H__
#define __DAQ_DPDK_STATSOP_H__


typedef struct __portinfo
{
    char if_name[64];
    uint8_t cIfup;
    uint64_t uRxPrcnt;
    uint64_t uRxPrbyte;
    uint64_t uRxPrbps;
    uint64_t uTxPrcnt;
    uint64_t uTxPrbyte;
    uint64_t uTxPrbps;
}Ifaceinfo;

#define     SQL_T_NAME_IF           "if_info"
#define     SQL_SELECT_IFINFO       "SELECT if_name FROM "SQL_T_NAME_IF" WHERE (if_name='%s');"
#define     SQL_INSERT_IFINFO       "INSERT INTO "SQL_T_NAME_IF" (if_name,if_state,if_rxcnt,if_rxbyte,\
                                        if_txcnt,if_txbyte,if_rxbps,if_txbps) \
                                        VALUES ('%s','%u','%lu','%lu','%lu','%lu','%lu','%lu');"
#define     SQL_UPDATE_IFINFO       "UPDATE "SQL_T_NAME_IF" SET if_state='%u',if_rxcnt='%lu',if_rxbyte='%lu',\
                                        if_txcnt='%lu',if_txbyte='%lu',if_rxbps='%lu',if_txbps='%lu' \
                                        WHERE (if_name='%s');"


static inline int daq_dpdk_secondary_recv(DpdkInstance *instance)
{
    void *msg;

    if (rte_ring_dequeue(instance->rsvmsg_ring, &msg) < 0){
        return -1;
    }

    rte_mempool_put(instance->msg_pool, msg);

    return 0;
}

int sys_ifinfo(void *args);

#endif  /*__DAQ_DPDK_STATSOP_H__*/
