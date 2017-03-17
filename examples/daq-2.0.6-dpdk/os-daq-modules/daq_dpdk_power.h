#ifndef __DAQ_DPDK_POWER_H__
#define __DAQ_DPDK_POWER_H__


#include <rte_timer.h>
#include <rte_power.h>
#include <rte_cycles.h>
#include <rte_interrupts.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <assert.h>


#define MAX_RX_QUEUE_PER_LCORE              16
#define MAX_EPOLL_FD_EVENTS                 16

#define MIN_ZERO_POLL_COUNT                 0x400
#define MINIMUM_SLEEP_TIME                  1
#define SUSPEND_THRESHOLD                   0x10000

#define DAQ_POWER_EPOOL_WAIT_TIMEOUT        1000

#ifdef DAQ_DPDK_POWER_FREQ_CTL
#define MAX_PKT_BURST                       32
/* around 100ms at 2 Ghz */
#define TIMER_RESOLUTION_CYCLES             200000000ULL
/* 100 ms interval */
#define TIMER_NUMBER_PER_SECOND             10
/* 100000 us */
#define SCALING_PERIOD                      (1000000/TIMER_NUMBER_PER_SECOND)
#define SCALING_DOWN_TIME_RATIO_THRESHOLD   0.25
#endif


/**
 * HW Rx queue size is 128 by default, Rx burst read at maximum 32 entries
 * per iteration
 */
#define FREQ_GEAR1_RX_PACKET_THRESHOLD             MAX_PKT_BURST
#define FREQ_GEAR2_RX_PACKET_THRESHOLD             (MAX_PKT_BURST*2)
#define FREQ_GEAR3_RX_PACKET_THRESHOLD             (MAX_PKT_BURST*3)
#define FREQ_UP_TREND1_ACC   1
#define FREQ_UP_TREND2_ACC   100
#define FREQ_UP_THRESHOLD    10000


enum freq_scale_hint_t
{
    FREQ_LOWER    =      -1,
    FREQ_CURRENT  =       0,
    FREQ_HIGHER   =       1,
    FREQ_HIGHEST  =       2
};

struct lcore_rx_queue {
//    uint8_t port_id;
//    uint8_t queue_id;
    enum freq_scale_hint_t freq_up_hint;
    uint32_t zero_rx_packet_count;
    uint32_t idle_hint;
    uint32_t padding[1];
} __rte_cache_aligned;

struct lcore_stats {
    uint32_t lcore_rx_idle_count;
    /* total sleep time in ms since last frequency scaling down */
    uint32_t sleep_time;
    /* number of long sleep recently */
    uint32_t nb_long_sleep;
    /* freq. scaling up trend */
    uint32_t trend;
    /* total packet processed recently */
    uint64_t nb_rx_processed;
    /* total iterations looped recently */
    uint64_t nb_iteration_looped;
    uint32_t padding[8];
} __rte_cache_aligned;

//Inline Defination
struct lcore_stats stats[RTE_MAX_LCORE] __rte_cache_aligned;
struct rte_timer power_timers[RTE_MAX_LCORE];
struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
rte_spinlock_t locks[RTE_MAX_ETHPORTS];

Dpdk_Power_Heuristic power_track;
struct rte_epoll_event rte_signalfd_epdata;

//Inline Function

#ifdef DAQ_DPDK_POWER_FREQ_CTL
/*  Freqency scale down timer callback */
static void power_timer_cb(__attribute__((unused)) struct rte_timer *tim,
              __attribute__((unused)) void *arg)
{
    uint64_t hz;
    float sleep_time_ratio;
    unsigned lcore_id = rte_lcore_id();

    /* accumulate total execution time in us when callback is invoked */
    sleep_time_ratio = (float)(stats[lcore_id].sleep_time) /
                    (float)SCALING_PERIOD;
    /**
     * check whether need to scale down frequency a step if it sleep a lot.
     */
    if (sleep_time_ratio >= SCALING_DOWN_TIME_RATIO_THRESHOLD) {
        if (rte_power_freq_down)
            rte_power_freq_down(lcore_id);
    }
    else if ( (unsigned)(stats[lcore_id].nb_rx_processed /
        stats[lcore_id].nb_iteration_looped) < MAX_PKT_BURST) {
        /**
         * scale down a step if average packet per iteration less
         * than expectation.
         */
        if (rte_power_freq_down)
            rte_power_freq_down(lcore_id);
    }

    /**
     * initialize another timer according to current frequency to ensure
     * timer interval is relatively fixed.
     */
    hz = rte_get_timer_hz();
    rte_timer_reset(&power_timers[lcore_id], hz/TIMER_NUMBER_PER_SECOND,
                SINGLE, lcore_id, power_timer_cb, NULL);

    stats[lcore_id].nb_rx_processed = 0;
    stats[lcore_id].nb_iteration_looped = 0;

    stats[lcore_id].sleep_time = 0;
}
#endif

static int eal_init_tls_epfd(void)
{
    int pfd = epoll_create(MAX_EPOLL_FD_EVENTS);

    if (pfd < 0) {
        RTE_LOG(ERR, EAL,
            "Cannot create epoll instance\n");
        return -1;
    }
    return pfd;
}

static int signalfd_register(DpdkInstance *dpdk_ins)
{
    int err;
    sigset_t sigset;
    struct epoll_event ev;

    if ( !power_track.intr_en )
    	return -1;

    /* Create a sigset of all the signals that we're interested in */
    err = sigemptyset(&sigset);
    assert(err == 0);
/*    err = sigaddset(&sigset, SIGINT);
    assert(err == 0);
    err = sigaddset(&sigset, SIGTERM);
    assert(err == 0);*/
    err = sigaddset(&sigset, SIGUSR1);
    assert(err == 0);
    err = sigaddset(&sigset, SIGCONT);
    assert(err == 0);
//    err = sigaddset(&sigset, SIGCONT);//continue
//    assert(err == 0);
    /* We must block the signals in order for signalfd to receive them */
    err = sigprocmask(SIG_BLOCK, &sigset, NULL);
    assert(err == 0);
    /* Create the signalfd */
    dpdk_ins->sigfd = signalfd(-1, &sigset, 0);
    assert(dpdk_ins->sigfd != -1);

    //rte_epdata
    memset(&rte_signalfd_epdata, 0, sizeof(rte_signalfd_epdata));
    rte_signalfd_epdata.fd = dpdk_ins->sigfd;
    rte_signalfd_epdata.status = RTE_EPOLL_VALID;

    //signalfd
    ev.data.fd = dpdk_ins->sigfd;//(void *)event;
    ev.events = EPOLLIN | EPOLLPRI | EPOLLET;//event->epdata.event;
    ev.data.ptr = &rte_signalfd_epdata;

    epoll_ctl(dpdk_ins->epfd, EPOLL_CTL_ADD, dpdk_ins->sigfd, &ev);

    return 0;
}

static int event_register(Dpdk_Context_t *dpdkc)
{
	DpdkInstance *dpdk_ins = dpdkc->rx_ins;
    uint8_t portid, queueid;
    uint32_t data;
    int ret;//, epfd;

    portid = dpdk_ins->port;

    for (queueid = 0; queueid < dpdk_ins->n_rx_queue; ++queueid) {
        data = portid << CHAR_BIT | queueid;

        DAQ_RTE_LOG("%s: rx interruput setup for port %d-queue %d\n",
                __func__, portid, queueid);

        dpdkc->epfds[queueid] = eal_init_tls_epfd();
        ret = rte_eth_dev_rx_intr_ctl_q(portid, queueid,
        		dpdkc->epfds[queueid],//RTE_EPOLL_PER_THREAD,
                RTE_INTR_EVENT_ADD,
                (void *)((uintptr_t)data));
        if (ret)
            return ret;

        if ( queueid == dpdk_ins->rx_queue_s ) {
            dpdk_ins->epfd = dpdkc->epfds[queueid];
        }
        else {
            DAQ_RTE_LOG("%s: wait for port %d-queue %d to get epfd(%d)\n",
                    __func__, portid, queueid, dpdkc->epfds[queueid]);
            ret = epfd_server(dpdkc, queueid, dpdkc->epfds[queueid]);
            if ( ret ) {
                DAQ_RTE_LOG("%s: port %d-queue %d send epfd fail, errno %d\n",
                        __func__, portid, queueid, ret);
                if ( 4 == ret ) {
                	RTE_LOG(ALERT, EAL, "%s: Interrupt Signal, exit\n", __func__);
                	return ret;
                }
            }
            else {
                DAQ_RTE_LOG("%s: port %d-queue %d send epfd ok\n",
                        __func__, portid, queueid);
            }
        }
    }

    return 0;
}

static inline uint32_t power_idle_heuristic(uint32_t zero_rx_packet_count)
{
    /* If zero count is less than 100,  sleep 1us */
    if (zero_rx_packet_count < SUSPEND_THRESHOLD)
        return MINIMUM_SLEEP_TIME;
    /* If zero count is less than 1000, sleep 100 us which is the
        minimum latency switching from C3/C6 to C0
    */
    else
        return SUSPEND_THRESHOLD;

    return 0;
}

#ifdef DAQ_DPDK_POWER_FREQ_CTL
static inline enum freq_scale_hint_t power_freq_scaleup_heuristic(unsigned lcore_id,
                 uint8_t port_id,
                 uint16_t queue_id)
{
    if (likely(rte_eth_rx_descriptor_done(port_id, queue_id,
            FREQ_GEAR3_RX_PACKET_THRESHOLD) > 0)) {
        stats[lcore_id].trend = 0;
        return FREQ_HIGHEST;
    } else if (likely(rte_eth_rx_descriptor_done(port_id, queue_id,
            FREQ_GEAR2_RX_PACKET_THRESHOLD) > 0))
        stats[lcore_id].trend += FREQ_UP_TREND2_ACC;
    else if (likely(rte_eth_rx_descriptor_done(port_id, queue_id,
            FREQ_GEAR1_RX_PACKET_THRESHOLD) > 0))
        stats[lcore_id].trend += FREQ_UP_TREND1_ACC;

    if (likely(stats[lcore_id].trend > FREQ_UP_THRESHOLD)) {
        stats[lcore_id].trend = 0;
        return FREQ_HIGHER;
    }

    return FREQ_CURRENT;
}
#endif

static inline void turn_on_intr(DpdkInstance *dpdk_ins)
{
    uint8_t port_id, queue_id;

    port_id = dpdk_ins->port;
    for (queue_id = dpdk_ins->rx_queue_s; queue_id < dpdk_ins->rx_queue_e; ++queue_id) {
        rte_spinlock_lock(&(locks[port_id]));
        rte_eth_dev_rx_intr_enable(port_id, queue_id);
        rte_spinlock_unlock(&(locks[port_id]));
    }
}

/**
 * force polling thread sleep until one-shot rx interrupt triggers
 * @param port_id
 *  Port id.
 * @param queue_id
 *  Rx queue id.
 * @return
 *  0 on success
 */
static inline int sleep_until_rx_interrupt(DpdkInstance *dpdk_ins)
{
    struct rte_epoll_event event[MAX_EPOLL_FD_EVENTS];
    int n, i;
    uint8_t port_id, queue_id;
    void *data;
    ssize_t read_sz;
    struct signalfd_siginfo sig_info;

    DAQ_RTE_LOG_DEEP("%s: lcore %u sleeps until interrupt triggers\n",
            __func__, rte_lcore_id());

    n = rte_epoll_wait(dpdk_ins->epfd,/*RTE_EPOLL_PER_THREAD,*/
            event, MAX_EPOLL_FD_EVENTS, DAQ_POWER_EPOOL_WAIT_TIMEOUT);//-1);
    for (i = 0; i < n; i++) {
        if ( dpdk_ins->sigfd == event[i].fd ) {
            read_sz = read(event[i].fd, &sig_info, sizeof(sig_info));
            if ( read_sz != sizeof(sig_info) ) {
                DAQ_RTE_LOG("%s: lcore %u is waked up from invalid signal interrupt\n",
                        __func__, rte_lcore_id());
                break;
            }

            switch ( sig_info.ssi_signo ) {
            case SIGINT:
            case SIGTERM:
                dpdk_ins->break_loop = 1;
                DAQ_RTE_LOG("%s: lcore %u is waked up from signal interrupt\n",
                        __func__, rte_lcore_id());
                break;
            case SIGCONT:
                DAQ_RTE_LOG("%s: lcore %u is waked up from SIGCONT signal and continue\n",
                        __func__, rte_lcore_id());
                break;
            default:
                DAQ_RTE_LOG("%s: lcore %u is waked up from other signal, continue\n",
                        __func__, rte_lcore_id());
                break;
            }
            break;
        }

        data = event[i].epdata.data;
        port_id = ((uintptr_t)data) >> CHAR_BIT;
        queue_id = ((uintptr_t)data) &
            RTE_LEN2MASK(CHAR_BIT, uint8_t);
        rte_eth_dev_rx_intr_disable(port_id, queue_id);
        DAQ_RTE_LOG_DEEP("%s: lcore %u is waked up from rx interrupt on"
            " port %d queue %d\n",
            __func__, rte_lcore_id(), port_id, queue_id);
        break;
    }

    rx_queue_list[dpdk_ins->rx_queue_s].zero_rx_packet_count = 0;

    DAQ_RTE_LOG_DEEP("%s: lcore %u waked up, event_n %d\n",
            __func__, rte_lcore_id(), n);
    return 0;
}

static int daq_dpdk_power_heuristic_init(Dpdk_Context_t *dpdkc)
{
    int ret;
#ifdef DAQ_DPDK_POWER_FREQ_CTL
    unsigned lcore_id;
    uint64_t hz;

    rte_timer_subsystem_init();

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        /* init power management library for a specified core */
        ret = rte_power_init(lcore_id);
        if (ret)
            RTE_LOG(ERR, POWER,
                "Library initialization failed on core %u\n", lcore_id);

        /* init timer structures for each enabled lcore */
        rte_timer_init(&power_timers[lcore_id]);
        hz = rte_get_timer_hz();
        rte_timer_reset(&power_timers[lcore_id], hz/TIMER_NUMBER_PER_SECOND,
                SINGLE, lcore_id, power_timer_cb, NULL);
    }
#endif

    memset(stats, 0, sizeof(stats));
    memset(rx_queue_list, 0, sizeof(rx_queue_list));
    memset(&power_track, 0, sizeof(power_track));

    /* add into event wait list */
    if ( 0 == (ret=event_register(dpdkc)) ) {
        power_track.intr_en = 1;
        DAQ_RTE_LOG(">>>>>>>>>>>>>RX interrupt enable, Primary process initialize done.\n");
    }
    else {
        DAQ_RTE_LOG(">>>>>>>>>>>>>RX interrupt won't enable, error(%d).\n", ret);
        return ret;
    }

    return 0;
}

static inline int daq_dpdk_power_preheuris(uint64_t cur_tsc_power)
{
    unsigned lcore_id = rte_lcore_id();
#ifdef DAQ_DPDK_POWER_FREQ_CTL
    uint64_t diff_tsc_power;
#endif

    stats[lcore_id].nb_iteration_looped++;
    stats[lcore_id].lcore_rx_idle_count = 0;

#ifdef DAQ_DPDK_POWER_FREQ_CTL
//    cur_tsc_power = rte_rdtsc();
    diff_tsc_power = cur_tsc_power - power_track.prev_tsc_power;
    if (diff_tsc_power > TIMER_RESOLUTION_CYCLES) {
        rte_timer_manage();
        power_track.prev_tsc_power = cur_tsc_power;
    }
#endif

    return 0;
}

static inline int daq_dpdk_power_heuris(DpdkInstance *dpdk_ins, uint8_t queueid, int nb_rx)
{
#ifdef DAQ_DPDK_POWER_FREQ_CTL
    uint8_t portid = dpdk_ins->port;
#endif
    unsigned lcore_id = dpdk_ins->lcore_id;
    struct lcore_rx_queue *rx_queue;

    rx_queue = &(rx_queue_list[queueid]);

    rx_queue->idle_hint = 0;
    stats[lcore_id].nb_rx_processed += nb_rx;

    if (unlikely(nb_rx == 0)) {
        /**
         * no packet received from rx queue, try to
         * sleep for a while forcing CPU enter deeper
         * C states.
         */
        //RTE_LOG(INFO, EAL, "queue %d is idle, count %d\n", queueid, rx_queue->zero_rx_packet_count);

        rx_queue->zero_rx_packet_count++;
        if (rx_queue->zero_rx_packet_count <=
                    MIN_ZERO_POLL_COUNT) {
            //continue;
            return 0;
        }

        rx_queue->idle_hint = power_idle_heuristic(rx_queue->zero_rx_packet_count);
        stats[lcore_id].lcore_rx_idle_count++;
    }
    else {
        rx_queue->zero_rx_packet_count = 0;
#ifdef DAQ_DPDK_POWER_FREQ_CTL
        /**
         * do not scale up frequency immediately as
         * user to kernel space communication is costly
         * which might impact packet I/O for received
         * packets.
         */
        rx_queue->freq_up_hint = power_freq_scaleup_heuristic(lcore_id,
                portid,
                queueid);
#endif
    }

    return 0;
}

static inline int daq_dpdk_power_heurissum(DpdkInstance *dpdk_ins)
{
    struct lcore_rx_queue *rx_queue;
    uint32_t i, lcore_idle_hint = 0;
    unsigned lcore_id = dpdk_ins->lcore_id;
#ifdef DAQ_DPDK_POWER_FREQ_CTL
    enum freq_scale_hint_t lcore_scaleup_hint;
#endif
    /*RTE_LOG(INFO, EAL, "%s: core[%d] lcore_rx_idle_count %d\n", __func__,
            lcore_id, stats[lcore_id].lcore_rx_idle_count);*/

    if ( !power_track.intr_en )
        return 0;

    if (likely(stats[lcore_id].lcore_rx_idle_count != dpdk_ins->rx_queue_h)) {
#ifdef DAQ_DPDK_POWER_FREQ_CTL
    	for (i = dpdk_ins->rx_queue_s,
                lcore_scaleup_hint = rx_queue_list[dpdk_ins->rx_queue_s].freq_up_hint;
                i < dpdk_ins->rx_queue_e;
                ++i) {
            rx_queue = &(rx_queue_list[i]);
            if ( lcore_scaleup_hint < rx_queue->freq_up_hint )
                lcore_scaleup_hint = rx_queue->freq_up_hint;
        }
        if ( FREQ_HIGHEST == lcore_scaleup_hint ) {
            if (rte_power_freq_max)
                rte_power_freq_max(lcore_id);
        }
        else if ( FREQ_HIGHER == lcore_scaleup_hint ) {
            if (rte_power_freq_up)
                rte_power_freq_up(lcore_id);
        }
#endif
    }
    else
    {
        /**
         * All Rx queues empty in recent consecutive polls,
         * sleep in a conservative manner, meaning sleep as
         * less as possible.
         */
        for (i = dpdk_ins->rx_queue_s,
                lcore_idle_hint = rx_queue_list[dpdk_ins->rx_queue_s].idle_hint;
                i < dpdk_ins->rx_queue_e; ++i) {
            rx_queue = &(rx_queue_list[i]);
            if ( lcore_idle_hint > rx_queue->idle_hint )
                lcore_idle_hint = rx_queue->idle_hint;
        }

        if ( 0 < lcore_idle_hint
                && lcore_idle_hint < SUSPEND_THRESHOLD) {
            /**
             * execute "pause" instruction to avoid context
             * switch which generally take hundred of
             * microseconds for short sleep.
             */
            rte_delay_us(lcore_idle_hint);
        }
        else if ( lcore_idle_hint >= SUSPEND_THRESHOLD ) {
            /* suspend until rx interrupt trigges
            RTE_LOG(INFO, EAL, "%s: idle hint %d, suspend until rx interrupt trigges\n",
                    __func__, lcore_idle_hint);*/
            if (power_track.intr_en) {
                turn_on_intr(dpdk_ins);
                sleep_until_rx_interrupt(dpdk_ins);
            }
            else {
                rte_delay_us(lcore_idle_hint);
            }
            /* start receiving packets immediately */
            //goto start_rx;
            return 1;
        }
        stats[lcore_id].sleep_time += lcore_idle_hint;
    }

    return 0;
}

#endif  /*__DAQ_DPDK_POWER_H__*/
