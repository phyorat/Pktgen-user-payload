#ifndef __DAQ_DPDK_EPFD_IPC_H__
#define __DAQ_DPDK_EPFD_IPC_H__

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>

//unsigned char *CMSG_DATA(struct cmsghdr *cp);

/*
 * Returns: pointer to data associated with cmsghdr structure
*/

//struct cmsghdr *CMSG_FIRSTHDR(struct msghdr *mp);
/*
Returns: pointer to first cmsghdr structure associated
with the msghdr structure, or NULL if none exists*/

//struct cmsghdr *CMSG_NXTHDR(struct msghdr *mp, struct cmsghdr *cp);

/*Returns: pointer to next cmsghdr structure associated with
the msghdr structure given the current cmsghdr
structure, or NULL if we're at the last one*/

//unsigned int CMSG_LEN(unsigned int nbytes);

/* size of control buffer to send/recv one file descriptor */
#define CONTROLLEN  CMSG_LEN(sizeof(int))
#define MAXLINE     256

void epfd_unlink_all(DpdkInstance *dpdk_ins);
int epfd_server(Dpdk_Context_t *dpdkc, int qid, int fd_to_send);
int epfd_server_loop(Dpdk_Context_t *dpdkc);
int epfd_client(Dpdk_Context_t *dpdkc);

#endif  /*__DAQ_DPDK_EPFD_IPC_H__*/
