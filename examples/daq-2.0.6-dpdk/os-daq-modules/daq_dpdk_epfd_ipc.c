
#include "daq_dpdk.h"
#include "daq_dpdk_epfd_ipc.h"

static struct cmsghdr *cmptr = NULL; /* malloc'ed first time */
static const char *socket_path = "/var/run/.daq_dpdk_epfd_ipc";

/*
 * Pass a file descriptor to another process.
 * If fd<0, then -fd is sent back instead as the error status.
 */
static int send_fd(int fd, int fd_to_send) {
	struct iovec iov[1];
	struct msghdr msg;
	char buf[2]; /* send_fd()/recv_fd() 2-byte protocol */

	iov[0].iov_base = buf;
	iov[0].iov_len = 2;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	if (fd_to_send < 0) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		buf[1] = -fd_to_send; /* nonzero status means error */
		if (buf[1] == 0)
			buf[1] = 1; /* -256, etc. would screw up protocol */
	} else {
		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return (-1);
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		cmptr->cmsg_len = CONTROLLEN;
		msg.msg_control = cmptr;
		msg.msg_controllen = CONTROLLEN;
		*(int *) CMSG_DATA(cmptr) = fd_to_send; /* the fd to pass */
		buf[1] = 0; /* zero status means OK */
	}
	buf[0] = 0; /* null byte flag to recv_fd() */
	if (sendmsg(fd, &msg, 0) != 2)
		return (-1);
	return (0);
}

static int recv_fd(int fd, ssize_t (*userfunc)(int, const void *, size_t))
{
	int newfd = -1, nr, status;
	char *ptr;
	char buf[MAXLINE];
	struct iovec iov[1];
	struct msghdr msg;

	status = -1;
	for (;;) {
		iov[0].iov_base = buf;
		iov[0].iov_len = sizeof(buf);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return (-1);
		msg.msg_control = cmptr;
		msg.msg_controllen = CONTROLLEN;
		if ((nr = recvmsg(fd, &msg, 0)) < 0) {
			perror("recvmsg error");
		} else if (nr == 0) {
			perror("connection closed by server");
			return (-1);
		}
		/*
		 * See if this is the final data with null & status.  Null
		 * is next to last byte of buffer; status byte is last byte.
		 * Zero status means there is a file descriptor to receive.
		 */
		for (ptr = buf; ptr < &buf[nr];) {
			if (*ptr++ == 0) {
				if (ptr != &buf[nr - 1])
				    DAQ_RTE_LOG("message format error");
				status = *ptr & 0xFF; /* prevent sign extension */
				if (status == 0) {
					if (msg.msg_controllen != CONTROLLEN)
					    DAQ_RTE_LOG("status = 0 but no fd");
					newfd = *(int *) CMSG_DATA(cmptr);
				} else {
					newfd = -status;
				}
				nr -= 2;
			}
		}

		if (nr > 0 && NULL != userfunc) {
			if ((*userfunc)(STDERR_FILENO, buf, nr) != nr)
				return (-1);
		}

		if (status >= 0) /* final data has arrived */
			return (newfd); /* descriptor, or -status */
	}

	return -1;
}

static inline void epfd_get_conn_path(int qid, char *buf, int buflen) {
	if (*socket_path == '\0') {
		buf[0] = '\0';
		snprintf(&(buf[1]), buflen - 2, "%s_%d", socket_path + 1, qid);
	} else {
		snprintf(buf, buflen - 1, "%s_%d", socket_path, qid);
	}
}

void epfd_unlink_all(DpdkInstance *dpdk_ins) {
	uint8_t queueid;
	char sun_path[128];

	for (queueid = 0; queueid < dpdk_ins->n_rx_queue; ++queueid) {
		epfd_get_conn_path(queueid, sun_path, sizeof(sun_path));
		unlink(sun_path);
	}
}

/*
 * Receive a file descriptor from a server process.  Also, any data
 * received is passed to (*userfunc)(STDERR_FILENO, buf, nbytes).
 * We have a 2-byte protocol for receiving the fd from send_fd().
 */

int epfd_server(Dpdk_Context_t *dpdkc, int qid, int fd_to_send) {
	struct sockaddr_un addr;
	int cl;

	if ((dpdkc->socfds[qid] = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	epfd_get_conn_path(qid, addr.sun_path, sizeof(addr.sun_path));

	DAQ_RTE_LOG("%s: addr.sun_path: %s\n", __func__, addr.sun_path);

	if (bind(dpdkc->socfds[qid], (struct sockaddr*) &addr, sizeof(addr))
			== -1) {
		perror("bind error");
		return -1;
	}

	if (listen(dpdkc->socfds[qid], 1) == -1) {
		perror("listen error");
		return -1;
	}

	if ((cl = accept(dpdkc->socfds[qid], NULL, NULL)) == -1) {
		perror("accept error");
		return errno;
	}

	/*        while ((rc = read(cl, buf, sizeof(buf))) > 0) {
	 printf("read %u bytes: %.*s\n", rc, rc, buf);
	 }*/

	send_fd(cl, fd_to_send);
	close(cl);
	//break;

	/*        if (rc == -1) {
	 perror("read");
	 exit(-1);
	 } else if (rc == 0) {
	 printf("EOF\n");
	 close(cl);
	 }*/
	//}
	return 0;
}

int epfd_server_loop(Dpdk_Context_t *dpdkc) {
	int cl, max_fd;
	int i, ret;
	fd_set readfds, read_fd_set;
	struct timeval tv;

	FD_ZERO(&readfds);
	max_fd = 0;
	for (i = 0; i < dpdkc->rx_ins->n_rx_queue; i++) {
		if (i == dpdkc->rx_ins->rx_queue_s)
			continue;

		FD_SET(dpdkc->socfds[i], &readfds);
		//RTE_LOG(INFO, EAL, "%s: add fd[%d] to sock handler\n", __func__, i);
		if (max_fd < dpdkc->socfds[i])
			max_fd = dpdkc->socfds[i];
	}

	do {
		read_fd_set = readfds;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		ret = select(max_fd + 1, &read_fd_set, NULL, NULL, &tv);
		if (-1 == ret) {
			perror("select error");
			break;
		}

		/*DAQ_RTE_LOG("%s: select return %d, max_fd %d\n",
				__func__, ret, max_fd);*/

		if (!ret)
			continue;

		DAQ_RTE_LOG("%s: sock data available\n", __func__);

		for (i = 0; i < dpdkc->rx_ins->n_rx_queue; i++) {
			if (FD_ISSET(dpdkc->socfds[i], &read_fd_set)) {
			    DAQ_RTE_LOG("%s: handling sock from queue %d\n", __func__, i);
				if ((cl = accept(dpdkc->socfds[i], NULL, NULL)) == -1) {
					perror("accept error");
					return errno;
				}

				send_fd(cl, dpdkc->epfds[i]);
				close(cl);
			}
		}
	}while(0);

	return 0;
}

int epfd_client(Dpdk_Context_t *dpdkc) {
	struct sockaddr_un addr;
	int qid = dpdkc->rx_ins->rx_queue_s;
	int fd;
	int newfd;

	if (0 == dpdkc->rx_ins->rx_queue_h) {
		return -1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		return -1;
	}

	newfd = -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	epfd_get_conn_path(qid, addr.sun_path, sizeof(addr.sun_path));

	DAQ_RTE_LOG("%s: addr.sun_path: %s\n", __func__, addr.sun_path);

	while (!dpdkc->break_loop) { //Wait for Primary process ready
		if (access(addr.sun_path, F_OK) != -1)
			break;
		usleep(1000);
	}

	sleep(DAQ_DPDK_SECONDARY_INIT_DELAY);

	if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
		perror("connect error");
		return -1;
	}

	/*    while ((rc = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
	 if (write(fd, buf, rc) != rc) {
	 if (rc > 0)
	 fprintf(stderr, "partial write");
	 else {
	 perror("write error");
	 exit(-1);
	 }
	 }
	 }*/

	newfd = recv_fd(fd, NULL);

#ifdef DAQ_DPDK_POWER_CTL
	if ( newfd >= 0 )
	    dpdkc->power_heurs->intr_en = 1;
#endif

	close(fd);

	return newfd;
}
