/*
 * kmscon - Pseudo Terminal Handling
 *
 * Copyright (c) 2012 Ran Benita <ran234@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <langinfo.h>
#include <netdb.h>
#include <net/if.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>

#include "color-names.h"
#include "eloop.h"
#include "pty.h"
#include "shl_log.h"
#include "shl_misc.h"
#include "shl_ring.h"

#define LOG_SUBSYSTEM "pty"

#define KMSCON_NREAD 16384

struct kmscon_pty {
	unsigned long ref;
	struct ev_eloop *eloop;

	int fd;
	pid_t child;
	struct ev_fd *efd;
	struct shl_ring *msgbuf;
	char io_buf[KMSCON_NREAD];

	struct kmscon_conf_t *conf;

	kmscon_pty_input_cb input_cb;
	void *data;

	char *term;
	char *colorterm;
	char **argv;
	char *seat;
	char *vtnr;
	bool env_reset;
};

int kmscon_pty_new(struct kmscon_pty **out, struct kmscon_conf_t *conf, 
                   kmscon_pty_input_cb input_cb, void *data)
{
	struct kmscon_pty *pty;
	int ret;

	if (!out || !input_cb)
		return -EINVAL;

	pty = malloc(sizeof(*pty));
	if (!pty)
		return -ENOMEM;

	memset(pty, 0, sizeof(*pty));
	pty->fd = -1;
	pty->ref = 1;
	pty->conf = conf;
	pty->input_cb = input_cb;
	pty->data = data;

	ret = ev_eloop_new(&pty->eloop, log_llog, NULL);
	if (ret)
		goto err_free;

	ret = shl_ring_new(&pty->msgbuf);
	if (ret)
		goto err_eloop;

	log_debug("new pty object");
	*out = pty;
	return 0;

err_eloop:
	ev_eloop_unref(pty->eloop);
err_free:
	free(pty);
	return ret;
}

void kmscon_pty_ref(struct kmscon_pty *pty)
{
	if (!pty)
		return;

	pty->ref++;
}

void kmscon_pty_unref(struct kmscon_pty *pty)
{
	if (!pty || !pty->ref || --pty->ref)
		return;

	log_debug("free pty object");
	kmscon_pty_close(pty);
	free(pty->vtnr);
	free(pty->seat);
	free(pty->argv);
	free(pty->colorterm);
	free(pty->term);
	shl_ring_free(pty->msgbuf);
	ev_eloop_unref(pty->eloop);
	free(pty);
}

int kmscon_pty_set_term(struct kmscon_pty *pty, const char *term)
{
	char *t;

	if (!pty || !term)
		return -EINVAL;

	t = strdup(term);
	if (!t)
		return -ENOMEM;
	free(pty->term);
	pty->term = t;

	return 0;
}

int kmscon_pty_set_colorterm(struct kmscon_pty *pty, const char *colorterm)
{
	char *t;

	if (!pty || !colorterm)
		return -EINVAL;

	t = strdup(colorterm);
	if (!t)
		return -ENOMEM;
	free(pty->colorterm);
	pty->colorterm = t;

	return 0;
}

int kmscon_pty_set_argv(struct kmscon_pty *pty, char **argv)
{
	char **t;
	int ret;

	if (!pty || !argv || !*argv || !**argv)
		return -EINVAL;

	ret = shl_dup_array(&t, argv);
	if (ret)
		return ret;

	free(pty->argv);
	pty->argv = t;
	return 0;
}

int kmscon_pty_set_seat(struct kmscon_pty *pty, const char *seat)
{
	char *t;

	if (!pty || !seat)
		return -EINVAL;

	t = strdup(seat);
	if (!t)
		return -ENOMEM;
	free(pty->seat);
	pty->seat = t;

	return 0;
}

int kmscon_pty_set_vtnr(struct kmscon_pty *pty, unsigned int vtnr)
{
	char *t;
	int ret;

	if (!pty)
		return -EINVAL;

	ret = asprintf(&t, "%u", vtnr);
	if (ret < 0)
		return -ENOMEM;
	free(pty->vtnr);
	pty->vtnr = t;

	return 0;
}

void kmscon_pty_set_env_reset(struct kmscon_pty *pty, bool do_reset)
{
	if (!pty)
		return;

	pty->env_reset = do_reset;
}

int kmscon_pty_get_fd(struct kmscon_pty *pty)
{
	if (!pty)
		return -EINVAL;

	return ev_eloop_get_fd(pty->eloop);
}

void kmscon_pty_dispatch(struct kmscon_pty *pty)
{
	if (!pty)
		return;

	ev_eloop_dispatch(pty->eloop, 0);
}

static bool pty_is_open(struct kmscon_pty *pty)
{
	return pty->fd >= 0;
}

static void __attribute__((noreturn))
exec_child(const char *term, const char *colorterm, char **argv,
	   const char *seat, const char *vtnr, bool env_reset)
{
	char **env;
	char **def_argv;

	if (env_reset) {
		env = malloc(sizeof(char*));
		if (!env) {
			log_error("cannot allocate memory for environment (%d): %m",
				  errno);
			exit(EXIT_FAILURE);
		}

		memset(env, 0, sizeof(char*));
		environ = env;

		def_argv = (char*[]){ "/bin/login", "-p", NULL };
	} else {
		def_argv = (char*[]){ "/bin/login", NULL };
	}

	if (!term)
		term = "vt220";
	if (!argv)
		argv = def_argv;

	setenv("TERM", term, 1);
	if (colorterm)
		setenv("COLORTERM", colorterm, 1);
	if (seat)
		setenv("XDG_SEAT", seat, 1);
	if (vtnr)
		setenv("XDG_VTNR", vtnr, 1);

	execve(argv[0], argv, environ);

	log_err("failed to exec child %s: %m", argv[0]);

	exit(EXIT_FAILURE);
}

static void setup_child(int master, struct winsize *ws)
{
	int ret;
	sigset_t sigset;
	pid_t pid;
	char slave_name[128];
	int slave = -1, i;
	struct termios attr;

	/* The child should not inherit our signal mask. */
	sigemptyset(&sigset);
	ret = pthread_sigmask(SIG_SETMASK, &sigset, NULL);
	if (ret)
		log_warn("cannot reset blocked signals: %m");

	for (i = 1; i < SIGUNUSED; ++i)
		signal(i, SIG_DFL);

	ret = grantpt(master);
	if (ret < 0) {
		log_err("grantpt failed: %m");
		goto err_out;
	}

	ret = unlockpt(master);
	if (ret < 0) {
		log_err("cannot unlock pty: %m");
		goto err_out;
	}

	ret = ptsname_r(master, slave_name, sizeof(slave_name));
	if (ret) {
		log_err("cannot find slave name: %m");
		goto err_out;
	}

	/* This also loses our controlling tty. */
	pid = setsid();
	if (pid < 0) {
		log_err("cannot start a new session: %m");
		goto err_out;
	}

	/* And the slave pty becomes our controlling tty. */
	slave = open(slave_name, O_RDWR | O_CLOEXEC);
	if (slave < 0) {
		log_err("cannot open slave: %m");
		goto err_out;
	}

	/* get terminal attributes */
	if (tcgetattr(slave, &attr) < 0) {
		log_err("cannot get terminal attributes: %m");
		goto err_out;
	}

	/* erase character should be normal backspace */
	attr.c_cc[VERASE] = 010;

	/* set changed terminal attributes */
	if (tcsetattr(slave, TCSANOW, &attr) < 0) {
		log_warn("cannot set terminal attributes: %m");
		goto err_out;
	}

	if (ws) {
		ret = ioctl(slave, TIOCSWINSZ, ws);
		if (ret)
			log_warn("cannot set slave window size: %m");
	}

	if (dup2(slave, STDIN_FILENO) != STDIN_FILENO ||
			dup2(slave, STDOUT_FILENO) != STDOUT_FILENO ||
			dup2(slave, STDERR_FILENO) != STDERR_FILENO) {
		log_err("cannot duplicate slave: %m");
		goto err_out;
	}

	close(master);
	close(slave);
	return;

err_out:
	ret = -errno;
	if (slave >= 0)
		close(slave);
	close(master);
	exit(EXIT_FAILURE);
}

/*
 * This is functionally equivalent to forkpty(3). We do it manually to obtain
 * a little bit more control of the process, and as a bonus avoid linking to
 * the libutil library in glibc.
 */
static int pty_spawn(struct kmscon_pty *pty, int master,
			unsigned short width, unsigned short height)
{
	pid_t pid;
	struct winsize ws;

	memset(&ws, 0, sizeof(ws));
	ws.ws_col = width;
	ws.ws_row = height;

	pid = fork();
	switch (pid) {
	case -1:
		log_err("cannot fork: %m");
		return -errno;
	case 0:
		setup_child(master, &ws);
		exec_child(pty->term, pty->colorterm, pty->argv, pty->seat,
			   pty->vtnr, pty->env_reset);
		exit(EXIT_FAILURE);
	default:
		log_debug("forking child %d", pid);
		pty->fd = master;
		pty->child = pid;
		break;
	}

	return 0;
}

static int send_buf(struct kmscon_pty *pty)
{
	const char *buf;
	size_t len;
	int ret;

	while ((buf = shl_ring_peek(pty->msgbuf, &len, 0))) {
		ret = write(pty->fd, buf, len);
		if (ret > 0) {
			shl_ring_drop(pty->msgbuf, ret);
			continue;
		}

		if (ret < 0 && errno != EWOULDBLOCK) {
			log_warn("cannot write to child process (%d): %m",
				 errno);
			return ret;
		}

		/* EWOULDBLOCK */
		return 0;
	}

	ev_fd_update(pty->efd, EV_READABLE | EV_ET);
	return 0;
}

static int read_buf(struct kmscon_pty *pty)
{
	ssize_t len, num;
	int mask;

	/* Use a maximum of 50 steps to avoid staying here forever.
	 * TODO: recheck where else a user might flush our queues and try to
	 * install an explicit policy. */
	num = 50;
	do {
		len = read(pty->fd, pty->io_buf, sizeof(pty->io_buf));
		if (len > 0) {
			if (pty->input_cb)
				pty->input_cb(pty, pty->io_buf, len, pty->data);
		} else if (len == 0) {
			log_debug("HUP during read on pty of child %d",
				  pty->child);
			break;
		} else if (errno != EWOULDBLOCK) {
			log_debug("cannot read from pty of child %d (%d): %m",
				  pty->child, errno);
			break;
		}
	} while (len > 0 && --num);

	if (!num) {
		log_debug("cannot read application data fast enough");

		/* We are edge-triggered so update the mask to get the
		 * EV_READABLE event again next round. */
		mask = EV_READABLE | EV_ET;
		if (!shl_ring_is_empty(pty->msgbuf))
			mask |= EV_WRITEABLE;
		ev_fd_update(pty->efd, mask);
	}

	return 0;
}

static void pty_input(struct ev_fd *fd, int mask, void *data)
{
	struct kmscon_pty *pty = data;

	/* Programs like /bin/login tend to perform a vhangup() on their TTY
	 * before running the login procedure. This also causes the pty master
	 * to get a EV_HUP event as long as no client has the TTY opened.
	 * This means, we cannot use the TTY connection as reliable way to track
	 * the client. Instead, we _must_ rely on the PID of the client to track
	 * them.
	 * However, this has the side effect that if the client forks and the
	 * parent exits, we loose them and restart the client. But this seems to
	 * be the expected behavior so we implement it here.
	 * Unfortunately, epoll always polls for EPOLLHUP so as long as the
	 * vhangup() is ongoing, we will _always_ get EPOLLHUP and cannot sleep.
	 * This gets worse if the client closes the TTY but doesn't exit.
	 * Therefore, we set the fd as edge-triggered in the epoll-set so we
	 * only get the events once they change. This has to be taken into
	 * account at all places of kmscon_pty to avoid missing events. */

	if (mask & EV_ERR)
		log_warn("error on pty socket of child %d", pty->child);
	if (mask & EV_HUP)
		log_debug("HUP on pty of child %d", pty->child);
	if (mask & EV_WRITEABLE)
		send_buf(pty);
	if (mask & EV_READABLE)
		read_buf(pty);
}

static void sig_child(struct ev_eloop *eloop, struct ev_child_data *chld,
			void *data)
{
	struct kmscon_pty *pty = data;

	if (chld->pid != pty->child)
		return;

	log_info("child exited: pid: %u status: %d",
		 chld->pid, chld->status);

	pty->input_cb(pty, NULL, 0, pty->data);
}

/*
 * Appends the given character to the buffer and increments *len. In the 
 * event that the buffer does not have enough space for the new character 
 * (judged via *size), the buffer will be reallocated with double the 
 * current size and the respective pointers will be updated.
 * 
 * Returns 0 on success, -EINVAL if there are NULL pointers (including *buf),
 * if size == 0, or if *len > *size. Returns -ENOMEM if expanding the buffer
 * fails. If the buffer can't be expanded, the pointer at *buf is left 
 * unchanged and is still valid, although the new character will not have 
 * been added (i.e., you still need to call free).
 */
int bputc(int c, char **buf, int *len, int *size) {
	char *abuf;
	int asize, alen;

	if (!buf || !*buf || !len || !size)
		return -EINVAL;

	abuf = *buf;
	asize = *size;
	alen = *len;

	if (!size || alen > asize)
		return -EINVAL;

	if (alen == asize) {
		abuf = realloc(abuf, 2 * asize);
		if (!abuf)
			return -ENOMEM;
		asize *= 2;

		*buf = abuf;
		*size = asize;
	}

	abuf[alen] = c;
	alen++;
	*len = alen;

	return 0;
}

/*
 * Appends the format string processed in conformance to printf (via the
 * dynamic arguments at the end) to the given buffer and increments *len.
 * In teh event that the vuffer does not have enough space for the new
 * characters, the buffer will be reallocated to a sufficiently large size
 * and the respective pointers will be updated.
 * 
 * Returns the number of characters written, or a negative error code.
 * Returns -EINVAL if there are NULL pointers (including *buf), if size == 0,
 * or if *len > *size. Returns -ENOMEM if expanding the buffer fails. If the 
 * buffer can't be expanded, the pointer at *buf is left unchanged and is still 
 * valid, although the new character will not have been added (i.e., you still
 * need to call free). If the vsnprintf call fails, then this function returns 
 * its return value.
 */
__attribute__((format (printf, 4, 5)))
int bprintf(char **buf, int *len, int *size, const char *format, ...) {
	va_list args;
	char *abuf;
	int asize, alen, flen;

	if (!buf || !*buf || !len || !size)
		return -EINVAL;

	abuf = *buf;
	asize = *size;
	alen = *len;

	if (!size || alen > asize)
		return -EINVAL;

	va_start(args, format);
	flen = vsnprintf(NULL, 0, format, args);
	va_end(args);

	if (flen < 0)
		return flen;

	if (alen + flen + 1 >= asize) {
		while (alen + flen + 1 >= asize)
			asize *= 2;
		abuf = realloc(abuf, asize);
		if (!abuf)
			return -ENOMEM;

		*buf = abuf;
		*size = asize;
	}

	va_start(args, format);
	flen = vsnprintf(abuf + alen, flen + 1, format, args);
	va_end(args);

	if (flen > 0) {
		alen += flen;
		*len = alen;
	}

	return flen;
}

// BEGIN ADAPTED AGETTY CODE

/*
 * MAXHOSTNAMELEN replacement
 */
static inline size_t get_hostname_max(void)
{
	long len = sysconf(_SC_HOST_NAME_MAX);

	if (len > 0)
		return len;

#ifdef MAXHOSTNAMELEN
	return MAXHOSTNAMELEN;
#elif HOST_NAME_MAX
	return HOST_NAME_MAX;
#endif
	return 64;
}

static int xgethostname(char **out)
{
	char *name;
	const size_t sz = get_hostname_max() + 1;

	if (!out)
		return -EINVAL;

	name = malloc(sizeof(char) * sz);
	if (!name) {
		log_error("cannot allocate memory for domain name");
		return -ENOMEM;
	}
	
	if (!gethostname(name, sz)) {
		free(name);
		return errno;
	}
	name[sz - 1] = '\0';
	*out = name;

	return 0;
}

static int xgetdomainname(char **out)
{
	char *name;
	const size_t sz  = get_hostname_max() + 1;

	if (!out)
		return -EINVAL;

	name = malloc(sizeof(char) * sz);
	if (!name) {
		log_error("cannot allocate memory for domain name");
		return -ENOMEM;
	}
	
	if (!getdomainname(name, sz)) {
		free(name);
		return errno;
	}
	name[sz - 1] = '\0';
	*out = name;

	return 0;
}

static int print_addr(sa_family_t family, void *addr, char **buf, int *len, int *size)
{
	char buff[INET6_ADDRSTRLEN + 1];

	if (!inet_ntop(family, addr, buff, sizeof(buff)))
		return errno;

	return bprintf(buf, len, size, "%s", buff);
}

/*
 * Prints IP for the specified interface (@iface), if the interface is not
 * specified then prints the "best" one (UP, RUNNING, non-LOOPBACK). If not
 * found the "best" interface then prints at least host IP.
 */
static int output_iface_ip(struct ifaddrs *addrs, const char *iface,
                            sa_family_t family, char **buf, int *len, int *size)
{
	struct ifaddrs *p;
	struct addrinfo hints, *info = NULL;
	char *host = NULL;
	void *addr = NULL;
	int ret;

	if (!addrs)
		return -EINVAL;

	for (p = addrs; p; p = p->ifa_next) {

		if (!p->ifa_name ||
		    !p->ifa_addr ||
		    p->ifa_addr->sa_family != family)
			continue;

		if (iface) {
			/* Filter out by interface name */
		       if (strcmp(p->ifa_name, iface) != 0)
				continue;
		} else {
			/* Select the "best" interface */
			if ((p->ifa_flags & IFF_LOOPBACK) ||
			    !(p->ifa_flags & IFF_UP) ||
			    !(p->ifa_flags & IFF_RUNNING))
				continue;
		}

		addr = NULL;
		switch (p->ifa_addr->sa_family) {
		case AF_INET:
			addr = &((struct sockaddr_in *)	p->ifa_addr)->sin_addr;
			break;
		case AF_INET6:
			addr = &((struct sockaddr_in6 *) p->ifa_addr)->sin6_addr;
			break;
		}

		if (addr) {
			return print_addr(family, addr, buf, len, size);
		}
	}

	if (iface)
		return -EINVAL;

	/* Hmm.. not found the best interface, print host IP at least */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	if (family == AF_INET6)
		hints.ai_flags = AI_V4MAPPED;

	ret = xgethostname(&host);
	if (ret)
		return ret;

	ret = getaddrinfo(host, NULL, &hints, &info); 
	if (ret)
		goto err_host;

	switch (info->ai_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *) info->ai_addr)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *) info->ai_addr)->sin6_addr;
		break;
	}

	ret = print_addr(family, addr, buf, len, size);

	freeaddrinfo(info);
err_host:
	free(host);
	return ret;
}

/*
 * parses \x{argument}, if not argument specified then returns NULL, the @fd
 * has to point to one char after the sequence (it means '{').
 */
static char *get_escape_argument(FILE *fd, char *buf, size_t bufsz)
{
	size_t i = 0;
	int c = fgetc(fd);

	if (c == EOF || (unsigned char) c != '{') {
		ungetc(c, fd);
		return NULL;
	}

	do {
		c = fgetc(fd);
		if (c == EOF)
			return NULL;
		if ((unsigned char) c != '}' && i < bufsz - 1)
			buf[i++] = (unsigned char) c;

	} while ((unsigned char) c != '}');

	buf[i] = '\0';
	return buf;
}

static int output_special_char(unsigned char c, struct kmscon_conf_t *conf,
                                char * tty, FILE *fp, char **buf, int *len, int *size)
{
	struct utsname uts;
	int ret;

	switch (c) {
	case 'e':
	{
		char escname[UL_COLORNAME_MAXSZ];

		if (get_escape_argument(fp, escname, sizeof(escname))) {
			const char *esc = color_sequence_from_colorname(escname);
			if (esc)
				return bprintf(buf, len, size, "%s", esc);
		} else {
			return bprintf(buf, len, size, "\033");
		}
		return -EINVAL;
	}
	case 's':
		if (uname(&uts))
			return errno;
		return bprintf(buf, len, size, "%s", uts.sysname);
	case 'n':
		if (uname(&uts))
			return errno;
		return bprintf(buf, len, size, "%s", uts.nodename);
	case 'r':
		if (uname(&uts))
			return errno;
		return bprintf(buf, len, size, "%s", uts.release);
	case 'v':
		if (uname(&uts))
			return errno;
		return bprintf(buf, len, size, "%s", uts.version);
	case 'm':
		if (uname(&uts))
			return errno;
		return bprintf(buf, len, size, "%s", uts.machine);
	case 'o':
	{
		char *dom = NULL;
		ret = xgetdomainname(&dom);
		if (ret)
			return ret;

		ret = bprintf(buf, len, size, "%s", dom ? dom : "unknown_domain");
		free(dom);
		return ret;
	}
	case 'O':
	{
		char *dom = NULL;
		char *host = NULL;
		char *canon = NULL;
		struct addrinfo hints, *info = NULL;

		ret = xgethostname(&host);
		if (ret)
			return ret;

		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_CANONNAME;

		ret = getaddrinfo(host, NULL, &hints, &info);
		if (ret)
			return ret;

		if (info->ai_canonname && (canon = strchr(info->ai_canonname, '.')))
			dom = canon + 1;

		ret = bprintf(buf, len, size, "%s", dom ? dom : "unknown_domain");
		if (info)
			freeaddrinfo(info);
		free(host);
		return ret;
	}
	case 'd':
	case 't':
	{
		time_t now;
		struct tm *tm;

		if (time(&now) == -1)
			return errno;
		tm = localtime(&now);
		if (!tm)
			return errno;

		if (c == 'd') /* ISO 8601 */
			return bprintf(buf, len, size, "%s %s %d  %d",
			               nl_langinfo(ABDAY_1 + tm->tm_wday),
			               nl_langinfo(ABMON_1 + tm->tm_mon),
			               tm->tm_mday,
			               tm->tm_year < 70 ? tm->tm_year + 2000 :
			               tm->tm_year + 1900);
		else
			return bprintf(buf, len, size, "%02d:%02d:%02d",
			               tm->tm_hour, tm->tm_min, tm->tm_sec);
	}
	case 'l':
		return bprintf (buf, len, size, "%s", tty);
	case 'b':
	{
		// TODO Get's the baud rate. Possibly add in later.
		return -EINVAL;
	}
	case 'S':
	{
		// TODO this one's complicated... work it out later.
		return -EINVAL;
	}
	case 'u':
	case 'U':
	{
		int users = 0;
		struct utmpx *ut;

		// There could be errors here, but properly handling this
		// gets complicated, so.... whatever.
		setutxent();
		while ((ut = getutxent()))
			if (ut->ut_type == USER_PROCESS)
				users++;
		endutxent();

		if (c == 'U')
			return bprintf(buf, len, size, (users == 1 ? "%d user" : "%d users"), users);
		else
			return bprintf (buf, len, size, "%d ", users);
	}
	case '4':
	case '6':
	{
		sa_family_t family = c == '4' ? AF_INET : AF_INET6;
		struct ifaddrs *addrs = NULL;
		char iface[128];

// TODO Possibly add this in
#ifdef AGETTY_RELOAD
		open_netlink();
#endif

		if (getifaddrs(&addrs))
			return errno;

		if (get_escape_argument(fp, iface, sizeof(iface)))
			ret = output_iface_ip(addrs, iface, family, buf, len, size);
		else
			ret = output_iface_ip(addrs, NULL, family, buf, len, size);

		freeifaddrs(addrs);
		return ret;
	}
	default:
		return bputc(c, buf, len, size);
	}

	// This should never happen
	return -EINVAL;
}

static int print_issue_file(struct kmscon_pty *pty, char *tty)
{
	FILE *fd;
	struct kmscon_conf_t *conf;
	int c;
	char *buf;
	int len, size, ret;

	ret = 0;
	conf = pty->conf;

	if (!conf->issue || !pty->input_cb) {
		return 0;
	}

	len = 0;
	size = 256;
	buf = malloc(256 * sizeof(char));
	if (!buf) {
		return -ENOMEM;
	}


	fd = fopen(conf->isfile, "r");
	if (!fd) {
		ret = errno;
		goto err_buf;
	}

	// Before every iteration, we need to clear errno
	// as the only reliable way to detect if the call
	// fails is to check errno; however, many of the
	// incidental calls will also set errno so we don't 
	// want a false positive.
	errno = 0;
	while ((c = getc(fd)) != EOF) {
		if (c == '\\') {
			c = getc(fd);
			if (c == EOF) 
				break;
			log_debug("issue special char: %c",c);
			ret = output_special_char(c, conf, tty, fd, &buf, &len, &size);
		} else {
			ret = bputc(c, &buf, &len, &size);
		}
			if (ret < 0)
				goto err_fd;

		errno = 0;
	}
	if (errno) {
		ret = errno;
		goto err_fd;
	}

	ret = bputc('\0', &buf, &len, &size);
	if (ret)
		goto err_fd;

	pty->input_cb(pty, buf, len, pty->data);

	err_fd:
		// We always want to close the fd. If it fails, only
		// log the error if no error has occurred yet.
		if (!fclose(fd) && !ret)
			ret = errno;
	err_buf:
		free(buf);
		return ret;
}

// END OF ADAPTED AGETTY CODE

int kmscon_pty_open(struct kmscon_pty *pty, unsigned short width,
							unsigned short height)
{
	int ret;
	int master;
	char *name;

	if (!pty)
		return -EINVAL;

	if (pty_is_open(pty))
		return -EALREADY;

	master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
	if (master < 0) {
		log_err("cannot open master: %m");
		return -errno;
	}

	ret = ev_eloop_new_fd(pty->eloop, &pty->efd, master,
			      EV_ET | EV_READABLE, pty_input, pty);
	if (ret)
		goto err_master;

	ret = ev_eloop_register_child_cb(pty->eloop, sig_child, pty);
	if (ret)
		goto err_fd;

	name = ptsname(master);
	if (!name) {
		log_err("could not retrieve master name, skipping issue");
	} else {
		ret = print_issue_file(pty, name);
		if (ret) {
			log_err("could not print issue: %d", ret);
			ret = 0;
		}
	}

	ret = pty_spawn(pty, master, width, height);
	if (ret)
		goto err_sig;

	return 0;

err_sig:
	ev_eloop_unregister_child_cb(pty->eloop, sig_child, pty);
err_fd:
	ev_eloop_rm_fd(pty->efd);
	pty->efd = NULL;
err_master:
	close(master);
	return ret;
}

void kmscon_pty_close(struct kmscon_pty *pty)
{
	if (!pty || !pty_is_open(pty))
		return;

	ev_eloop_rm_fd(pty->efd);
	pty->efd = NULL;
	ev_eloop_unregister_child_cb(pty->eloop, sig_child, pty);
	close(pty->fd);
	pty->fd = -1;
}

int kmscon_pty_write(struct kmscon_pty *pty, const char *u8, size_t len)
{
	int ret;

	if (!pty || !pty_is_open(pty) || !u8 || !len)
		return -EINVAL;

	if (!shl_ring_is_empty(pty->msgbuf))
		goto buf;

	ret = write(pty->fd, u8, len);
	if (ret < 0) {
		if (errno != EWOULDBLOCK) {
			log_warn("cannot write to child process");
			return ret;
		}
	} else if (ret >= len) {
		return 0;
	} else if (ret > 0) {
		len -= ret;
		u8 = &u8[ret];
	}

	ev_fd_update(pty->efd, EV_READABLE | EV_WRITEABLE | EV_ET);

buf:
	ret = shl_ring_write(pty->msgbuf, u8, len);
	if (ret)
		log_warn("cannot allocate buffer; dropping output");

	return 0;
}

void kmscon_pty_signal(struct kmscon_pty *pty, int signum)
{
	int ret;

	if (!pty || !pty_is_open(pty) || signum < 0)
		return;

	ret = ioctl(pty->fd, TIOCSIG, signum);
	if (ret) {
		log_warn("cannot send signal %d to child", signum);
		return;
	}

	log_debug("send signal %d to child", signum);
}

void kmscon_pty_resize(struct kmscon_pty *pty,
			unsigned short width, unsigned short height)
{
	int ret;
	struct winsize ws;

	if (!pty || !pty_is_open(pty))
		return;

	memset(&ws, 0, sizeof(ws));
	ws.ws_col = width;
	ws.ws_row = height;

	/*
	 * This will send SIGWINCH to the pty slave foreground process group.
	 * We will also get one, but we don't need it.
	 */
	ret = ioctl(pty->fd, TIOCSWINSZ, &ws);
	if (ret) {
		log_warn("cannot set window size");
		return;
	}
}
