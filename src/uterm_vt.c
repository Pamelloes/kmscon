/*
 * uterm - Linux User-Space Terminal
 *
 * Copyright (c) 2011-2012 David Herrmann <dh.herrmann@googlemail.com>
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

/*
 * Virtual Terminals
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <termios.h>
#include <unistd.h>
#include "eloop.h"
#include "log.h"
#include "static_misc.h"
#include "uterm.h"
#include "uterm_internal.h"

#define LOG_SUBSYSTEM "vt"

struct uterm_vt {
	unsigned long ref;
	struct kmscon_dlist list;
	struct uterm_vt_master *vtm;
	unsigned int mode;

	uterm_vt_cb cb;
	void *data;

	bool active;

	/* this is for *real* linux kernel VTs */
	int real_fd;
	int real_num;
	int real_saved_num;
	struct termios real_saved_attribs;
	struct ev_fd *real_efd;
};

struct uterm_vt_master {
	unsigned long ref;
	struct ev_eloop *eloop;

	bool vt_support;
	struct kmscon_dlist vts;
};

static int vt_call(struct uterm_vt *vt, unsigned int event)
{
	int ret;

	switch (event) {
	case UTERM_VT_ACTIVATE:
		if (!vt->active) {
			if (vt->cb) {
				ret = vt->cb(vt, event, vt->data);
				if (ret)
					log_warning("vt event handler returned %d instead of 0 on activation", ret);
			}
			vt->active = true;
		}
		break;
	case UTERM_VT_DEACTIVATE:
		if (vt->active) {
			if (vt->cb) {
				ret = vt->cb(vt, event, vt->data);
				if (ret)
					return ret;
			}
			vt->active = false;
		}
		break;
	}

	return 0;
}

static void real_enter(struct ev_eloop *eloop, struct signalfd_siginfo *info,
		       void *data)
{
	struct uterm_vt *vt = data;
	struct vt_stat vts;
	int ret;

	if (vt->real_fd < 0)
		return;

	ret = ioctl(vt->real_fd, VT_GETSTATE, &vts);
	if (ret || vts.v_active != vt->real_num)
		return;

	log_debug("enter VT %d %p", vt->real_num, vt);

	ioctl(vt->real_fd, VT_RELDISP, VT_ACKACQ);

	if (ioctl(vt->real_fd, KDSETMODE, KD_GRAPHICS))
		log_warn("cannot set graphics mode on vt %p", vt);

	vt_call(vt, UTERM_VT_ACTIVATE);
}

static void real_leave(struct ev_eloop *eloop, struct signalfd_siginfo *info,
		       void *data)
{
	struct uterm_vt *vt = data;
	struct vt_stat vts;
	int ret;

	if (vt->real_fd < 0)
		return;

	ret = ioctl(vt->real_fd, VT_GETSTATE, &vts);
	if (ret || vts.v_active != vt->real_num)
		return;

	if (vt_call(vt, UTERM_VT_DEACTIVATE)) {
		log_debug("leaving VT %d %p denied", vt->real_num, vt);
		ioctl(vt->real_fd, VT_RELDISP, 0);
	} else {
		log_debug("leaving VT %d %p", vt->real_num, vt);
		ioctl(vt->real_fd, VT_RELDISP, 1);
		if (ioctl(vt->real_fd, KDSETMODE, KD_TEXT))
			log_warn("cannot set text mode on vt %p", vt);
	}
}

static void real_input(struct ev_fd *fd, int mask, void *data)
{
	struct uterm_vt *vt = data;

	if (vt->real_fd < 0)
		return;

	/* we ignore input from the VT because we get it from evdev */
	tcflush(vt->real_fd, TCIFLUSH);
}

static int open_tty(int id, int *tty_fd, int *tty_num)
{
	int fd;
	char filename[16];

	if (!tty_fd || !tty_num)
		return -EINVAL;

	if (id < 0) {
		fd = open("/dev/tty0", O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
		if (fd < 0) {
			fd = open("/dev/tty1",
					O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
			if (fd < 0) {
				log_err("cannot find parent tty");
				return -errno;
			}
		}

		if (ioctl(fd, VT_OPENQRY, &id) || id <= 0) {
			close(fd);
			log_err("cannot get unused tty");
			return -EINVAL;
		}
		close(fd);
	}

	snprintf(filename, sizeof(filename), "/dev/tty%d", id);
	filename[sizeof(filename) - 1] = 0;
	log_notice("using tty %s", filename);

	fd = open(filename, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		log_err("cannot open tty %s", filename);
		return -errno;
	}

	*tty_fd = fd;
	*tty_num = id;
	return 0;
}

static int real_open(struct uterm_vt *vt)
{
	struct termios raw_attribs;
	struct vt_mode mode;
	struct vt_stat vts;
	int ret;
	sigset_t mask;

	if (vt->real_fd >= 0)
		return -EALREADY;

	log_debug("open vt %p", vt);

	ret = open_tty(-1, &vt->real_fd, &vt->real_num);
	if (ret)
		return ret;

	ret = ev_eloop_register_signal_cb(vt->vtm->eloop, SIGUSR1, real_leave,
					  vt);
	if (ret)
		goto err_fd;

	ret = ev_eloop_register_signal_cb(vt->vtm->eloop, SIGUSR2, real_enter,
					  vt);
	if (ret)
		goto err_sig1;

	ret = ev_eloop_new_fd(vt->vtm->eloop, &vt->real_efd, vt->real_fd,
			      EV_READABLE, real_input, vt);
	if (ret)
		goto err_sig2;

	/*
	 * Get the number of the VT which is active now, so we have something
	 * to switch back to in kmscon_vt_switch_leave.
	 */
	ret = ioctl(vt->real_fd, VT_GETSTATE, &vts);
	if (ret) {
		log_warn("cannot find the currently active VT");
		vt->real_saved_num = -1;
	} else {
		vt->real_saved_num = vts.v_active;
	}

	if (tcgetattr(vt->real_fd, &vt->real_saved_attribs) < 0) {
		log_err("cannot get terminal attributes");
		ret = -EFAULT;
		goto err_eloop;
	}

	/* Ignore control characters and disable echo */
	raw_attribs = vt->real_saved_attribs;
	cfmakeraw(&raw_attribs);

	/* Fix up line endings to be normal (cfmakeraw hoses them) */
	raw_attribs.c_oflag |= OPOST | OCRNL;

	if (tcsetattr(vt->real_fd, TCSANOW, &raw_attribs) < 0)
		log_warn("cannot put terminal into raw mode");

	if (ioctl(vt->real_fd, KDSETMODE, KD_GRAPHICS)) {
		log_err("vt: cannot set graphics mode\n");
		ret = -errno;
		goto err_reset;
	}

	memset(&mode, 0, sizeof(mode));
	mode.mode = VT_PROCESS;
	mode.relsig = SIGUSR1;
	mode.acqsig = SIGUSR2;

	if (ioctl(vt->real_fd, VT_SETMODE, &mode)) {
		log_err("cannot take control of vt handling");
		ret = -errno;
		goto err_text;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	return 0;

err_text:
	ioctl(vt->real_fd, KDSETMODE, KD_TEXT);
err_reset:
	tcsetattr(vt->real_fd, TCSANOW, &vt->real_saved_attribs);
err_eloop:
	ev_eloop_rm_fd(vt->real_efd);
	vt->real_efd = NULL;
err_sig2:
	ev_eloop_unregister_signal_cb(vt->vtm->eloop, SIGUSR2, real_enter, vt);
err_sig1:
	ev_eloop_unregister_signal_cb(vt->vtm->eloop, SIGUSR1, real_leave, vt);
err_fd:
	close(vt->real_fd);
	vt->real_fd = -1;
	return ret;
}

static void real_close(struct uterm_vt *vt)
{
	if (vt->real_fd < 0)
		return;

	log_debug("closing vt %p", vt);
	ioctl(vt->real_fd, KDSETMODE, KD_TEXT);
	tcsetattr(vt->real_fd, TCSANOW, &vt->real_saved_attribs);
	ev_eloop_rm_fd(vt->real_efd);
	ev_eloop_unregister_signal_cb(vt->vtm->eloop, SIGUSR2, real_enter, vt);
	ev_eloop_unregister_signal_cb(vt->vtm->eloop, SIGUSR1, real_leave, vt);
	vt->real_efd = NULL;
	close(vt->real_fd);

	vt->real_fd = -1;
	vt->real_num = -1;
	vt->real_saved_num = -1;
}

/* Switch to this VT and make it the active VT. */
static int real_activate(struct uterm_vt *vt)
{
	int ret;

	if (vt->real_fd < 0 || vt->real_num < 0)
		return -EINVAL;

	ret = ioctl(vt->real_fd, VT_ACTIVATE, vt->real_num);
	if (ret) {
		log_warn("cannot enter VT %p", vt);
		return -EFAULT;
	}

	log_debug("entering VT %p on demand", vt);
	return 0;
}

/*
 * Switch back to the VT from which we started.
 * Note: The VT switch needs to be acknowledged by us so we need to react on
 * SIGUSR. This function returns -EINPROGRESS if we started the VT switch but
 * still needs to react on SIGUSR. Make sure you call the eloop dispatcher again
 * if you get -EINPROGRESS here.
 *
 * Returns 0 if we don't know the previous VT or if the previous VT is already
 * active. Returns -EINPROGRESS if we started the VT switch. Returns <0 on
 * failure.
 */
static int real_deactivate(struct uterm_vt *vt)
{
	int ret;
	struct vt_stat vts;

	if (vt->real_fd < 0)
		return -EINVAL;

	if (vt->real_saved_num < 0)
		return 0;

	ret = ioctl(vt->real_fd, VT_GETSTATE, &vts);
	if (ret) {
		log_warn("cannot find current VT");
		return -EFAULT;
	}

	if (vts.v_active != vt->real_num)
		return 0;

	ret = ioctl(vt->real_fd, VT_ACTIVATE, vt->real_saved_num);
	if (ret) {
		log_warn("cannot leave VT %p", vt);
		return -EFAULT;
	}

	log_debug("leaving VT %p on demand", vt);
	return -EINPROGRESS;
}

static bool check_vt_support(void)
{
	if (!access("/dev/tty", F_OK))
		return true;
	else
		return false;
}

static void vt_idle_event(struct ev_eloop *eloop, void *unused, void *data)
{
	struct uterm_vt *vt = data;

	ev_eloop_unregister_idle_cb(eloop, vt_idle_event, data);
	vt_call(vt, UTERM_VT_ACTIVATE);
}

int uterm_vt_allocate(struct uterm_vt_master *vtm,
		      struct uterm_vt **out,
		      const char *seat,
		      uterm_vt_cb cb,
		      void *data)
{
	struct uterm_vt *vt;
	int ret;

	if (!vtm || !out)
		return -EINVAL;
	if (!seat)
		seat = "seat0";

	vt = malloc(sizeof(*vt));
	if (!vt)
		return -ENOMEM;
	memset(vt, 0, sizeof(*vt));
	vt->ref = 1;
	vt->vtm = vtm;
	vt->cb = cb;
	vt->data = data;

	vt->real_fd = -1;
	vt->real_num = -1;
	vt->real_saved_num = -1;

	if (!strcmp(seat, "seat0") && vtm->vt_support) {
		vt->mode = UTERM_VT_REAL;
		ret = real_open(vt);
		if (ret)
			goto err_free;
	} else {
		vt->mode = UTERM_VT_FAKE;
		ret = ev_eloop_register_idle_cb(vtm->eloop, vt_idle_event, vt);
		if (ret)
			goto err_free;
	}

	kmscon_dlist_link(&vtm->vts, &vt->list);
	*out = vt;
	return 0;

err_free:
	free(vt);
	return ret;
}

void uterm_vt_deallocate(struct uterm_vt *vt)
{
	if (!vt || !vt->vtm)
		return;

	if (vt->mode == UTERM_VT_REAL) {
		real_close(vt);
	} else {
		ev_eloop_unregister_idle_cb(vt->vtm->eloop, vt_idle_event,
					    vt);
		vt_call(vt, UTERM_VT_DEACTIVATE);
	}
	kmscon_dlist_unlink(&vt->list);
	vt->vtm = NULL;
	uterm_vt_unref(vt);
}

void uterm_vt_ref(struct uterm_vt *vt)
{
	if (!vt || !vt->ref)
		return;

	++vt->ref;
}

void uterm_vt_unref(struct uterm_vt *vt)
{
	if (!vt || !vt->ref || --vt->ref)
		return;

	uterm_vt_deallocate(vt);
	free(vt);
}

int uterm_vt_activate(struct uterm_vt *vt)
{
	if (!vt || !vt->vtm)
		return -EINVAL;

	if (vt->mode == UTERM_VT_REAL)
		return real_activate(vt);
	else
		return -EFAULT;
}

int uterm_vt_deactivate(struct uterm_vt *vt)
{
	if (!vt || !vt->vtm)
		return -EINVAL;

	if (vt->mode == UTERM_VT_REAL)
		return real_deactivate(vt);
	else
		return -EFAULT;
}

int uterm_vt_master_new(struct uterm_vt_master **out,
			struct ev_eloop *eloop)
{
	struct uterm_vt_master *vtm;

	if (!out || !eloop)
		return -EINVAL;

	vtm = malloc(sizeof(*vtm));
	if (!vtm)
		return -ENOMEM;
	memset(vtm, 0, sizeof(*vtm));
	vtm->ref = 1;
	vtm->eloop = eloop;
	kmscon_dlist_init(&vtm->vts);
	vtm->vt_support = check_vt_support();

	ev_eloop_ref(vtm->eloop);
	*out = vtm;
	return 0;
}

void uterm_vt_master_ref(struct uterm_vt_master *vtm)
{
	if (!vtm || !vtm->ref)
		return;

	++vtm->ref;
}

void uterm_vt_master_unref(struct uterm_vt_master *vtm)
{
	struct uterm_vt *vt;

	if (!vtm || !vtm->ref || --vtm->ref)
		return;

	while (vtm->vts.next != &vtm->vts) {
		vt = kmscon_dlist_entry(vtm->vts.next,
					struct uterm_vt,
					list);
		uterm_vt_deallocate(vt);
	}

	ev_eloop_unref(vtm->eloop);
	free(vtm);
}
