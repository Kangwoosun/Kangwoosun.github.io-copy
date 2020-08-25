---
title: TDCTF 2018 - sandbox_school_5
categories:
 - pwnable
tags: shellcode, seccomp, sandbox, sandbox_escape
---

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference


## Introduction


## Vunlnerability

```c
// gcc sb_school_5.c -o sb5
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "seccomp-bpf.h"

static int install_syscall_filter(void)
{
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		DISALLOW_SYSCALL(open),
		DISALLOW_SYSCALL(openat),
		DISALLOW_SYSCALL(fork),
		DISALLOW_SYSCALL(vfork),
		DISALLOW_SYSCALL(clone),
		DISALLOW_SYSCALL(creat),
		DISALLOW_SYSCALL(ptrace),
		DISALLOW_SYSCALL(prctl),
		DISALLOW_SYSCALL(execve),
		DISALLOW_SYSCALL(execveat),
		ALLOW_PROCESS
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL)
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	return 1;
}

int main()
{
	void (*sc)();
	unsigned char *shellcode;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (shellcode == MAP_FAILED) {
		printf("[err] Please, let me know this issue (hackability@naver.com)\n");
		return -1;
	}

	printf("[*] Welcome to sandbox school for beginner!\n");
	printf("[*] Put your shellcode as binary stream. I'll ready for your input as read(0, shellcode, 1024)\n");
	printf("[*] Lv   : Troll\n");
	printf("[*] Desc : Now, you can't see me.\n");
	printf("> ");

	alarm(10);

	read(0, shellcode, 1024);

	for(int i=0 ; i<1024-1; i++) {
		if (shellcode[i] == 0x0f && shellcode[i+1] == 0x05) {
			printf("[*] blocked !\n");
			return -1;
		}
	}

	install_syscall_filter();

	sc = (void *)shellcode;
	sc();	
	
	return 0;
}

```



## Exploit

```c
SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
	struct task_struct *me = current;
	unsigned char comm[sizeof(me->comm)];
	long error;
	error = security_task_prctl(option, arg2, arg3, arg4, arg5);
	if (error != -ENOSYS)
		return error;
	error = 0;
	switch (option) {

	/* snip.. */

	case PR_SET_SECCOMP:
		error = prctl_set_seccomp(arg2, (char __user *)arg3);
		break;

	/* snip.. */

	default:
		error = -EINVAL;
		break;
	}
	return error;
}
```

```c
long prctl_set_seccomp(unsigned long seccomp_mode, void __user *filter)
{
	unsigned int op;
	void __user *uargs;
	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		op = SECCOMP_SET_MODE_STRICT;
		/*
		 * Setting strict mode through prctl always ignored filter,
		 * so make sure it is always NULL here to pass the internal
		 * check in do_seccomp().
		 */
		uargs = NULL;
		break;
	case SECCOMP_MODE_FILTER:
		op = SECCOMP_SET_MODE_FILTER;
		uargs = filter;
		break;
	default:
		return -EINVAL;
	}
	/* prctl interface doesn't have flags, so they are always zero. */
	return do_seccomp(op, 0, uargs);
}
```

```c
static long do_seccomp(unsigned int op, unsigned int flags,
		       void __user *uargs)
{
	switch (op) {
	case SECCOMP_SET_MODE_STRICT:
		if (flags != 0 || uargs != NULL)
			return -EINVAL;
		return seccomp_set_mode_strict();
	case SECCOMP_SET_MODE_FILTER:
		return seccomp_set_mode_filter(flags, uargs);
	case SECCOMP_GET_ACTION_AVAIL:
		if (flags != 0)
			return -EINVAL;
		return seccomp_get_action_avail(uargs);
	case SECCOMP_GET_NOTIF_SIZES:
		if (flags != 0)
			return -EINVAL;
		return seccomp_get_notif_sizes(uargs);
	default:
		return -EINVAL;
	}
}
```
```c
static long seccomp_set_mode_filter(unsigned int flags,
				    const char __user *filter)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_FILTER;
	struct seccomp_filter *prepared = NULL;
	long ret = -EINVAL;
	int listener = -1;
	struct file *listener_f = NULL;
	/* Validate flags. */
	if (flags & ~SECCOMP_FILTER_FLAG_MASK)
		return -EINVAL;
	/* Prepare the new filter before holding any locks. */
	prepared = seccomp_prepare_user_filter(filter);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);
	if (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
		listener = get_unused_fd_flags(O_CLOEXEC);
		if (listener < 0) {
			ret = listener;
			goto out_free;
		}
		listener_f = init_listener(prepared);
		if (IS_ERR(listener_f)) {
			put_unused_fd(listener);
			ret = PTR_ERR(listener_f);
			goto out_free;
		}
	}
	/*
	 * Make sure we cannot change seccomp or nnp state via TSYNC
	 * while another thread is in the middle of calling exec.
	 */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC &&
	    mutex_lock_killable(&current->signal->cred_guard_mutex))
		goto out_put_fd;
	spin_lock_irq(&current->sighand->siglock);
	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;
	ret = seccomp_attach_filter(flags, prepared);
	if (ret)
		goto out;
	/* Do not free the successfully attached filter. */
	prepared = NULL;
	seccomp_assign_mode(current, seccomp_mode, flags);
out:
	spin_unlock_irq(&current->sighand->siglock);
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		mutex_unlock(&current->signal->cred_guard_mutex);
out_put_fd:
	if (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
		if (ret < 0) {
			listener_f->private_data = NULL;
			fput(listener_f);
			put_unused_fd(listener);
		} else {
			fd_install(listener, listener_f);
			ret = listener;
		}
	}
out_free:
	seccomp_filter_free(prepared);
	return ret;
}
```


















```c

int __secure_computing(const struct seccomp_data *sd)
{
	int mode = current->seccomp.mode;
	int this_syscall;
	if (IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) &&
	    unlikely(current->ptrace & PT_SUSPEND_SECCOMP))
		return 0;
	this_syscall = sd ? sd->nr :
		syscall_get_nr(current, task_pt_regs(current));
	switch (mode) {
	case SECCOMP_MODE_STRICT:
		__secure_computing_strict(this_syscall);  /* may call do_exit */
		return 0;
	case SECCOMP_MODE_FILTER:
		return __seccomp_filter(this_syscall, sd, false);
	default:
		BUG();
	}
}
```

```c
static int __seccomp_filter(int this_syscall, const struct seccomp_data *sd,
			    const bool recheck_after_trace)
{
	u32 filter_ret, action;
	struct seccomp_filter *match = NULL;
	int data;
	struct seccomp_data sd_local;
	/*
	 * Make sure that any changes to mode from another thread have
	 * been seen after TIF_SECCOMP was seen.
	 */
	rmb();
	if (!sd) {
		populate_seccomp_data(&sd_local);
		sd = &sd_local;
	}
	filter_ret = seccomp_run_filters(sd, &match);
	data = filter_ret & SECCOMP_RET_DATA;
	action = filter_ret & SECCOMP_RET_ACTION_FULL;
	switch (action) {
	case SECCOMP_RET_ERRNO:
		/* Set low-order bits as an errno, capped at MAX_ERRNO. */
		if (data > MAX_ERRNO)
			data = MAX_ERRNO;
		syscall_set_return_value(current, task_pt_regs(current),
					 -data, 0);
		goto skip;
	case SECCOMP_RET_TRAP:
		/* Show the handler the original registers. */
		syscall_rollback(current, task_pt_regs(current));
		/* Let the filter pass back 16 bits of data. */
		seccomp_send_sigsys(this_syscall, data);
		goto skip;
	case SECCOMP_RET_TRACE:
		/* We've been put in this state by the ptracer already. */
		if (recheck_after_trace)
			return 0;
		/* ENOSYS these calls if there is no tracer attached. */
		if (!ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)) {
			syscall_set_return_value(current,
						 task_pt_regs(current),
						 -ENOSYS, 0);
			goto skip;
		}
		/* Allow the BPF to provide the event message */
		ptrace_event(PTRACE_EVENT_SECCOMP, data);
		/*
		 * The delivery of a fatal signal during event
		 * notification may silently skip tracer notification,
		 * which could leave us with a potentially unmodified
		 * syscall that the tracer would have liked to have
		 * changed. Since the process is about to die, we just
		 * force the syscall to be skipped and let the signal
		 * kill the process and correctly handle any tracer exit
		 * notifications.
		 */
		if (fatal_signal_pending(current))
			goto skip;
		/* Check if the tracer forced the syscall to be skipped. */
		this_syscall = syscall_get_nr(current, task_pt_regs(current));
		if (this_syscall < 0)
			goto skip;
		/*
		 * Recheck the syscall, since it may have changed. This
		 * intentionally uses a NULL struct seccomp_data to force
		 * a reload of all registers. This does not goto skip since
		 * a skip would have already been reported.
		 */
		if (__seccomp_filter(this_syscall, NULL, true))
			return -1;
		return 0;
	case SECCOMP_RET_USER_NOTIF:
		seccomp_do_user_notification(this_syscall, match, sd);
		goto skip;
	case SECCOMP_RET_LOG:
		seccomp_log(this_syscall, 0, action, true);
		return 0;
	case SECCOMP_RET_ALLOW:
		/*
		 * Note that the "match" filter will always be NULL for
		 * this action since SECCOMP_RET_ALLOW is the starting
		 * state in seccomp_run_filters().
		 */
		return 0;
	case SECCOMP_RET_KILL_THREAD:
	case SECCOMP_RET_KILL_PROCESS:
	default:
		seccomp_log(this_syscall, SIGSYS, action, true);
		/* Dump core only if this is the last remaining thread. */
		if (action == SECCOMP_RET_KILL_PROCESS ||
		    get_nr_threads(current) == 1) {
			kernel_siginfo_t info;
			/* Show the original registers in the dump. */
			syscall_rollback(current, task_pt_regs(current));
			/* Trigger a manual coredump since do_exit skips it. */
			seccomp_init_siginfo(&info, this_syscall, data);
			do_coredump(&info);
		}
		if (action == SECCOMP_RET_KILL_PROCESS)
			do_group_exit(SIGSYS);
		else
			do_exit(SIGSYS);
	}
	unreachable();
skip:
	seccomp_log(this_syscall, 0, action, match ? match->log : false);
	return -1;
}
```


## slv.py


## 느낀 점



## Reference
- [https://code.woboq.org/linux/linux/kernel/seccomp.c.html](https://code.woboq.org/linux/linux/kernel/seccomp.c.html)
- [https://code.woboq.org/linux/linux/kernel/sys.c.html#2266](https://code.woboq.org/linux/linux/kernel/sys.c.html#2266)
- [https://code.woboq.org/linux/linux/kernel/seccomp.c.html#prctl_set_seccomp](https://code.woboq.org/linux/linux/kernel/seccomp.c.html#prctl_set_seccomp)
- [https://code.woboq.org/linux/linux/kernel/seccomp.c.html#seccomp_set_mode_strict](https://code.woboq.org/linux/linux/kernel/seccomp.c.html#seccomp_set_mode_strict)
- [https://dreamhack.io/learn/11#31](https://dreamhack.io/learn/11#31)