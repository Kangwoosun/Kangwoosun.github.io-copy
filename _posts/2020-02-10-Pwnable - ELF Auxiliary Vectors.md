---
title: Pwnable - ELF Auxiliary Vectors
categories:
 - pwnable
tags: pwn, auxv, kernel
---

이전 포스팅 `https://kangwoosun.github.io/pwnable/2020/02/08/Pwnable-linux-canary/`에서 

canary를 생성할때 사용되었던 `_dl_random`의 값을 정해줄때 사용되었던

`av->a_un.a_val`, `av->a_type`, `av`에 대해 분석해보는 시간을 가지려고 한다.

해당 코드에서 사용된 `AT_RANDOM`이라는 type에 어떤 값이 들어가는지에 대해 알아보자.

```c
static int
create_elf_tables(struct linux_binprm *bprm, const struct elfhdr *exec,
		unsigned long load_addr, unsigned long interp_load_addr,
		unsigned long e_entry)
{
	struct mm_struct *mm = current->mm;
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	elf_addr_t __user *u_base_platform;
	elf_addr_t __user *u_rand_bytes;
	const char *k_platform = ELF_PLATFORM;
	const char *k_base_platform = ELF_BASE_PLATFORM;
	unsigned char k_rand_bytes[16];
	int items;
	elf_addr_t *elf_info;
	int ei_index;
	const struct cred *cred = current_cred();
	struct vm_area_struct *vma;
	
	.
	.
	.

	/*
	 * Generate 16 random bytes for userspace PRNG seeding.
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (elf_addr_t __user *)
		       STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (__copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	/* Create the ELF interpreter info */
	elf_info = (elf_addr_t *)mm->saved_auxv;
	/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		*elf_info++ = id; \
		*elf_info++ = val; \
	} while (0)

#ifdef ARCH_DLINFO
	/* 
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 * update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT() in
	 * ARCH_DLINFO changes
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, e_entry);
	NEW_AUX_ENT(AT_UID, from_kuid_munged(cred->user_ns, cred->uid));
	NEW_AUX_ENT(AT_EUID, from_kuid_munged(cred->user_ns, cred->euid));
	NEW_AUX_ENT(AT_GID, from_kgid_munged(cred->user_ns, cred->gid));
	NEW_AUX_ENT(AT_EGID, from_kgid_munged(cred->user_ns, cred->egid));
	NEW_AUX_ENT(AT_SECURE, bprm->secureexec);
	
	NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
	.
	.
	.
}
```

`linux/fs/binfmt_elf.c`의 `create_elf_tables`함수에서 

`NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes)`를 호출하여

aux의 각 타입마다 값을 넣어주고 있다.

매크로 `NEW_AUX_ENT`는 elf_info 주소를 늘리면서 type과 value를 인자로 받아 설정해준다.

`AT_RANDOM`의 값으로 들어가는 `u_rand_bytes`는 `get_random_bytes`로 값을 받은 `k_rand_bytes`를 

대입하게 되고 `u_rand_bytes`는 `unsigned long`의 size만큼만 전달하게된다. (32bit는 4바이트, 64bit는 8바이트)

포스팅중..(20.02.14)