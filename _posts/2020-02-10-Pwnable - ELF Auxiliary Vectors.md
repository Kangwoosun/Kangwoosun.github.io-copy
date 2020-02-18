---
title: Pwnable - ELF Auxiliary Vectors
categories:
 - pwnable
tags: pwn, auxv, kernel
---

이전 포스팅 `https://kangwoosun.github.io/pwnable/2020/02/08/Pwnable-linux-canary/`에서 

canary를 생성할때 사용되었던 `_dl_random`의 값을 정해줄때 사용되었던

`av->a_un.a_val`, `av->a_type`, `av`에 대해 분석해보는 시간을 가지려고 한다.

(본 포스팅의 내용은 `https://nekoplu5.tistory.com/206`에서 많이 참조함.)

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

정리하면

1. `get_get_random_bytes`로 무작위 16byte `k_rand_bytes` 생성
2. `STACK_ALLOC`으로 `u_rand_bytes` 공간 할당 후 `k_rand_bytes`의 값을 복사
3. `NEW_AUX_ENT`를 사용해 `AT_RANDOM` type에 `u_rand_bytes`의 value 입력

이렇게 `AT_RANDOM` type의 value가 정해진다.

`AT_RANDOM`의 값이 어떻게 설정되는지 살펴보았으니 이번에는 auxv값이 binary에 어떤 형태로 들어가는지

테스트 코드를 통해 확인해보도록 하겠다.

(여기서부터는 `http://articles.manugarg.com/aboutelfauxiliaryvectors.html`, `https://umbum.tistory.com/439`을 참조했다.)

```c
/* 32bit */
/* gcc ./test.c -o ./test -m32 */

#include <stdio.h>
#include <elf.h>

main(int argc, char* argv[], char* envp[])
{
        Elf32_auxv_t *auxv;
        while(*envp++ != NULL); /*from stack diagram above: *envp = NULL marks end of envp*/

        for (auxv = (Elf32_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
      /* auxv->a_type = AT_NULL marks the end of auxv */
        {
                if( auxv->a_type == AT_SYSINFO)
                        printf("AT_SYSINFO is: 0x%x\n", auxv->a_un.a_val);
        }
}



/* 64bit */
/* gcc ./test.c -o ./test */
#include <stdio.h>
#include <elf.h>

void main(int argc, char* argv[], char* envp[])
{
        Elf64_auxv_t *auxv;
	
        while(*envp++ != NULL); /*from stack diagram above: *envp = NULL marks end of envp*/
    
	for (auxv = (Elf64_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
      /* auxv->a_type = AT_NULL marks the end of auxv */
        {
                if( auxv->a_type == AT_RANDOM)
                        printf("AT_RANDOM is: 0x%p\n", auxv->a_un.a_val);
				
        }
}

```
```
+-----------------------+
|          argv         |
+-----------------------+
|         argv[0]       |
+-----------------------+
|           .           |
+-----------------------+
|           .           |
+-----------------------+
|         argv[n]       |
+-----------------------+
|         envp[0]       |
+-----------------------+
|           .           |
+-----------------------+
|           .           |
+-----------------------+
|         envp[m]       |
+-----------------------+
|          auxv         |
+-----------------------+
|    type   |   value   |
+-----------------------+
|    type   |   value   |
+-----------------------+
|           .           |
+-----------------------+
|           .           |
+-----------------------+
|           .           |
+-----------------------+
```

이렇게 만들어진 auxv들은 `argc``argv[0]`...`argv[n](NULL)``envp[0]`...`envp[m](NULL)``auxv[]`...

형태로 메모리상 `envp`의 뒷부분에 존재한다. `NEW_AUX_ENT`에서 16byte로 8byte는 id, 8byte val를 넣기 때문에

구조상 {type:value}의 형식으로 존재하게 된다.


# Reference

```
https://umbum.tistory.com/439
https://nekoplu5.tistory.com/206
```


포스팅중..(20.02.18)