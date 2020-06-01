---
title: SAMSUNG CTF 2018 - noleak
categories:
 - pwnable
tags: 
---

푸는중...

```
main(0x400c55)

    setvbuf(stdout, 0, 2, 0)
    setvbuf(stdout, 0, 2, 0)
    
    
    [rbp-0x28] = fopen("/dev/urandom", 'r')
    
    if [rbp-0x28] == 0:
        puts("cannot open /dev/urandom")
        exit(0)
        
    
    fread(0x6020cc(seed), 4, 1)
    fclose([rbp-0x28])
    
    puts("making less predictable heap")
    malloc(0x6020cc(seed) & 0x1ffff)
    
    puts("\n- select menu -")
    puts("1. : leak memory contents")
    puts("2. : leak stack canary")
    puts("3. : start bof")
    puts("4. : exit> ")
    
    scanf("%d", rbp-0x2c)
    getchar()
    
    if [rbp-0x2c] == 1:
        
        call menu1()
            
            
            puts("give me bytes")
            [rbp-0x8] = malloc(0xc8)
            
            fgets([rbp-0x8], 0x96, stdin)
            puts("info leak with uninitialized bytes?")
            fwrite([rbp-0x8], 0x4, 0x1, stdout)
            
            free([rbp-0x8])
            
            
    
    
    elif [rbp-0x2c] == 2:
    
        call menu2()
        
            BYTE PTR [rbp-0x9] = 0x0
            [rbp-0x1a8] = 0x0
            
            for([rbp-0x1a4] = 0; [rbp-0x1a4] <= 0x62; [rbp-0x1a4]++):
                [rbp-0x1a0 + 4*[rbp-0x1a4]] = 0x31337
                
            
            for([rbp-0x1a4] = 0; [rbp-0x1a4] <= 0x63; [rbp-0x1a4]++):
                [rbp-0x1a8] += [rbp-0x1a0 + 4*[rbp-0x1a4]]
            
            printf("info leak with oob read? %x\n", [rbp-0x1a8])
            
            
            
            
            
    
    
    elif [rbp-0x2c] == 3:
    
        call menu3()
            
            [rbp-0x80] = rbp-0x24
            
            memset(rbp-0x70, 0, 0x64)
            
            puts("you may start stack BOF but...")
            puts("no memory leak from now!")
            
            close(1)
            close(2)
            [rbp-0x78] = malloc(0x64)
            
            fgets([rbp-0x78], 0x74, stdin)
            
            
            while [[rbp-0x80]] <= 0xc7:
                
                rdx = [[rbp-0x80]]
                rdx += [rbp-0x78]
                
                BYTE PTR [rbp-0x70+[[rbp-0x80]]] = BYTE PTR [[[rbp-0x80]] + [rbp-0x78]]
                
                [[rbp-0x80]]++
                
                
            
    
    elif [rbp-0x2c] > 3:
    
        if [rbp-0x2c] == 0xfeedbeef:
            system("echo flag")
    
    
    elif [rbp-0x2c] < 1:
    
        exit(0)
```