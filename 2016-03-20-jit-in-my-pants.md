---
layout: post
title: "jit-in-my-pants, Boston Key Party 2016 CTF"
date: 2016-03-20
categories: [ctf-writeups, reversing]
description: A challenge in which we take the back roads...
toc: true
---
#### Meta
`jit-in-my-pants` was a 3 point reverse engineering "crackme" problem from Boston Key Party 2016. The problem takes `argv[1]` (i.e., the correct flag) and validates it.  The goal is to reverse the binary and solve for `argv[1]`.  The original binary and challenge description can be found [here](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/reversing/jit-in-my-pants-3).

#### Solution
The first thing to note about the binary is the complexity: there is something in the order of 800 internal functions and tons of libc imports as well.  Whatever this VM implementation is, it's complex.  And for the relatively low point value of the problem, it's likely a giant waste of time to reverse the VM all the way.  The question then becomes how to reduce the size of the problem to something manageable.

Right away this binary started to remind me of the `rolling` challenge from the 2014 9447 CTF, [which I also made a writeup for](http://blog.pop2ret.net/ctf-writeups/reversing/2014/12/02/rolling.html).  `rolling` had a nice information leak: the flag checking function progressed further down the code path with each 'correct' character.  This made it vulnerable to leaking the next 'correct' character via instruction counting (see [the full writeup](http://blog.pop2ret.net/ctf-writeups/reversing/2014/12/02/rolling.html) for the entire explanation and script).

I stole my `rolling` script and adapted it for `jit-in-my-pants`.  tl;dr: I use Intel's PIN tool to perform instruction counting as the script 'guesses' the next correct character.  I continue doing this until guessing a correct `}`, as this signifies the end of the flag format for this CTF.

I also made the assumption that the flag started with `BKPCTF` which was true for the other challenges.  I actually seeded the solve script with `BKP` to validate that it would find what *should* be the next correct character (C).  Here's the script:

```python
#!/usr/bin/env python
from subprocess import check_output

pin_path = '/home/dropkick/src/pin-3.0-76991-gcc-linux/'
pintool = '/source/tools/ManualExamples/obj-intel64/inscount0.so'
validchars = [chr(c) for c in range(0x30, 0x7f)]
bin_name = './jit-in-my-pants'

def get_inscount():
    fd = open('inscount.out')
    inscount = fd.read().split()[1]
    fd.close()
    return int(inscount)

def run_binary(flag):
    return check_output([pin_path+'pin', '-t', pin_path+pintool, '--', bin_name, flag])

# We know flags start with BKPCTF{
flag = 'BKPCTF{'

# Establish baseline instruction count
run_binary(flag)
base_inscount = get_inscount()

# Main loop
while True:
    for c in validchars:
        print 'Trying flag {0}...'.format(flag+c)
        output = run_binary(flag + c)
        if 'Nope' not in output:
            print 'Victory! The flag is: {0}'.format(flag+c)
            quit()
        inscount = get_inscount()
        print '\tIns count: {0}'.format(inscount)
        if inscount > base_inscount:
            base_inscount = inscount
            # We found the next character
            flag = flag + c
            print 'Found next char, flag is now: {0}'.format(flag)
            if c == '}':
                print 'Done.'
                quit()
            break
```


Upon running the script, I got nonsense.  Not only did I get nonsense, but I got what seemed to be very random instruction counts across characters for each run of the script.  If it were the case that the entire flag is evaluated *at once* vice *char-by-char*, I'd at least see semi-consistent instruction counts and simply fail to notice a big jump when a correct character is found.  This led me to believe that was screwing with dynamic analysis on purpose.  Oh, did I also mention that the binary contains the string `././jitter-amd64.c`?

Running the binary under `strace` didn't turn up much of anything, but `ltrace` did:

```bash
~/code/ctfs/bkp2016/reversing/jit-in-my-pants $ ltrace -c ./jit-in-my-pants asdfasdfasdf
Nope.
% time     seconds  usecs/call     calls      function
------ ----------- ----------- --------- --------------------
 67.04    2.065733          82     25093 malloc
 26.31    0.810703          82      9835 gettimeofday
  6.62    0.203912          80      2533 free
  0.02    0.000613         613         1 puts
  0.00    0.000113         113         1 mprotect
  0.00    0.000099          99         1 sysconf
  0.00    0.000098          98         1 posix_memalign
  0.00    0.000095          95         1 memcpy
------ ----------- ----------- --------- --------------------
100.00    3.081366                 37466 total
```

The program makes a **ton** of calls to `gettimeofday()`.  Why?  If you break on `gettimeofday()` and trace back to the JIT'd assembly in memory, you see that the `tv.tv_usec` field of the timeval struct returned by the function is used.  How it was used exactly was still a mystery to me (the code is complex), but I figured I should assume its being used in some way to produce the random instruction count jitter.  After taking wayyyy too long to figure out how I can deal with `gettimeofday()`, I wrote a shared library and loaded it with LD_PRELOAD:

```c
struct timeval {
    long tv_sec;     /* seconds */
    long tv_usec;    /* microseconds */
};

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}
```

I set LD_PRELOAD, ran my solve script*, and then...

```bash
Victory! The flag is: BKPCTF{S1de_Ch4nnel_att4cks_are_s0_1338}
```

*Note: It took me a few runs to get the correct flag.  My solve script + preload sometimes produces false characters in the flag for reasons I still don't understand (might be bugs in pin or the pintool).  Luckily the flag was semi-intelligible so it was easy to see when it was off.
