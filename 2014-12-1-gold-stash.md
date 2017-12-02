---
layout: post
title: "Gunslinger Joe’s Gold Stash, hack.lu CTF 2014"
date: 2014-12-01
categories: [ctf-writeups, reversing]
description: writeup of a 200 point reversing challenge from hack.lu CTF
toc: true
---

This one was a 200 point reversing challenge:

```
Silly Gunslinger Joe has learned from his mistakes with his private terminal 
and now tries to remember passwords. But he's gotten more paranoid and chose 
to develope an additional method: protect all his private stuff with a secure 
locking mechanism that no one would be able to figure out! He's so confident 
with this new method that he even started using it to protect all his precious 
gold. So â€¦ we better steal all of it! 
```

Downloading the binary and looking at it revealed a single function `main()` with the following structure:

![alt text][main_structure]

[main_structure]: http://i.imgur.com/iqXbNo5.png

Fairly simple structure. Looking closer at the meat of the function...

![alt text][main]

[main]: http://i.imgur.com/iF7xcAC.png

Ok. This seems to match the problem description. Enter the right username/pass, and get a shell. The binary on the server was suid ‘gold’, and the FLAG file was owned by gold. This all makes sense. So the username is `Joe` and the pass is `omg_joe_is_so_rich`? And this is a 200 point challenge??? It immediately seemed to easy. Just be sure, I tried the binary on my local box, and it worked. Then I tried it on the server...

```
joes_gold@goldstash:~$ ./gold_stash 
          (_/-------------_______________________)
          `|  /~~~~~~~~~~\                       |
           ;  |--------(-||______________________|
           ;  |--------(-| ____________|
           ;  \__________/'
         _/__         ___;
      ,~~    |  __--~~       Gunslinger Joe's
     '        ~~| (  |       Private Stash of Gold
    '      '~~  `____'
   '      '
  '      `            Password Protection activated!
 '       `
'--------`
Username: Joe
Password: omg_joe_is_so_rich
Authentication failed!
```

I tried again and again. Still failed. I tried typing it out in a text editor and cutting and pasting. I went back and looked at the private terminal challenge, and saw there was some environment manipulation going on. So I tried a different environment, different shell, even a different libc I uploaded, figuring that maybe `strcmp()` had been monkey’d with. I then hypothesized that the `execve()` call was failing for some reason; the password was right, but since `execve()` failed I fell through to code that prints out `Authentication failed!`, which sits below the `execve()` call in the binary. But this can’t be. If that was the case, I would have first seen the success message then the failure message. From here I went nuts. I contacted the challenge creator, who assured me everything was right in the world. If that’s the case, then *something* on this server was screwing with me. It’s almost as if there’s something deep inside *this server* that is looking for me to type that specific password so it can mangle it somehow.

I then typed `lsmod` and saw a module named `joe`.

`joe.ko` was easy to find.  And in IDA...

![alt text][joe_ko]

[joe_ko]: http://i.imgur.com/YNn3Uz1.png

t was an aggravating 30 minutes or so until I thought about the possibility of an evil kernel module targeting my password string. The tl;dr is that `joe.ko` looks for binaries running as `1001` (which this one was), and checks strings coming from userspace to see if it finds `omg_joe_is_so_rich`.  If it does, it runs the string through a simple xor transformation before returning it to userspace. It also works in reverse, taking in any strings from binaries running as `1001` and if it finds a string that *decrypts* to `omg_joe_is_so_rich`, returns that instead. Here’s a small script in python that prints out the user/pass:

```python
#!/usr/bin/python

import sys
p='omg_joe_is_so_rich'
key = '123456789012445678'

print 'Joe'
for i in range(len(p)):
    sys.stdout.write(chr((ord(p[i])^ord(key[i]))+4))
sys.stdout.write('\n')
```

And here it is:

```bash
joes_gold@goldstash:~$ ./gold_stash 
          (_/-------------_______________________)
          `|  /~~~~~~~~~~\                       |
           ;  |--------(-||______________________|
           ;  |--------(-| ____________|
           ;  \__________/'
         _/__         ___;
      ,~~    |  __--~~       Gunslinger Joe's
     '        ~~| (  |       Private Stash of Gold
    '      '~~  `____'
   '      '
  '      `            Password Protection activated!
 '       `
'--------`
Username: Joe
Password: bcXoc]VkTGrE_oKcXT
Access granted!
$ id
uid=1001(gold) gid=1000(joes_gold) egid=1001(gold) groups=1001(gold),1000(joes_gold)
$ cat FLAG
flag{joe_thought_youd_never_find_that_module}
```
