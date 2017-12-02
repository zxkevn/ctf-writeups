# postit_hardened

tl;dr - This challenge is a hardened version of the pwnies 'postit' challenge (in particular, the stack is set no-execute).  A stack-based buffer overflow is used to get past part 1, and a ROP payload can be used to exec a shell in the second part by leveraging a not-so-straightforward format string vulnerability.

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

