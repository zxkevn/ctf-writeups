# KeyGenMe v7

tl;dr - This is a reverse engineering challenge with the ulitmate goal being to create a key generator.  The key checking algorithm is based on the username.  The algorithm itself is hidden within two different obfuscated code blocks within the .text section.  These blocks can be successfully decrypted by entering any 32-byte string in the form 'XXXXXXX-XXXXXX-XXXXXX-XXXXXX-XXX' into the dialog box and browsing the code under debugger control.  A key generator based on the recovered algorithm is provided below.

The original challenge and description can be retreived from http://www.reddit.com/r/REmath/comments/2ft0mr/keygenme

## Part 1 - Remove the nag screen

Even though I didn't mention it, removing the startup nag screen is the first goal of the challenge:

![nag screen](http://i.imgur.com/6vVRGVf.png)

A few minutes of browsing the disassembly did not turn up much, so I ran the file under debugger control to trace the execution flow.  I came across an interesting function `sub_401469` that seems to open its own process ID, inject code, and spin up a new thread.  I followed execution and indeed it turned out to be code that creates and displays the nag screen.  Since `sub_401469` doesn't seem to have any purpose other than launching the nag screen in a sneaky fashion, I patched the first bytes of the fuction with `0xc3 (ret)`.  I ran the file again, and no nag screen!


## Part 2 - Deobfuscating the key checker

Once the nag screen is successfully removed, the only thing left is a simple window to enter a username and serial:

![main window](http://i.imgur.com/B23Q6Xy.png)

Using IDA Pro, I searched the binary for the string "Username..." and found that `dword_403024` is a pointer to the UI component for the username input box.  Similarly, `dword_40302C` is the UI component for the serial number edit box.  Searching the references to `dword_403024`, I found a piece of code that start with something like this:
```
result = GetWindowTextLengthW(dword_403024);
  if ( result >= 3 )
  {
    result = GetWindowTextLengthW(dword_403024);
    if ( result <= 16 )
    {
      result = GetWindowTextLengthW(dword_40302C);
      if ( result == 32 )
      {
      ....
```
This code checks the length of the text in the username and serial edit boxes.  If `3 <= len(username) <= 16` and `len(serial) == 32`, the remainder of the code within the `result == 32` if statement is executed.  This is the beginning of the key checking algorithm.  The algorithm computes a value based on the size and contents of the username field.  It then enters a series of nested loops that unfortunately aren't very helpful.  In fact, static analysis turns out to be useless beyond this point due to an endless loop followed by jibberish:
```
.text:00401BB7                 jmp     short loc_401BB7
.text:00401BB9 ; ---------------------------------------------------------------------------
.text:00401BB9                 push    eax
.text:00401BBA                 jmp     short loc_401BB7
.text:00401BBA ; ---------------------------------------------------------------------------
.text:00401BBC                 dd 0FF8C4589h, 16AD475h, 402C15FFh, 0FF500040h, 40403C15h
.text:00401BBC                 dd 0EC4D8B00h, 8BF04D03h, 0F799E845h, 53905F9h, 45890000h
.text:00401BBC                 dd 0E8458BF8h, 0F87DF799h, 8BF84589h, 3340F045h, 4589F845h
.text:00401BBC                 dd 6A046AF8h, 98458D00h, 15FF50h, 83004030h, 26A0CC4h
.text:00401BBC                 dd 0C06B58h, 66F04D8Bh, 0FC4D8C8Bh, 66FFFFFEh, 98054C89h
.text:00401BBC                 dd 5098458Dh, 407415FFh, 26A0040h, 0C06B58h, 66F04D8Bh
.text:00401BBC                 dd 9805448Bh, 4D848966h, 0FFFFFEFCh, 0FC03350h, 3352C09Bh
.text:00401BBC                 dd 2E2C1D0h, 0C10B5A92h, 0F84D6B58h, 458B410Fh, 0C22B99ECh
.text:00401BBC                 dd 0FED1F08Bh, 99C18B46h, 4589FEF7h, 0D07D83F8h, 8B1074FFh
.text:00401BBC                 dd 453BD045h, 8B0875F8h, 0E0D1F845h, 83F84589h, 7C22F87Dh
.text:00401BBC                 dd 0F8458B0Ah, 45894848h, 83F0EBF8h, 7D00F87Dh, 0F8458B0Ah
.text:00401BBC                 dd 45894040h, 8BF0EBF8h, 4589F845h, 2B310FD0h, 3D8C45h
.text:00401BBC                 dd 76000700h, 0F84DFF03h, 0FF0458Bh, 0FC4584B7h, 8BFFFFFEh
....
```
There is an similar block of code (a loop followed by obfuscated code) at `0x00401E1D` and another infinite loop at `0x004020F8`.  The two blocks consisting of loops + obfuscated code have a similar block of code preceding the loop.  At a high level, it looks something like this:
```
v17 = loc_401E1A;
v32 = loc_401E1A;
v3 = GetProcessHeap();
v40 = HeapAlloc(v3, 8u, 7u);
VirtualProtect(v40, 7u, 0x40u, &v13);
VirtualProtect(v32, 5u, 0x40u, &v13);
xor_routine(&v27, 366612, 2);
for ( l = 0; l < 2; ++l )
  memset(v40 + l, *(&v27 + l), 1);
xor_routine(&v27, 366612, 2);
memset(v32, 233, 1);
v23 = (v40 + -v32 - 5);
memcpy(v32 + 1, &v23, 4);
memset(v40 + 2, 233, 1);
v23 = v32 + 5 - (v40 + 7);
memcpy(v40 + 3, &v23, 4);
```
This is the code that deobfuscates the code block following the self-referential jmp at `loc_401E1A`.  It also removes the infinite loop.  Both `0x00401E1D` and `0x004020F8` have similar bodies of code preceding them.  Simply running the program under debugger control deobfuscates these protected code areas.  The real work comes from reversing the key checking assembly code into a working key generator.  This is fairly straightforward, just time consuming.  Some of the deobfuscated code turns out to be rather useless, such as this example:
```
.text:00401EF5 push    eax                             ; big nop?
.text:00401EF6 xor     eax, eax
.text:00401EF8 setnp   al
.text:00401EFB push    edx
.text:00401EFC xor     edx, eax
.text:00401EFE shl     edx, 2
.text:00401F01 xchg    eax, edx
.text:00401F02 pop     edx
.text:00401F03 or      eax, ecx
.text:00401F05 pop     eax
```
This is essentially a big NOP, and it appears throughout the code on multiple occasions.  I'm not sure why this code sequence appears so often; maybe it's intended to increase the workload of reversing.  In any case, it can be ignored.  The full source for the key generator is below.  Enjoy.

