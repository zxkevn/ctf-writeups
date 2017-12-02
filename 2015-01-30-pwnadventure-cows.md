---
layout: post
title: "PwnAdventure 3 - Until the Cows Come Home, GitS 2015"
date: 2015-01-30
categories: [ctf-writeups, reversing, pwnadventure]
description: A write-up where we hack one of the levels of a MMORPG
toc: true
---

[GitS 2015](http://ghostintheshellcode.com/2015-final/) featured a number of challenges exclusive to the completely hackable MMORPG [PwnAdventure 3](http://www.pwnadventure.com/).  Working these challenges was a ton of fun, which is why I was disappointed by the lack of write-ups for both Until the Cows Come Home and Egg Hunter (There is [one write-up](http://lockboxx.blogspot.com/2015/01/ghost-in-shellcode-2015-ctf-writeup-pwn.html) for Cows in which they find the island by brute force search, but we can do better).

### Until the Cows Come Home (Windows version)

Find the farmer on the Gold Farm, and he gives you the following nugget of info:

```
'My cows are missing! One night I heard a massive amount of thunder, then my cows had disappeared. I have no idea where they went.'
```

This unlocks the challenge.  Talking to him again will gives us an additional hint:

```
'Any luck finding the cows? It's like they were teleported to some other place!'
```

Since the only mode of travel in PwnAdventure is running and the FastTravel, we looked at FastTravel.  Cracking open GameLogic.dll in IDA and looking at all functions that contain the string *FastTravel* yields over 20 member functions and multiple related classes.  A big obstacle in all this year's challenges related to PwnAdventure was figuring out whether code was client or server side; the presumption was that the game logic library was the same on the client and server, which proved true.  Sometimes it was obvious (i.e., the function lives in the `ServerWorld` class), but most times an experiment or two was in order.  For the sake of brevity we'll just go right to method we need (discovered by plenty of experimentation), `Player::FastTravel()`, which has the following prototype:

```c
void __thiscall Player::FastTravel(Player *this, const char *origin, const char *dest)
```

Right, so ideally we just call this method (somehow) with the correct arguments (whatever they might be) and teleport to a secret place in the game where we find some cows.  A quick tour of the GameLogic.dll module will reveal a number of strings related to cows, to include *Cowabunga* and *CowLevel*, with *CowLevel* being used in code that appears to be related to dealing with other named regions such as *GoldFarm* and *Town*.  With *CowLevel* being the likely value needed for the dest argument to `Player::FastTravel()`, and a very limited number of possibilities for the origin argument (it turned out not to matter at all), the remaining issues are how to call the method and how to get a pointer to our own player object.  These issues are related: if we found a pointer to our player object in memory, and we reconstructed the vtable of the `Player` class (correctly), we could use the player object to call the member function.  

I took another route for my final solution and [hooked](http://en.wikipedia.org/wiki/Hooking) [methods](http://stackoverflow.com/questions/873658/how-can-i-hook-windows-functions-in-c-c?rq=1) [directly](http://snipd.net/hooking-with-the-microsoft-detours-library-in-c) with [MS Detours](http://research.microsoft.com/en-us/projects/detours/).  The majority of member functions are *not*  exported by the DLL, but Detours is fine with taking addresses calculated at runtime (i.e. `GetModuleHandle()` + known_offset_to_func).  The added bonus to hooking member functions directly is we no longer have to find the `Player` object in memory; it's passed directly to us as the first argument.  

But this all comes with a price.  Note that `Player::FastCall()` is a member function and therefore uses the [thiscall](http://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions) calling convention.  We cannot arbitrarily declare our functions as using `thiscall` (the compiler will not let this happen).  One way around this issue is to use `fastcall`, which is *pretty close* to `thiscall`.  with the exception of expecting the second argument to be in the edx register.  But remember: callers will invoke you using `thiscall` so you can safely ignore the contents of edx and everything works fine.  This *will* require you to specify a throwaway second argument to any hook functions, as such:

```c
void __fastcall HookedPlayerFastTravel(Player *p, int edx, const char *origin, const char *dest)
```

Simply ignore the 'edx' argument.  And that's basically it\*.  My first successful attempt at traveling to Cow Island was by hooking `Player::FastTravel()` and changing the *dest* argument from *GoldFarm* to *CowLevel*, which worked just fine. It will break FastTravel though, so I later decided to instead hook `Player::Chat()` and pass custom commands (i.e. '/cows') that would trigger a call directly to `Player::FastTravel()` with the args I wanted.  See [this gist](https://gist.github.com/dropkickgit/2b65c0ac18506e5c5f0f) for the full code listing.  Should build with MS Visual C++.  And final note, you must be in (or at least near) a FastTravel booth when calling the Hooked FastTravel function or it will not work.

\* If it seems like I handwaved away details on hooking with Detours, I did.  The interwebs (and the DLL code itself) are full of good examples with explanations on using Detours and proper hooking.

