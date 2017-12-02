---
layout: post
title: "PwnAdventure 3 - Egg Hunter, GitS 2015"
date: 2015-01-31
categories: [ctf-writeups, reversing, pwnadventure]
description: A write-up for another PwnAdventure challenge from GitS 2015
toc: true
---

This writeup tails off of [my previous write-up on the Cows challenge](http://dropkickgit.github.io/2015/01/pwnadventure-cows), in which I used MS Detours to perform function hooking and hack parts of PwnAdventure 3. This one can be solved with basically the same approach as Cows.  Most of the eggs can be found via brute-force search of the island, but that sucks.  Lets instead hook network traffic and see what the unencrypted traffic looks like.  To do this, we can hook the following functions in the GameLogic library:

```c
bool __thiscall TCPSocket::Read(TCPSocket *this, void *buf, unsigned int len)
bool __thiscall TCPSocket::Write(TCPSocket *this, const void *buf, unsigned int len)
```

If you hook these functions prior to connecting to the server, and then successfully login, you will get a stream of what looks like initial positions of objects in game:

```
Recv():
  0000  43 6f 77 43 68 65 73 74                          CowChest
Recv():
  0000  00 fe 76 48                                      ..vH
Recv():
  0000  00 a1 6f c8                                      ..o.
Recv():
  0000  00 40 92 44                                      .@.D

...

Recv():
  0000  4c 61 76 61 43 68 65 73 74                       LavaChest
Recv():
  0000  00 bc 46 47                                      ..FG
Recv():
  0000  00 d8 a3 c5                                      ....
Recv():

  0000  00 60 be 44                                      .`.D
```

and if you search for 'eggs', you find this:

```
Recv():
  0000  47 6f 6c 64 65 6e 45 67 67 31                    GoldenEgg1
Recv():
  0000  00 aa c3 c6                                      ....
Recv():
  0000  00 4a 8d 46                                      .J.F
Recv():
  0000  00 00 82 43                                      ...C
Recv():
  0000  00 00                                            ..
Recv():
  0000  00 00                                            ..
Recv():
  0000  00 00                                            ..
Recv():
  0000  47 6f 6c 64 65 6e 45 67 67 32                    GoldenEgg2
Recv():
  0000  00 72 49 c7                                      .rI.
Recv():
  0000  00 1f 6f c7                                      ..o.
Recv():

  0000  00 e0 9c 45                                      ...E

...

Recv():
  0000  42 61 6c 6c 6d 65 72 50 65 61 6b 45 67 67        BallmerPeakEgg
Recv():
  0000  00 a0 2d c5                                      ..-.
Recv():
  0000  00 6c 2c c6                                      .l,.
Recv():
  0000  00 20 24 46                                      . $F
```

The general form of the captured egg-related traffic seems to be GoldenEgg[1-9] <dword> <dword> <dword>.  Those dwords turn out to be floating point values, and three floating point values (a vector) specify a three dimensional location on the island.  We have our egg locations.  But what is this BallmerPeakEgg?  When you run it to ground via analysis of the GameLogic library, the BallmerPeakEgg is a special egg on the egg hunt that will only appear once a condition is met in-game.  That condition happens to be shooting the Ballmer Peak xkcd poster with the *CowboyCoder*, a special revolver that can be puchased in Town:

![cowboy coder code](http://i.imgur.com/zT8QpIX.png)

So we know the locations of the eggs, and we know how to make the Ballmer egg appear.  What's the best way to collect eggs?  A teleporting function would be nice.  Again, after a few hours of experimenting, `Actor::SetPosition()` turned out the be the easiest function to approach.  It has the following prototype:

```c
void __thiscall Actor::SetPosition(Actor *this, Vector3 *pos)
```

The goal is not to hook this function, but instead to call it with the arguments we want.  We know pos -  it will be the position vector for the given egg we're going after.  But what about the Actor pointer?  We handled this by hooking the `Player::Chat()` function again (we did this in Cows). `Player::Chat()` gets passed a pointer to the current player object.  And here's the layout of the `Player` class according to IDA:

![player class](http://i.imgur.com/Pzj5UcK.png)

As you can see, there is multiple inheritance going on here: `Player` inherits from both `Actor` and `IPlayer` (in C++, objects that inherit from other classes instantiate the parent class(es) and keep the entire object within themselves in memory).  So if we have a pointer to the `Player` object, we have the `Actor` object as well.  At this point I went on to waste an hour figuring out why my hooked calls to `Actor::SetPosition()` were failing and crashing the game.  In the end, it turned out that the first arg to `Actor::SetPosition()` was not a pointer to the `Player` object but rather to the `IPlayer` object within the `Player` object.  Once this was discovered, this was an easy fix, since the `IPlayer` object sits right after the `Actor` object in memory.  `sizeof(Actor)` is 0x70 bytes according to IDA, so the call to the hooked function changed to this:

```c
ActorSetPosition((Actor *)(((char *)p) - 0x70), v);
```

where `p` is the pointer to the `IPlayer` object and `v` is a pointer to the position vector we want to teleport to.  With the fix in place, I added a new command to my hooked version of `Player::Chat()` to teleport to egg locations by entering '/teleport egg[1-10]', with egg10 being the Ballmer Peak egg.  From there, it's simply a matter of collecting all the eggs and getting your flag.  Here's the full code for the Samurai PwnAdventure DLL:

```c
#include <Windows.h>
#include <detours.h>
#include <fstream>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "detours.lib")

// Classes
class TCPSocket {};
class Player {};
class Actor {};

// Structs
struct Vector3 {
  float x, y, z;
};

// Typedefs
typedef bool(__thiscall *SendFunc)(TCPSocket *, const void*, unsigned int);
typedef bool(__thiscall *RecvFunc)(TCPSocket *, void*, unsigned int);
typedef bool(__thiscall *CanJumpFunc)(Player *);
typedef bool(__thiscall *PlayerChatFunc)(Player *, const char *);
typedef void(__thiscall *PlayerFastTravelFunc)(Player *, const char *, const char *);
typedef void(__thiscall *ActorSetPositionFunc)(Actor *, Vector3 *);

// Globals
SendFunc RealSend;
RecvFunc RealRecv;
CanJumpFunc RealCanJump;
PlayerChatFunc RealChat;
PlayerFastTravelFunc PlayerFastTravel;
ActorSetPositionFunc ActorSetPosition;
Player *playerObj = 0;
TCPSocket *clientSock = 0;
std::ofstream DbgLogger;

// Eggs!
Vector3 goldEggs[10] = {
  { -25045.0, 18085.0, 260.0 },
  { -51570.0, -61215.0, 5020.0 },
  { 24512.0, 69682.0, 2659.0 },
  { 60453.0, -17409.0, 2939.0 },
  { 1522.0, 14966.0, 7022.0 },
  { 11604.0, -13131.0, 411.0 },
  { -72667.0, -53567.0, 1645.0 },
  { 48404.0, 28117.0, 704.0 },
  { 65225.0, -5740.0, 4928.0 },
  { -2778.0, -11035.0, 10504.0 }
};

// Known offsets
DWORD TCPSocket_Read_Offset = 0x60950;
DWORD TCPSocket_Write_Offset = 0x60A30;
DWORD Player_CanJump_Offset = 0x51680;
DWORD Player_Chat_Offset = 0x551A0;
DWORD Player_Teleport_Offset = 0x54E50;
DWORD Player_FastTravel_Offset = 0x55AE0;
DWORD Player_PerformFastTravel_Offset = 0x55C10;
DWORD Player_Obj_Offset = 0x97e48;
DWORD Actor_SetPosition_Offset = 0x1C80;

// Thanks to paxdiablo from stackoverflow for the sweet formatting code
// http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data/7776146#7776146
void LogPacket(char *desc, void *addr, int len) {
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char*)addr;
  FILE* pktLog;

  fopen_s(&pktLog, "PwnHaxPkts.txt", "a+");
  if (desc != NULL)
    fprintf(pktLog, "%s:\n", desc);
  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0)
        fprintf(pktLog, "  %s\n", buff);

      // Output the offset.
      fprintf(pktLog, "  %04x ", i);
    }

    // Now the hex code for the specific character.
    fprintf(pktLog, " %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    fprintf(pktLog, "   ");
    i++;
  }

  // And print the final ASCII bit.
  fprintf(pktLog, "  %s\n", buff);
  fclose(pktLog);
}

bool __fastcall HookedSend(TCPSocket *s, int edx, const void* buf, unsigned int len) 
{
  // Save pointer to TCPSocket for later
  if (clientSock == 0) {
    clientSock = s;
  }
  LogPacket("Send()", (void *)buf, len);
  return RealSend(s, buf, len);
}

bool __fastcall HookedRecv(TCPSocket *s, int edx, void *buf, unsigned int len) 
{
  bool retVal;

  retVal = RealRecv(s, buf, len);
  LogPacket("Recv()", buf, len);
  return retVal;
}

bool __fastcall HookedCanJump(Player *p, int edx)
{
  return TRUE;
}

void __fastcall HookedChat(Player *p, int edx, const char *text)
{
  char buf[256];

  sprintf(buf, "PwnHax.dll: Hooked Chat(): player ptr is %p\n", p);
  OutputDebugStringA(buf);
  if (strcmp(text, "foo") == 0) {
    // Just for testing
    OutputDebugStringA("PwnHax.dll: Hooked Chat(): got 'foo'\n");
  }
  else if (strcmp(text, "/cows") == 0) {
    OutputDebugStringA("PwnHax.dll: Hooked Chat(): got '/cows'\n");
    PlayerFastTravel(p, "Town", "CowLevel");
  }
  else if (strncmp(text, "/teleport", 9) == 0) {
    Vector3 *v;
    char *eggName;

    OutputDebugStringA("PwnHax.dll: Hooked Chat(): got '/teleport'\n");
    
    // Make a pointer to the egg name
    eggName = (char *)text + 10;
    
    // Set our vector to the right egg
    // (what a fucking ugly block of code)
    if (strcmp(eggName, "egg1") == 0) {
      v = &goldEggs[0];
    }
    else if (strcmp(eggName, "egg2") == 0) {
      v = &goldEggs[1];
    }
    else if (strcmp(eggName, "egg3") == 0) {
      v = &goldEggs[2];
    }
    else if (strcmp(eggName, "egg4") == 0) {
      v = &goldEggs[3];
    }
    else if (strcmp(eggName, "egg5") == 0) {
      v = &goldEggs[4];
    }
    else if (strcmp(eggName, "egg6") == 0) {
      v = &goldEggs[5];
    }
    else if (strcmp(eggName, "egg7") == 0) {
      v = &goldEggs[6];
    }
    else if (strcmp(eggName, "egg8") == 0) {
      v = &goldEggs[7];
    }
    else if (strcmp(eggName, "egg9") == 0) {
      v = &goldEggs[8];
    }
    else if (strcmp(eggName, "egg10") == 0) {
      v = &goldEggs[9];
    }
    else {
      sprintf(buf, "PwnHax.dll: Hooked Chat(): unknown teleport location %s\n", eggName);
      OutputDebugStringA(buf);
      return;
    }

    // Actor::SetPosition() takes a pointer to the Player's Actor base class.  The Player pointer
    // passed to this member function is actually to the IPlayer object for the current player.
    // From IDA we can deduce that the Actor object comes before the IPlayer object for the player in memory.
    // In other words, take the first argument, subtract 0x70 (sizeof(Actor)), and you have a pointer
    // to the Actor object you need.
    ActorSetPosition((Actor *)(((char *)p) - 0x70), v);
    return;
  }

  RealChat(p, text);
}

void __fastcall HookedPlayerFastTravel(Player *p, int edx, const char *origin, const char *dest)
{
  OutputDebugStringA("PwnHax.dll: Hooked Player::FastTravel() called.\n");
  // Yet another way to get the CowLevel.  This can be disabled since you can just
  // type '/cows' in chat, but I'll leave it as an example of another solution for hacking
  // FastTravel
  if (strcmp(dest, "GoldFarm") == 0) {
    PlayerFastTravel(p, origin, "CowLevel");
  }
  else {
    PlayerFastTravel(p, origin, dest);
  }
}

// This dummy export is necessary for proper loading of the DLL
extern "C" __declspec(dllexport) void dummy(void)
{
  return;
}

BOOL ResolveSymbols(void)
{
  HMODULE hLib = GetModuleHandleA("GameLogic.dll");
  if (hLib == NULL) {
    DbgLogger << "Couldn't locate GameLogic.dll!" << std::endl;
    return FALSE;
  }
  
  DbgLogger << "Addr of GameLogic.dll: " << hLib << std::endl;
  
  DWORD_PTR realSendAddress = (DWORD_PTR)hLib + TCPSocket_Write_Offset;
  RealSend = (SendFunc)realSendAddress;
  DbgLogger << "Addr of TCPSocket::Write(): " << (HMODULE)realSendAddress << std::endl;

  DWORD_PTR realRecvAddress = (DWORD_PTR)hLib + TCPSocket_Read_Offset;
  RealRecv = (RecvFunc)realRecvAddress;
  DbgLogger << "Addr of TCPSocket::Read(): " << (HMODULE)realRecvAddress << std::endl;

  DWORD_PTR realCanJumpAddress = (DWORD_PTR)hLib + Player_CanJump_Offset;
  RealCanJump = (CanJumpFunc)realCanJumpAddress;
  DbgLogger << "Addr of Player::CanJump(): " << (HMODULE)realCanJumpAddress << std::endl;

  DWORD_PTR realChatAddress = (DWORD_PTR)hLib + Player_Chat_Offset;
  RealChat = (PlayerChatFunc)realChatAddress;
  DbgLogger << "Addr of Player::Chat(): " << (HMODULE)realChatAddress << std::endl;

  DWORD_PTR playerFastTravelAddress = (DWORD_PTR)hLib + Player_FastTravel_Offset;
  PlayerFastTravel = (PlayerFastTravelFunc)playerFastTravelAddress;
  DbgLogger << "Addr of Player::FastTravel(): " << (HMODULE)playerFastTravelAddress << std::endl;

  DWORD_PTR actorSetPositionAddress = (DWORD_PTR)hLib + Actor_SetPosition_Offset;
  ActorSetPosition = (ActorSetPositionFunc)actorSetPositionAddress;
  DbgLogger << "Addr of Actor::SetPosition(): " << (HMODULE)actorSetPositionAddress << std::endl;

  playerObj = (Player *)hLib + Player_Obj_Offset;
  DbgLogger << "Addr of IPlayer: " << (HMODULE)playerObj << std::endl;

  return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
  LONG error;

  if (DetourIsHelperProcess()) {
    return TRUE;
  }

  DbgLogger.open("PwnHaxDbg.txt", std::ios::out);
  DbgLogger << "Logging started!!!" << std::endl;

  if (dwReason == DLL_PROCESS_ATTACH) {
    if (ResolveSymbols() == FALSE) {
      return FALSE;
    }
    //DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID &)RealSend, HookedSend);
    DetourAttach(&(PVOID &)RealRecv, HookedRecv);
    DetourAttach(&(PVOID &)RealCanJump, HookedCanJump);
    DetourAttach(&(PVOID &)RealChat, HookedChat);
    DetourAttach(&(PVOID &)PlayerFastTravel, HookedPlayerFastTravel);

    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
      DbgLogger << "Attached successfully...." << std::endl;
    }
    else {
      DbgLogger << "Failed to attach!!!" << std::endl;
    }
  }
  else if (dwReason == DLL_PROCESS_DETACH) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID &)RealSend, HookedSend);
    DetourDetach(&(PVOID &)RealRecv, HookedRecv);
    DetourDetach(&(PVOID &)RealCanJump, HookedCanJump);
    DetourDetach(&(PVOID &)RealChat, HookedChat);
    DetourDetach(&(PVOID &)PlayerFastTravel, HookedPlayerFastTravel);
    DetourTransactionCommit();
    DbgLogger.close();
  }

  return TRUE;
}
```

Last note: I have crashed the game twice by teleporting to egg locations with the method described above in a completely random, unrepeatable way.  If it happens to you, don't get discouraged, just try again.
