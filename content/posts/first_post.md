+++
date = '2025-11-02T14:41:54+02:00'
draft = false
title = 'A slightly different Reflective DLL'
subtitle = 'Making reflective DLLs CRT compatible and "shellcodable"'
+++
<!--more-->

## The plot

As a developer, I am acustomed to having libraries that facilitate certain code actions such as math, randomness, http requests, etc.
When it comes to C++, the standard library contains a whole arsenal of useful tools one can use to use the language to its full potential.

An easy example are strings. Something we may take for granted by using **std::string**, but without the **\<string\>** import, we would have to implement them in the traditional C style. (I know, it's not that bad, just giving an example).
<br>
<br>
<img src="/images/libraries.png" alt="library usage" style="max-width: 400px; border-radius: 8px;">
<br>

In malware development, it's a fairly common pratice to use **reflective DLLs** as an implant or loader. While newer stuff like **PIC** is available, the truth is that Reflective DLLs are still being used as the 'goto' format of malware commonly used.

The concept is simple to understand, it is a DLL that is capable of loading itself in memory. Now, there are multiple ways of doing this as the techniques evolved over the years, we're going to explore some to understand the problem I tried to fix.

So what is the problem exactly? Well, like I mentioned before, I like using the C++ standard library and on Windows this is achieved by having a dependency called the **CRT**. The CRT is the C runtime, that contains all the necessary C and C++ functionality like **strings, vectors, functions like memcpy, strlen, memset, etc**.

But when making reflective DLL, our code is supposed to be position independent (during the reflective loading, anyway), meaning it cannot have any dependencies. There are countless examples of Reflective DLLs online, but somehow I couldn't find one that included the CRT. Or I should say, that explained **why** and **how** could we include the CRT.


## Learning from failure

The typical Reflective DLL exports a function (usually called Reflective Function) that needs to be called so that the DLL can load itself into memory. This call is usually done by a specialized loader, increasing the overhead and complexity of the whole process.

The flow is illustrated below:
- Loader reads ReflectiveDLL into memory
- Does some parsing until it finds the Exported function offset(Reflective Function)
- Inject the DLL on a process and create a thread starting at the Reflective Function
- From here the RDLL will load and execute itself.


<br>
<br>
<img src="/images/rdll2.jpg" alt="library usage">
<br>


Once more, this is not ideal as it requires both a specialized loader and a DLL that exports a specific function, both are more likely to get flagged as mallicious behavior by security solutions.

And using common examples of RDLL templates (I will be using the **MaldevAcademy** one, awesome content btw, **highly** recommend it to anyone), once we try to use some C/C++ functionality like **printf**, we are likely to see errors such as these:

<br>
<img src="/images/errors.png" alt="library usage">
<br>

This error shows precisely that the linker is configured to not include the CRT, hence the unresolved dependencies of printf (which comes from stdio.h)


## A way forward

The errors are relatively easy to fix, on this particular configuration the culprit was the **Entry Point** and the **\/NODEFAULTLIB**, both under the **Linker** configurations on Visual Studio. Change the first to empty (It was DllMain) and the second to also empty (was Yes), and magicly you can include all the standard library magic within the Reflective DLL!

But I was not satisfied enough with this approach. So I decided to do some more tweaks to the original code, which lead me down a rabbit hole of debugging, and that's where I learned the most actually. **This blogpost is meant to illustrate only that there are several ways of achieving the same outcome and that the end goal matters less than the journey sometimes.**

## Why tho?

Removing the CRT from malware has always divided me. I understand the reasons behind the practice originally, where reducing the size of the binary, removing unnecessary compiler optimizations helped get less detections.
However, in the modern landscape I no longer believe this to be the case.

A practice I follow and has yield good results, is that malware should try to mimick as much as possible "real" software to blend in. EDR evasion is not about zero alerts, it is about blending with the normal noise.

Having said this, the majority of programs I have analyzed, do not strip the CRT from their binaries, and when it comes to size, modern binaries have sizes upwards of 20-100mb. So when trying to blend in, why should we remove a component that is used by legitimate software **AND** aids us on the development process?

With this conclusion, I have explained my design choices for not only including the CRT on my RDLL, but **removing compiler intrinsic versions** of the legitimate functions like **memcpy, memset, etc**.


## The journey

The first challenge I faced, was during the ReflectiveFunction's execution, a step requires mapping the PE sections in memory. This was done by using a **memcpy** but not an "original" one, the version used was from a compiler intrinsic version.


![alt text](/images/memcopy.png)

<br>

![alt text](/images/cimem.png)

The problem here is that, even though on other parts of the code I will freely use the "real" memcpy function that lives in the CRT, for this specific operation during the ReflectiveFunction's execution, since the DLL is loading itself in memory, there cannot be any dependencies, hence the original choice of using the intrinsic function replacement.

What I did was replace this with a version of my own, that mimicks the behavior of the goal here, map the PE sections correctly:

![alt text](/images/custommemcpy.png)

<br>

![alt text](/images/cmemcpy.png)

There was another instance of memcpy on the original code, that I also replaced with a simple for loop.
```c++
//memcpy(cForwarderName, pFunctionAddress, StringLengthA((PCHAR)pFunctionAddress));

for (int i = 0; i < StringLengthA((PCHAR)pFunctionAddress); i++)
{
    ((PUCHAR)cForwarderName)[i] = ((PUCHAR)pFunctionAddress)[i];
}
```

## That anoying minor detail...

Getting rid of any references to **memcpy** was easy, but the code also had an instrinsic function for **memset**. I found it odd because there were not references to it anywhere.

I decided to ignore it, obviously. And it slapped right back into my face.

The ``ReflectiveFunction`` kept crashing, so with the amazing help of Nick (from the Offensive Windows Dev Discord), I was able to debug and see what was happening.


The program kept crashing with an access violation:
```
0:021> g
(d88.5bdc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
00000195`8a161c6c ff252e080000    jmp     qword ptr [00000195`8a1624a0] ds:00000195`8a1624a0=7273722e00000098
```

Call stack:

```
0:021> k
 # Child-SP          RetAddr               Call Site
00 00000058`7a2ffa68 00000195`8a1607a5     0x00000195`8a161c6c
01 00000058`7a2ffa70 00000195`8a1600f8     0x00000195`8a1607a5
02 00000058`7a2ffa78 00000195`8a1601e8     0x00000195`8a1600f8
03 00000058`7a2ffa80 00000195`8a93cfa0     0x00000195`8a1601e8
04 00000058`7a2ffa88 00007ffb`5b5cb0ee     0x00000195`8a93cfa0
05 00000058`7a2ffa90 00007ffb`5b5cb01d     ntdll!RtlpHpFreeWithExceptionProtection+0x1e
06 00000058`7a2ffb00 00007ffb`5b59e937     ntdll!RtlFreeHeap+0x6d
07 00000058`7a2ffb40 00007ffb`58c87ad0     ntdll!RtlFreeUnicodeString+0x17
08 00000058`7a2ffb70 00007ffb`58ce239f     KERNELBASE!LoadLibraryExA+0x40
09 00000058`7a2ffbb0 00000195`8a160ae4     KERNELBASE!LoadLibraryA+0x3f
0a 00000058`7a2ffbe0 00000195`8a173980     0x00000195`8a160ae4
0b 00000058`7a2ffbe8 00007ffb`5aa60000     0x00000195`8a173980
0c 00000058`7a2ffbf0 00000000`000009a8     KERNEL32!Module32NextW <PERF> (KERNEL32+0x0)
0d 00000058`7a2ffbf8 00000195`8a173058     0x9a8
0e 00000058`7a2ffc00 00000000`00000000     0x00000195`8a173058
```

We can take a look at the last function called:

```
0:021> ub 00000195`8a1607a5
00000195`8a160780 0f8208010000    jb      00000195`8a16088e
00000195`8a160786 4a8d0426        lea     rax,[rsi+r12]
00000195`8a16078a 483bd8          cmp     rbx,rax
00000195`8a16078d 0f83fb000000    jae     00000195`8a16088e
00000195`8a160793 33d2            xor     edx,edx
00000195`8a160795 488d4c2420      lea     rcx,[rsp+20h]
00000195`8a16079a 41b804010000    mov     r8d,104h
00000195`8a1607a0 e8c7140000      call    00000195`8a161c6c
```

``e8c7140000`` Let's take this and spin up IDA:

![alt text](/images/ida.png)

<br>

![alt text](/images/ida2.png)

There it is! The **memset** call! But this wasn't in any part of the C source code, how can it be calling it? The disassembly clearly tells us, but decompiling makes it even more clear:

![alt text](/images/ida3.png)

<br>

Where in our source code do we define ``cForwarderName``?

![alt text](/images/culprit.png)

The compiler places a **memset** call if we initialize the array with zeroes!

So we can just define it as:
```cpp
CHAR cForwarderName[MAX_PATH];
```
This fixes the issue, finally let's create some CRT imports by for example, having the string import and print:

```cpp
 case DLL_PROCESS_ATTACH:
 {
     Payload();
     std::string mystring = "hello";
     printf("%s", mystring);
     ExitProcess(1);
     break;

 }
 ```
Now, to test the result, we just need to inject it into a process:

![alt text](/images/works.png)

And by looking at the DLL on PE-Bear, we can clearly see that the CRT is being imported successfully!

![alt text](/images/imported.png)


## The last mile is the longest

I almost stopped here, I achieved my goal of having a RDLL that loads the CRT. But I did not like the way that I had to do a specialized loader, I wanted to avoid the overhead of manually looking for the exported function and redirecting execution to it specifically.

As many of you know, sRDI exists and it is a straight up fix to this issue: https://github.com/monoxgas/sRDI

Basically, instead of making the RDLL export a specific function, sRDI works by prepending the DLL with a blob of position independent code that does the loading of the DLL.

This makes sRDI usable with **any** DLL, and as far as my knowledge goes, it is the most flexible way of achieving also my end goal, since you can load any DLL, their imports do not matter at all, the loader blob will parse and import all the requirements.

By accident, I also found a **very** good article from IBM X-Force about the Cobalt Strike UDRL: https://www.ibm.com/think/x-force/defining-cobalt-strike-reflective-loader

Upon reading it, about halfway Bobby talks about the way that Cobalt Strike's Beacon is turned into shellcode, and I realized this could be yet another alternative that I could use.

## A slightly different RDLL

Instead of prepending a loader to the DLL and exporting it as shellcode, why don't we just use the initial bytes from the DLL itself?

![alt text](/images/beacon.png)

The image above is from the article mentioned beforehand, and the idea is that by patching the DLL's initial bytes with assembly instructions that find the ``ReflectiveLoader`` function address and execute it, we no longer need a blob that loads the DLL into memory, making this a sort of **hybrid** between classic RDLL and the sRDI version.

One caveat though, is that in Beacon's case, DLLMain is still called after the ReflectiveLoader function executes. In my case, this is not needed as the function itself will call DllMain.


![alt text](/images/shellcode.png)

This is an example of what the shellcode could look like (I use NeoVim, btw).

So now, after patching the DLL and saving it as a binary file, we can use any shellcode loader to load our payload.

![alt text](/images/outcome.png)


## Was this all worth the trouble?

I went out to solve a problem that didn't really require a solution (sRDI already existed), but I ended up learning a lot from the journey itself. Trying things and understanding why they work, their design choices, troubleshooting them are skills that I have found valuable to have in this field.

I will be posting the code soon to my Github page, or should I re-write everything in Rust?...