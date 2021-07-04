# LuckyCharms v4
> A detailed analysis of the cheat's inner-workings

Injected library download for people who aren't interested in the write-up:
* [LuckyCharms.dll](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/LuckyCharms.dll)

### Initial user authentication
Upon logging in, the loader will make several requests to requests to vps-5aaa99d9.vps.ovh.us to communicate with the server.
I have not analyzed this further since it is useless to my goal.

### Attempt at disabling Valve's anti-cheating measures
If the "insecure" option is disabled, the loader will send a kill signal to all running Steam processes, then start Steam and block the loading of various modules (it does this horribly, and sometimes causes various critical modules to unload which results in Steam faulting and restarting without any anti-cheat patches.).

The loader will attempt to do this by calling [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) on the Steam image path (lower-cased) with the flag __CREATE_SUSPENDED__.
Various memory writing is done, and finally [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) is called. The process is then resumed using an undocumented system call, [NtResumeProcess](https://doxygen.reactos.org/da/d3c/ntoskrnl_2ps_2state_8c.html#a0fd8f14a401ca54d812602c721ad967c).

- --> [mem0.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem0.bin) NtWriteVirtualMemory(): 004B31E8 / 4
- --> [mem1.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem1.bin) NtWriteVirtualMemory(): 00721000 / 5632
- --> [mem2.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem2.bin) NtWriteVirtualMemory(): 00723000 / 2560
- --> [mem3.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem3.bin) NtWriteVirtualMemory(): 00724000 / 512
- --> [mem4.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem4.bin) NtWriteVirtualMemory(): 00725000 / 512
- --> [mem5.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem5.bin) NtWriteVirtualMemory(): 00726000 / 512
- _lpParameter for startThread_ --> [mem6.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem6.bin) NtWriteVirtualMemory(): 00730000 / 28
- _shellcode_ --> [mem7.bin](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem7.bin) NtWriteVirtualMemory(): 0073001C / 304
- _shellcode execution_ --> CreateRemoteThread(): stackSize=0 startAddress=0073001C lpParameter=00730000

### Library injection
The loader searches for a process with the image name __csgo.exe__ then creates a process handle.
Following this, the library bytes are written into CS:GO (__6__ __NtWriteVirtualMemory__ calls), the [lpParameter](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem15.bin) (28) and [shellcode](https://github.com/0xa00/luckycharms-analysis/blob/main/bin/mem16.bin) (256).
__CreateRemoteThread__ gets called to execute the shellcode.

The loader will communicate with the library using two files:
* AppData\Local\Temp\lkjlknreieoit\\__QE2iYhpLK2pUORn__
        _This file is never deleted, and it's purpose is unknown._
* AppData\Local\Temp\qwieovnuoiq\\__tkUAEpEhiDV2NHk__
        _This file will get deleted almost instantly by the library, and is created by the loader. It's purpose is to communicate user data (such as early access and username)._

### Process termination
The loader will create a separate thread that lists all running processes, and compares their image name to the list below.
If a process is found at start-up, a kill signal will be sent and if any of these processes get started again the launcher will forcefully exit.
- 0xfcc9fd0 (16): joeboxserver.exe
- 0xfcca048 (17): ProcessHacker.exe
- 0xfcca070 (16): HookExplorer.exe
- 0xfcca098 (17): joeboxcontrol.exe
- 0xfcca0c0 (16): SysInspector.exe
- 0xfcca0e8 (17): proc_analyzer.exe
- 0xfcca138 (16): SysInspector.exe
- 0xfcca160 (16): HookExplorer.exe
- 0xfcca188 (16): HookExplorer.exe
- 0xfcca1d8 (17): joeboxcontrol.exe
- 0xfcca228 (17): ProcessHacker.exe
- 0xfcca250 (16): HookExplorer.exe
- 0xfcca278 (16): joeboxserver.exe
- 0xfcca2a0 (17): joeboxcontrol.exe
- 0xfcca2c8 (16): joeboxserver.exe
- 0xfcca2f0 (17): proc_analyzer.exe
- 0xfcca318 (20): ImmunityDebugger.exe
- 0xfcca340 (17): joeboxcontrol.exe
- 0xfcca368 (16): SysInspector.exe
- 0xfcca390 (20): ImmunityDebugger.exe
- 0xfcca3b8 (17): joeboxcontrol.exe

### Odd file system calls
The loader will check for these files in the working directory and make sure they don't exist:
I haven't analyzed this further.
- oculusmedium.exe
- petromod_nvidia_profile_identifier.ogl
- aurora.dll
