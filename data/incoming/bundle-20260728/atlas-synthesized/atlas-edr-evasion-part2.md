# Atlas Material — edr-evasion (part 2)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: evasion
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: on-disk patching, memory-mapped image, Ntdll.dll, system stability, third-party binaries
Summary: The text discusses the risks and considerations of on-disk patching for red teaming tools, specifically focusing on system stability and detection risk. It compares memory-mapped images versus disk files and advises against patching critical system DLLs like Ntdll.dll due to their widespread use.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 24 On-Disk Patching Should survive reboots; cascading effect Should survive reboots; cascading effect Are files on disk better protected from patching than their memory mapped image? Is there a way to undo your changes if you accidentally break something with your patch? Could you render a system unstable if you patch system files? Could you get caught faster by patching files on disk? On-Disk Patching There might come a time when you would have to patch the file as it resides on the file system. If you have the proper permissions, you might be able to patch the binaries that offer signature scanning for 

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AppCert DLLs, CreateProcess, WinExec, Registry key query, reboot required
Summary: This unit describes the AppCert DLL mechanism where specific Registry keys are queried during certain API calls like CreateProcess and WinExec. It explains that while this method allows for loading DLLs, it requires administrative privileges and a system reboot to be implemented.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 31 AppCert DLLs Certain Create* API calls look for AppCert. Certain Create* API calls look for AppCert. CreateProcess CreateProcess Like AppInit, Windows will investigate the Registry for DLLs that must be loaded into a process. The AppCert key will be queried when the CreateProcess, CreateProcessAsUser, CreateProcessWithLogin, CreateProcessWithToken, or WinExec functions are called. WinExec WinExec AppCert DLLs Almost as a compliment to AppInit, there is AppCert, which is extremely similar in the sense that a Registry key will be queried to find a list of DLLs a process must load. The AppCert key would b

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL, hiding service, Joshua Wright, SANS SEC670
Summary: The unit describes a real-world example of using Security Descriptor Definition Language (SDDL) strings to hide Windows services. It includes a specific SDDL string crafted by an instructor for this purpose and provides a reference link.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 54 Exercise: SDDL Hiding the service Hiding the service From Joshua Wright From Joshua Wright "D: (D;;DCLCWPDTSD;;;IU) (D;;DCLCWPDTSD;;;SU) (D;;DCLCWPDTSD;;;BA) (A;;CCLCSWLOCRRC;;;IU) (A;;CCLCSWLOCRRC;;;SU) (A;;CCLCSWRPWPDTLOCRRC;;;SY) (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) S: (AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)" Applies to several SIDs Applies to several SIDs Exercise: SDDL SANS instructor and author Joshua Wright crafted the SDDL string shown on the slide during an engagement and used it to hide a service he created. Take 10-15 minutes to break down this real-world example piece by piece just like we 

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL, hiding services, Windows service, Joshua Wright
Summary: This unit provides a real-world example of an SDDL string used to hide a Windows service from standard discovery tools. It includes the specific SDDL syntax and a reference link for further study.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 54 Exercise: SDDL Hiding the service Hiding the service From Joshua Wright From Joshua Wright "D: (D;;DCLCWPDTSD;;;IU) (D;;DCLCWPDTSD;;;SU) (D;;DCLCWPDTSD;;;BA) (A;;CCLCSWLOCRRC;;;IU) (A;;CCLCSWLOCRRC;;;SU) (A;;CCLCSWRPWPDTLOCRRC;;;SY) (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) S: (AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)" Applies to several SIDs Applies to several SIDs Exercise: SDDL SANS instructor and author Joshua Wright crafted the SDDL string shown on the slide during an engagement and used it to hide a service he created. Take 10-15 minutes to break down this real-world example piece by piece just like we 

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL strings, securitybaseapi.h, aclapi.h, SetSecurityDescriptorControl, SetNamedSecurityInfo, Programmatically Hide a Service
Summary: The text discusses the programmatic methods for hiding a Windows service by using specific APIs instead of manual SDDL strings. It highlights the use of securitybaseapi.h and aclapi.h headers to access functions like SetSecurityDescriptorControl and SetNamedSecurityInfo. These techniques are essential for developers creating custom tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 58 Programmatically Hide a Service Manual versus programmatically Manual versus programmatically As with almost everything you do manually in a shell like the cmd prompt, there are Windows APIs on the back end that enable that effort. SDDL strings and ACE strings can be daunting to hand jam in an interactive session, but perhaps using the APIs is easier. Programmatically Hide a Service Crafting your SDDL string to change the permissions of an object is not intuitive by any means and rather annoying. This is largely due to the archaic SDDL syntax, but it can come in handy for those one-offs where you do no

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, base address, relocation, RVAs, loader mapping, ASLR
Summary: The text explains how the Windows loader handles Dynamic-linked Libraries (DLLs) and their base addresses. It covers scenarios where a DLL is mapped to its preferred address versus being relocated due to memory conflicts, and notes that Address Space Layout Randomization (ASLR) makes finding module locations unpredictable.
Excerpt:
Dynamic-linked Libraries (7) It was already discussed that EXE and DLL files have a base value that indicates its preferred base address. There are times when the preferred base address for a DLL can be given by the loader when it is loaded, but the more common case is that it will not get its preferred base address. If you look at the graphic on the slide, the stack of pages on the left side of the slide shows the address space along with several items, like threads and the image itself, already occupying some memory regions. It just so happens that nothing is mapped at the DLL’s preferred base address. When the loader is mapping it in and it sees this, it will happily map it there. The sta

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IFEO GlobalFlag, silent process exit, fflags.exe, Windows SDK
Summary: The unit describes the IFEO GlobalFlag setting in Windows and its impact on monitoring silent processes. It mentions that this flag is bundled with the Windows SDK and relates to process monitoring.
Excerpt:
Visual caption: A slide and accompanying text describe the IFEO GlobalFlag setting in Windows, explaining how it affects the process monitoring of 'silent' processes. Visible text: IFE0 GlobalFlag; A nice addition to the traditional IFEO; fflags.exe; silent process exit; Bundled with the Windows SDK; Monitor on any process; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control; IFE0 GlobalFlag. Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Gflags.exe, GUI version, kernel settings, image file settings, silent process exit
Summary: The unit describes the Gflags.exe utility and its graphical user interface for modifying kernel, image file, and silent process exit settings. It encourages users to explore these features for potential programmatic implementation in custom tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 83 Running Gflags.exe Running Gflags.exe The GUI version of the gflags program looks similar to the screenshot on the slide. You can see the various tabs at the top of the window that are specific to categories like the Kernel, Image File, and Silent Process Exit. Feel free to explore the tool and the features that it provides. Once you have an understanding you can programmatically implement many of these items on your own. © 2024 Jonathan Reiter 83 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Gflags.exe, GUI version, kernel, image file, programmatic implementation
Summary: The unit describes the GUI version of Gflags.exe, a tool used for manipulating kernel and image file settings. It notes that features in the GUI can be able to be programmatically implemented by developers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 83 Running Gflags.exe Running Gflags.exe The GUI version of the gflags program looks similar to the screenshot on the slide. You can see the various tabs at the top of the window that are specific to categories like the Kernel, Image File, and Silent Process Exit. Feel free to explore the tool and the features that it provides. Once you have an understanding you can programmatically implement many of these items on your own. © 2024 Jonathan Reiter 83 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GflagsX, gflags.exe, Paweł Ýosifovich, sourcing tool
Summary: The unit describes the tool GflagsX, a modern version of gflags.exe created by Paweł Ýosifovich. It highlights its purpose as an alternative to the original utility and provides a link to the source repository.
Excerpt:
Visual caption: A screenshot of a webpage or document page featuring the tool 'GflagsX' and its description. Visible text: GflagsX; A modern take on the original gflags.exe utility; Paweł Ýosifovich created a new version of gflags that offers a great new look to the tool.; Check out his repo for this and other awesome tools: https://github.com/zodiacon.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control; 84 Alt/source label:

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GFlagx, GUI for PowerShell tool, Silent Process Exit, SEC-701 Red Teaming Tools
Summary: The unit contains a screenshot and description of the GFlagx tool, which provides a GUI for managing Windows process flags. It specifically highlights options like 'Silent Process Exit' within a red teaming context.
Excerpt:
Visual caption: A screenshot of a GUI tool named 'GFlagx' showing various configuration options for Windows process flags. Visible text: Running GFlagx; GUI for PowerShell tool; GFlagx; Silent Process Exit; SEC-701 Red Teaming Tools Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GflagsX, GUI comparison, Silent Process Exit, Image tab
Summary: The text describes the comparison between GflagsX and a legacy tool, highlighting its modernized GUI and consolidated features like Silent Process Exit options under the Image tab.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 Running GflagsX Running GflagsX The GUI for Pavel’s tool looks much nicer and more modern than the legacy tool. There are not as many tabs at the top of the window, but many of those features are consolidated. For example, the Silent Process Exit tab and its options are located under the Image tab for GflagsX. © 2024 Jonathan Reiter 85 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GflagsX, GUI, Silent Process Exit, image tab, legacy tool
Summary: The text describes the GUI and features of GflagsX, a modern tool for managing process flags. It highlights that it provides a user-friendly interface compared to legacy tools while consolidating several features into fewer tabs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 Running GflagsX Running GflagsX The GUI for Pavel’s tool looks much nicer and more modern than the legacy tool. There are not as many tabs at the top of the window, but many of those features are consolidated. For example, the Silent Process Exit tab and its options are located under the Image tab for GflagsX. © 2024 Jonathan Reiter 85 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IFEO, SilentProcessExit, terminals/permissions issues
Summary: The unit discusses the definition and intended use of IFEO (Image File Execution Options) and its variant, SilentProcessExit. It covers how these features can be abused for malicious purposes while noting permission limitations when not running with elevated privileges.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 92 Module Summary Defined IFEO Defined IFEO Abused IFEO manually and programmatically Abused IFEO manually and programmatically Observed limiting factors such as permissions for IFEO Observed limiting factors such as permissions for IFEO Module Summary In this module, we defined IFEO and discussed how Microsoft intended for it to be used. We also moved into discussing another variant of IFEO, which was the SilentProcessExit option. From there we looked at how we can abuse both variants while at the same time observing permissions issues if not being done with elevated permissions like Admin or SYSTEM. 92 

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Sysmon, WMI attacks, Event Filter, WMI EventConsumer
Summary: The text discusses the use of Sysmon to detect WMI-based attacks, specifically focusing on how it can log events related to Event Filters, Event Consumers, and their bindings. It highlights that while logs are generated, determining if an event is malicious requires manual or automated categorization.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 108 Detecting WMI Attacks Sysmon can be configured to detect WMI attacks. Sysmon can be configured to detect WMI attacks. The abuse that has been done with WMI can be detected using several tools, one of them being Sysmon. The configuration can catch the Event Filters, the Event Consumers, and our bindings of filters and consumers. Detecting WMI Attacks There are several methods and tools for detecting these style of attacks, so be careful before you implement this method. One of the more popular tools today is one put out by Microsoft called Sysmon. It has proven to be very formidable, and when configure

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WMI, Sysmon configuration, symptoms of abuse
Summary: The unit describes how Sysmon can be used as a detection mechanism for WMI-based attacks. It highlights that specific configurations can identify malicious activity within WMI event filters.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Detecting WMI Attacks' featuring a note about Sysmon configuration. Visible text: Detecting WMI Attacks; Sysmon can be configured to detect WMI attacks.; The abuse that has been done with WMI can be detected using several tools, one of them being Sysmon. The configuration can catch on the Event Filters, the Event Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Sysmon, WMI attacks, Event Filter, Event Consumer, binding
Summary: The text discusses the use of Sysmon to detect WMI-based attacks, specifically focusing on how it can log events related to Event Filters, Event Consumers, and their bindings. It highlights that while logs are generated, determining if an event is just a notification or malicious depends on analyst interpretation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 108 Detecting WMI Attacks Sysmon can be configured to detect WMI attacks. Sysmon can be configured to detect WMI attacks. The abuse that has been done with WMI can be detected using several tools, one of them being Sysmon. The configuration can catch the Event Filters, the Event Consumers, and our bindings of filters and consumers. Detecting WMI Attacks There are several methods and tools for detecting these style of attacks, so be careful before you implement this method. One of the more popular tools today is one put out by Microsoft called Sysmon. It has proven to be very formidable, and when configure

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Reflective DLL Injection, RDI, manual mapping, system loader
Summary: The unit describes Reflective DLL Injection (RDI) as a technique for loading DLLs into memory without being listed by the system loader. It explains how RDI allows manual mapping of a source DLL into a target's virtual address space.
Excerpt:
Visual caption: A presentation slide and accompanying text describing Reflective DLL Injection (RDI) as a stealthy technique for loading DLLs into memory without being listed by the system loader. Visible text: Let Your Reflection Show; Reflective DLL Injection (RDI); With Reflective DLL Injection, or RDI, the source DLL is manually mapped into the target's virtual address space. This means that the full path of the DLL will Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: syscalls, unhooking hooks, hoooked functions, AV products
Summary: This unit introduces the objectives for a module on syscalls, unhooking hooks, and identifying hooked functions. It explains that hooked functions may indicate the presence of security software or other malicious actors.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 27 Objectives Our objectives for this module are: Learn about syscalls Discuss why we would need to unhook hooks Learn how to find hooked functions Learn how to re-hook hooked functions The objectives for this module are to learn about syscalls, discuss why we would even need to unhook functions. The presence of a hooked function could indicate that another malicious actor is on the box with us or that some AV product has been installed and implemented its own hooks for functions that it thinks it needs to “watch.” The latter option is most likely going to be the situation you might come across during you

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: syscalls, unhooking hooks, finding hooked functions, re-hooking
Summary: This unit introduces the objectives for a module on syscalls and unhooking functions. It covers why unhooking is necessary, such as detecting AV products or other malicious actors. The text also mentions the need to identify and re-hook functions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 27 Objectives Our objectives for this module are: Learn about syscalls Discuss why we would need to unhook hooks Learn how to find hooked functions Learn how to re-hook hooked functions The objectives for this module are to learn about syscalls, discuss why we would even need to unhook functions. The presence of a hooked function could indicate that another malicious actor is on the box with us or that some AV product has been installed and implemented its own hooks for functions that it thinks it needs to “watch.” The latter option is most likely going to be the situation you might come across during you

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: syscalls, unhooking hooks, finding hooked functions, re-hooking
Summary: The unit describes learning objectives for a module focused on system calls and unhooking hooks. It covers identifying and re-hooking functions in the context of developing Windows implants.
Excerpt:
Visual caption: A slide outlining the learning objectives for a module on system calls and unhooking hooks. Visible text: Objectives; Learn about syscalls; Discuss why we would need to unhook hooks; Learn how to find hooked functions; Learn how to re-hook hooked functions; SEC701 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NtAllocateVirtualMemory, user mode to kernel mode transition, ntdll.dll, win32u.dll, syscall number, VirtualAlloc
Summary: The text describes the transition from user mode to kernel mode via system calls, specifically focusing on how functions like VirtualAlloc are forwarded through ntdll.dll and win32u.dll. It explains that these DLLs prepare stubs for syscall execution by setting registers and performing sanity checks on syscall numbers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 30 Hello Operator? Syscall NtAllocateVirtualMemory please Syscall NtAllocateVirtualMemory please User mode User mode Kernel mode Kernel mode main:VirtualAlloc kernelbase:VirtualAlloc ntdll!NtAllocateVirtualMemory Func Addr Nt Index fffff80… 0 fffff80… 1 fffff80… … fffff80… 17 fffff80… 18 Hello Operator? Without diving deep into the weeds with the full transition into the kernel, how does a user mode process get the help of the kernel and its syscalls? When a user mode application needs to create an objects, like a process object, or when it needs to allocate pages of memory, it will eventually need the he

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: user-mode hooks, ntdll.dll, kernelbase, win32u.dll, security product monitoring, syscall number obfuscation
Summary: The text discusses how security products implement user-mode hooks in libraries like ntdll and kernelbase to monitor for malicious behavior. It explains that these hooks can obscure the original syscall numbers, requiring developers to create restoration operations for implants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 33 Hooked Syscalls NTDLL.DLL (Native) NTDLL.DLL (Native) WIN32U.DLL (GUI) WIN32U.DLL (GUI) NtOpenProcess NtUserOpenClipboard Notepad++.exe e93b3c1600 jmp 00007ffe`063f0cc0 cc int 3 cc int 3 cc int 3 Hooked Syscalls Security products will often implement any number of user mode hooks. In fact, there have been a few people that take the time to document all the hooked functions and in what modules they are hooked; ntdll, kernelbase, win32u, etc. One of those efforts is hosted by VX-Underground on their GitHub repo. The whitepaper is called AntiVirus artifacts with first, second, and third editions. The best

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: user mode hooks, ntdll.dll, kernelbase.dll, win32u.dll, Bitdefender example, syscall numbers, restore operation
Summary: The text discusses the concept of user-mode hooks implemented by security products to monitor and inspect function arguments for malicious behavior. It highlights that while individual APIs are benign, combinations can be suspicious, and notes that developers must account for these hooks when creating implants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 33 Hooked Syscalls NTDLL.DLL (Native) NTDLL.DLL (Native) WIN32U.DLL (GUI) WIN32U.DLL (GUI) NtOpenProcess NtUserOpenClipboard Notepad++.exe e93b3c1600 jmp 00007ffe`063f0cc0 cc int 3 cc int 3 cc int 3 Hooked Syscalls Security products will often implement any number of user mode hooks. In fact, there have been a few people that take the time to document all the hooked functions and in what modules they are hooked; ntdll, kernelbase, win32u, etc. One of those efforts is hosted by VX-Underground on their GitHub repo. The whitepaper is called AntiVirus artifacts with first, second, and third editions. The best

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: hooked syscalls, Notepad++.exe, NtOpenProcess, NtUserOpenClipboard, NT10.DLL, WIN32.DLL
Summary: The unit contains a screenshot of a tool displaying hooked syscalls for the Notepad++ process. It identifies specific system calls like NtOpenProcess and NtUserOpenClipboard across both native and GUI libraries.
Excerpt:
Visual caption: A screenshot of a software tool showing hooked syscalls for the Notepad++ process, including native and GUI versions. Visible text: Hooked Syscalls; Notepad++.exe; NT10.DLL (Native); WIN32.DLL (GUI); NtOpenProcess; NtUserOpenClipboard; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Direct Syscalls, NtAllocateVirtualMemory, ntdll.dll, EDR bypass, call stack spoofing
Summary: The unit discusses the concept of assembly-level direct syscalls to bypass EDR user-mode hooks. It explains how bypassing ntdll.dll's standard execution path for functions like NtAllocateVirtualMemory is used to avoid detection. The text also mentions that while it avoids user-mode hooks, kernel-mode components may still detect the call stack.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 34 Direct Syscalls Normal stub for syscall in ntdll NtAllocateVirtualMemory mov r10, rcx mov eax, 0x18 test byte ptr [7FFE0308h], 1 jne ntdll!NtAllocateVirtualMemory+0x15 syscall ret int 0x2e ret main:VirtualAlloc kernelbase:VirtualAlloc ntdll!NtAllocateVirtualMemory syscall kernel user Direct Syscalls Hello operator, I would like to make a direct call to NtAllocateVirtualMemory. Direct syscalls are as much interesting as they are old, but they are still being used to bypass some EDRs that are not up to speed with everything. This technique has been around for at least 10 years or so, but here is the gist

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: direct syscalls, ntallocatevirtualmemory, ntdll, edr bypass
Summary: The unit describes the concept of direct syscalls as a method to bypass EDR hooks by avoiding standard Windows API functions. It specifically mentions NtAllocateVirtualMemory and the difference between between normal stubs for syscalls in ntdll.
Excerpt:
Visual caption: A slide explaining the concept of direct syscalls and how they bypass EDR hooks by avoiding the standard Windows API functions. Visible text: Direct Syscalls; NtAllocateVirtualMemory; Normal stub for syscall in ntdll; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Direct Syscalls, NtAllocateVirtualMemory, ntdll.dll, EDR bypass, syscall number recovery, call stack spoofing
Summary: The unit discusses the technique of direct syscalls to bypass EDR user-mode hooks by bypassing ntdll.dll's standard execution path. It explains that while it avoids user-mode hooks, kernel-mode components may still detect calls not originating from ntdll.dll. The text also mentions methods for recovering syscall numbers and the necessity of call stack spoofing to evade advanced detection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 34 Direct Syscalls Normal stub for syscall in ntdll NtAllocateVirtualMemory mov r10, rcx mov eax, 0x18 test byte ptr [7FFE0308h], 1 jne ntdll!NtAllocateVirtualMemory+0x15 syscall ret int 0x2e ret main:VirtualAlloc kernelbase:VirtualAlloc ntdll!NtAllocateVirtualMemory syscall kernel user Direct Syscalls Hello operator, I would like to make a direct call to NtAllocateVirtualMemory. Direct syscalls are as much interesting as they are old, but they are still being used to bypass some EDRs that are not up to speed with everything. This technique has been around for at least 10 years or so, but here is the gist

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: indirect syscalls, ntdll.dll, NtAllocateVirtualMemory, evasion
Summary: The unit describes the concept of indirect syscalls as a technique to evade security products by jumping to known locations in ntdll.dll. It specifically mentions NtAllocateVirtualMemory and shellcode execution.
Excerpt:
Visual caption: A slide explaining the concept of indirect syscalls for evading security products by jumping to a known location in ntdll.dll. Visible text: Indirect Syscalls; NtAllocateVirtualMemory; Shellcode blob; ntdll.dll; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unhooking Hooks, NtMapViewOfSection, security product monitoring, recon of hooked APIs
Summary: The text discusses the rationale and risks associated with unhooking functions in a Windows environment. It explains how security products or nation-states may use hooks to monitor or modify behavior, and why red teamers might choose to unhook them to restore original functionality.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 37 Unhooking Hooks: Why? Restore intended use of a function Restore intended use of a function Hooks are, by design, implemented to change the behavior of a function. If we are trying to clean up and restore items of interest, it would be a good idea to also restore the original, intended use of a function like NtMapViewOfSection. Unhooking Hooks: Why? Perhaps a better question is who else out there might be hooking functions besides us? As mentioned previously, nation states and security products could be a solid bet. Security products might not be changing the behavior of a function but instead, looking

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unhooking Hooks, NtMapViewOfSection, security product monitoring, recon of hooked APIs
Summary: The text discusses the rationale and risks associated with unhooking functions in a Windows environment. It explains how security products or nation-states may use hooks to monitor behavior, and why red teamers might choose to unhook them to restore original functionality.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 37 Unhooking Hooks: Why? Restore intended use of a function Restore intended use of a function Hooks are, by design, implemented to change the behavior of a function. If we are trying to clean up and restore items of interest, it would be a good idea to also restore the original, intended use of a function like NtMapViewOfSection. Unhooking Hooks: Why? Perhaps a better question is who else out there might be hooking functions besides us? As mentioned previously, nation states and security products could be a solid bet. Security products might not be changing the behavior of a function but instead, looking

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unhooking Hooks, Restore intended use, security research
Summary: The unit discusses the rationale for unhooking hooks in security research. It explains that hooks are designed to change function behavior and restoring original functionality is necessary when cleaning up an area of interest.
Excerpt:
Visual caption: A presentation slide titled 'Unhooking Hooks: Why?' discussing the rationale for restoring original function behavior in security research. Visible text: Unhooking Hooks: Why?; Restore intended use of a function; Hooks are, by design, implemented to change the behavior of a function. If we are trying to clean up an area of interest, it would be a good idea to also restor; SANS SEC407: Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: unhooking, Ntdll.dll, function hooks, memory vs disk comparison, overwriting hooks
Summary: The unit describes techniques for identifying and unhooking hooks in Windows system DLLs, specifically Ntdll.dll. It details the process of scanning function headers to detect jumps or unexpected bytes, comparing memory contents against disk versions to validate findings, and replacing hooked bytes with original or custom patches.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 38 Unhooking Hooks: The Search Cannot unhook what you cannot find Cannot unhook what you cannot find Search criteria Search criteria Searching for bytes that should not be there. Function bytes should start with MOV EDI, EDI. Validation data Validation data Implementation Implementation Arguably best place to validate bytes is the version on disk, C:\Windows\Syst em32\Ntdll.dll Replace the patched bytes with original bytes or with your own patch (hook). Unhooking Hooks: The Search As discussed on the previous slide, you could come across functions that have already been hooked. You have a few options at t

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unhooking Hooks, tldns.org, VLD_version.Sys, patching bytes
Summary: The unit describes a methodology for identifying and restoring original function bytes to bypass hooks in a Windows environment. It covers search criteria, validation data like VLD_version.Systs, and the process of replacing patched bytes with original or custom patches.
Excerpt:
Visual caption: A presentation slide titled 'Unhooking Hooks: The Search' outlining the methodology for identifying and restoring original function bytes. Visible text: Unhooking Hooks: The Search; Search criteria; tldns.org; Validation data; VLD_version.Systs; Implementation; Replace the patched bytes with original bytes or with your own patch (hook). Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Meet the Gates, Heaven's gate, Hell's gate, Halo's gate, system calls, kernel mode
Summary: The unit describes three specific techniques (Heaven's Gate, Hell's Gate, and Halo's Gate) for evading detection by directly invoking system calls. It focuses on these methods as ways to bypass security controls in the kernel.
Excerpt:
Visual caption: A presentation slide titled 'Meet the Gates' describing three different methods for evading detection by directly invoking system calls. Visible text: Meet the Gates; Heaven's gate; Hell's gate; Halo's gate; The gatekeepers to kernel mode Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Heaven's Gate, Hell's Gate, Halo's Gate, syscall stub, position independent, Wow64 application
Summary: The unit describes three techniques for executing system calls: Heaven's Gate, Hell's Gate, and Halo's Gate. These methods are used to bypass hooks by avoiding direct Nt* API calls and instead invoking syscalls directly or dynamically. The text introduces the concept of turn-key solutions for these gates.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 41 Meet the Gates The gatekeepers to kernel mode The gatekeepers to kernel mode Heaven’s gate Heaven’s gate Hell’s gate Hell’s gate The gate that enables Wow64 application to jump back to 64-bit code Dynamically finds and executes syscalls while being position independent Halo’s gate Halo’s gate Determines the syscall ID of the hooked version by looking at its neighbors Meet the Gates The general idea with these gates is to evade your intentions by not making direct Nt* API calls, but instead, invoking the system call yourself. This can be done by creating your own syscall stub, identifying the proper sys

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Heaven's Gate, Hell's Gate, Halo's Gate, syscall stub, position independent, 41
Summary: The unit describes three types of syscall gate techniques: Heaven's Gate, Hell's Gate, and Halo's Gate. These methods are used to bypass hooks by invoking system calls directly or dynamically identifying syscall numbers. The text introduces these concepts as a means to evade detection during red teaming operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 41 Meet the Gates The gatekeepers to kernel mode The gatekeepers to kernel mode Heaven’s gate Heaven’s gate Hell’s gate Hell’s gate The gate that enables Wow64 application to jump back to 64-bit code Dynamically finds and executes syscalls while being position independent Halo’s gate Halo’s gate Determines the syscall ID of the hooked version by looking at its neighbors Meet the Gates The general idea with these gates is to evade your intentions by not making direct Nt* API calls, but instead, invoking the system call yourself. This can be done by creating your own syscall stub, identifying the proper sys

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Halo's Gate, direct syscalls, Ntdll.dll hooks, syscall IDs, neighboring addresses
Summary: The text describes 'Halo's Gate', a technique for using direct syscalls to bypass EDR hooks in Ntdll.dll. It explains how the method addresses the limitation of Hell's Gate by checking neighboring syscall IDs to determine the correct ID even if a function is just hooked. It concludes that this approach allows for executing syscalls without repairing the hook, thus evading detection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 43 Halo’s Gate Find your neighbor, find yourself Find your neighbor, find yourself 0 1 2 3 SSN Halo’s Gate Halo’s gate offers a refreshing twist on using direct syscalls. The downside to Hell’s gate is that it does not account for the possibility that the function in Ntdll.dll is already hooked. Should the function be hooked, then Hell’s gate will fail. Where Halo’s gate helps with this is taking advantage of the fact that the syscall IDs in Ntdll.dll are in numerical order. So, you will not find syscall 4F first. 4F will come immediately after 4E, and so on. Knowing this, if a function is already hooked,

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: 32-bit Wow64, prolog hook, NOP instruction, move edi, edi, hot patch
Summary: The text describes the mechanics of 32-bit (Wow64) function prologues and how they can be exploited for hooking. It explains the role of 'MOV EDI, EDI' as a two-byte NOP equivalent that allows for short jump instructions to bypass or implement hot patches.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 46 Unhooking Hooks: 32-Bit Example What a prolog hook might look like for 32-bit (Wow64) What a prolog hook might look like for 32-bit (Wow64) Non-hooked function Non-hooked function Hooked function Hooked function nop nop nop nop nop mov edi, edi push ebp mov ebp, esp jmp rel32 E9 xx xx xx xx jmp 0xFB (‐5) EB F9 Unhooking Hooks: 32-Bit Example 32-bit functions are very interesting because they typically begin with several NOP instructions, or no operations. If you are not familiar with the NOP instruction, then do not worry because it literally does nothing but waste one CPU cycle. It has no effect on re

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: 32-bit, assembly language, hop hook, jmp +0x32, jmp 0xF8
Summary: The unit describes a 32-bit assembly comparison between non-hooked and hooked functions to demonstrate how hooks are identified.
Excerpt:
Visual caption: A slide titled 'Unhooking Hooks: 32-Bit Example' showing a comparison between non-hooked and hooked functions in assembly language. Visible text: Unhooking Hooks: 32-Bit Example; What a prolog hook might look like for 32-bit (Wow64); Non-hooked function; Hooked function; jmp +0x32; jmp 0xF8 (-5); SEC_70 | Red Team Tooling. Developing Windows Implants, Shellcode, Command and Control Alt/source label:
