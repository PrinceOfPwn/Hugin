# Atlas Material — edr-evasion (part 3)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: evasion
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: 32-bit, Wow64, Unhooking Hooks, MOV EDI, EDI, hot patches
Summary: The text describes the mechanics of 32-bit (Wow64) function hooking, specifically focusing on how `MOV EDI, EDI` instructions are used as placeholders for hot patches. It explains why these specific instructions are used and how they can be overwritten with jump instructions to bypass hooks.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 46 Unhooking Hooks: 32-Bit Example What a prolog hook might look like for 32-bit (Wow64) What a prolog hook might look like for 32-bit (Wow64) Non-hooked function Non-hooked function Hooked function Hooked function nop nop nop nop nop mov edi, edi push ebp mov ebp, esp jmp rel32 E9 xx xx xx xx jmp 0xFB (‐5) EB F9 Unhooking Hooks: 32-Bit Example 32-bit functions are very interesting because they typically begin with several NOP instructions, or no operations. If you are not familiar with the NOP instruction, then do not worry because it literally does nothing but waste one CPU cycle. It has no effect on re

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: assembly, unhooking hooks, 46-bit, non-hooked vs hooked
Summary: The unit describes an assembly language comparison between non-hooked and hooked functions in a 46-bit environment. It illustrates what a typical prologue hook looks like.
Excerpt:
Visual caption: A slide titled 'Unhooking Hooks: 46-Bit Example' showing a comparison between non-hooked and hooked functions in assembly language. Visible text: Unhooking Hooks: 46-Bit Example; Non-hooked function; Hooked function; What a prolog hook might look like for 46-bit; SANS SEC70 Alt/source label:

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: 64-bit inline hook, MOV, JPRQ instructions, RAX register usage, template for 64-bit jump
Summary: The unit describes the mechanics of 64-bit inline hooks, specifically how they utilize MOV and JMP instructions to handle absolute addresses in a 64-bit environment. It explains the difference between 32-bit and 15-byte padding for 64-bit hooks due to variable instruction lengths. The text also details why RAX is used as an intermediate register.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 47 Unhooking Hooks: 64-Bit Example What a prolog hook might look like for 64-bit What a prolog hook might look like for 64-bit Non-hooked function Non-hooked function Hooked function Hooked function mov r10, rcx mov eax, 41 .... mov rax, 1122334455667788 jmp rax nop nop nop Unhooking Hooks: 64-Bit Example Just like the previous slide that covered 32-bit inline hook, we have a visualization for a 64-bit inline hook. Even though there is no typical prolog like what you might normally see for x86, the JMP instruction is used in a similar fashion. The JMP instruction is quite interesting for both 32-bit and 6

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: unhooking hooks, Ntdll.dll, C:\Windows\System32, TEXT section, grabbing a fresh copy
Summary: The text describes a method for unhooking hooks by replacing the tampered memory version of system libraries like Ntdll.dll with a fresh copy from the disk. This technique, known as 'grabbing a fresh copy,' involves copying the entire TEXT section to restore original functionality. It also notes that while detections exist, they are uncommon and mentions the risk of patching on-disk files.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 50 Unhooking Hooks: A Fresh Copy There is another way to unhook hooks. There is another way to unhook hooks. The system libraries that are stored in C:\Windows\System32 can serve as a validation for your integrity checks, but instead of copying the first several bytes from disk to memory, just copy in the entire TEXT section. Unhooking Hooks: A Fresh Copy When it comes to unhooking a function, there are several methods we can implement. One method is to use the original version of the function as found in the DLL on disk. This method has been dubbed “a fresh copy” where a clean copy of a system library fo

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: unhooking hooks, Ntdll.dll, C:\Windows\System32, TEXT section, grabbing a fresh copy
Summary: The text describes a method for unhooking hooks by replacing the in-memory version of system libraries like Ntdll.dll with a fresh copy from the disk. This technique, known as 'grabbing a fresh copy,' involves copying the entire TEXT section to restore original functionality. It also notes that while detections exist, they are uncommon and mentions the risk of patching on-disk files.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 50 Unhooking Hooks: A Fresh Copy There is another way to unhook hooks. There is another way to unhook hooks. The system libraries that are stored in C:\Windows\System32 can serve as a validation for your integrity checks, but instead of copying the first several bytes from disk to memory, just copy in the entire TEXT section. Unhooking Hooks: A Fresh Copy When it comes to unhooking a function, there are several methods we can implement. One method is to use the original version of the function as found in the DLL on disk. This method has been dubbed “a fresh copy” where a clean copy of a system library fo

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NTDLL.dll, CreateFileA, CreateFileMapping, MapViewOfFile, .text section, file mapping
Summary: The text describes a technique for restoring a fresh copy of NTDLL.dll on disk using file mapping APIs. It outlines a specific sequence of create, map, and copy operations to replace a tampered .text section in memory.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 A Fresh Copy Visualization On disk On disk In memory In memory Ntdll.dll Ntdll.dll .text .text 1. CreateFileA(ntdll.dll, ...) 2. CreateFileMapping(hNtdll, ...) 3. MapViewOfFile(hNtdllMapping, ...) 4. Find NtHeader 5. Find .text section 6. memcpy() section over A Fresh Copy Visualization Perhaps the best way to copy over a fresh copy of NTDLL on disk is to create a file mapping. The process is not complicated at all once you become familiar with the few APIs involved. The first action to execute is to obtain a module handle to the DLL using the CreateFile API, which will return a handle to us. From the 

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unhooking Hooks, bypassing security hooks, SEC701, Red Teaming Tools
Summary: The unit describes a slide from a cybersecurity course discussing techniques for bypassing security hooks. It specifically mentions 'Unhooking Hooks' as a method to bypass monitoring.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Unhooking Hooks: A Suspended Copy' discussing techniques for bypassing security hooks. Visible text: Unhooking Hooks: A Suspended Copy; Yet another way to unhook hooks; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: unhooking, suspended state, CreateProcess, Ntdll.dll, .text section
Summary: The text describes a method for unhooking hooks by creating a process in a suspended state to retrieve an unhooked version of Ntdll.dll's .text section. This technique leverages the fact that EDR/AV solutions cannot hook functions during the initial loading phase of a process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 52 Unhooking Hooks: A Suspended Copy Yet another way to unhook hooks Yet another way to unhook hooks What modules are loaded when you create a process in the suspended state? A debugger can show you that only Ntdll.dll should be implicitly loaded because it is getting ready to load the image into memory. If a process is created in the suspended state, its thread does not execute yet, thus no AV/EDR hooks can be implemented yet. Unhooking Hooks: A Suspended Copy Grabbing the .text section of Ntdll.dll from disk is not the only option. For this one, think back to when we created a process in the suspended s

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unhooking Hooks, Suspended Copy, Ntdll.dll .text section, CreateProcess API, suspended state
Summary: The text describes a technique for unhooking hooks by creating a process in a suspended state to retrieve an unhooked version of Ntdll.dll's .text section. This method leverages the fact that EDR/AV solutions cannot hook functions during the initial loading phase of a process. The content focuses on how and why this approach is effective for bypassing security software.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 52 Unhooking Hooks: A Suspended Copy Yet another way to unhook hooks Yet another way to unhook hooks What modules are loaded when you create a process in the suspended state? A debugger can show you that only Ntdll.dll should be implicitly loaded because it is getting ready to load the image into memory. If a process is created in the suspended state, its thread does not execute yet, thus no AV/EDR hooks can be implemented yet. Unhooking Hooks: A Suspended Copy Grabbing the .text section of Ntdll.dll from disk is not the only option. For this one, think back to when we created a process in the suspended s

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcess(), CREATE_SUSPENDED, syscall table, hooked process, security research
Summary: The unit describes a technique for obtaining syscall tables from suspended processes. It details steps such as creating a process with CREATE_SUSPENDED, locating the text section, finding the syscall table, and copying it into a hooked process.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'A Suspended Copy' describing the process of obtaining syscall tables from suspended processes. Visible text: A Suspended Copy; Call CreateProcess() with CREATE_SUSPENDED; Find the text section; Find the syscall table; Copy the table into the hooked process; Inject your shellcode at will; In memory; NtDll - text; syscall table; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: user mode hooks, EDR DLL, kernel mode, SEC770
Summary: The text describes a lab exercise focused on identifying and clearing user-mode hooks implemented by EDR DLLs. It notes that kernel-mode EDR components will be covered in subsequent courses.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 56 What’s the Point? What’s the point? 56 What’s the Point? The point of this lab was to explore one of several methods of clearing out user mode hooks that an EDR’s DLL might implement. The kernel mode side of an EDR will be discussed in follow-on courses like SEC770. 56 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: user mode hooks, EDR DLL, clearing out hooks
Summary: The text describes a lab exercise focused on identifying and clearing user-mode hooks implemented by EDR DLLs. It notes that kernel-mode EDR components will be covered in subsequent courses.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 56 What’s the Point? What’s the point? 56 What’s the Point? The point of this lab was to explore one of several methods of clearing out user mode hooks that an EDR’s DLL might implement. The kernel mode side of an EDR will be discussed in follow-on courses like SEC770. 56 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Sywshipers, system call detection bypass, WoW4, EGGs, direct syscall jumps
Summary: The unit describes the Sywshipers tool used for bypassing system call detection. It highlights specific techniques such as WoW4, EGGs, and direct syscall jumps in both WoW4 and x64 architectures.
Excerpt:
Visual caption: A slide titled 'More Techniques' describing the Sywshipers tool for bypassing system call detection. Visible text: More Techniques; Sywshipers1, 2, 3; Sywshipers3: WoW4, EGGs, direct syscall jumps in both WoW4 and x64, direct syscall jumps to random syscalls Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: unhooking, hooked functions, custom hooks, SEC679
Summary: The unit describes a summary slide for a module on unhooking hooks in the context of red teaming tools. It covers why unhooking is necessary, identifying hooked functions, and exploring various methods to implement custom hooks.
Excerpt:
Visual caption: A summary slide for a module on unhooking hooks in the context of red teaming tools. Visible text: Module Summary; Discussed why we would unhook hooks; Found hooked functions; Explored various ways to unhook hooks; Implemented your own hooks; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: unhooking, hooked functions, summary of methods
Summary: The unit discusses the rationale and techniques for unhooking functions that have been hooked by security software or other malware. It covers identifying hooked functions, exploring various unhooking methods, and implementing custom hooks.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 58 Module Summary Discussed why we would unhook hooks Discussed why we would unhook hooks Found hooked functions Found hooked functions Explored various ways to unhook hooks Explored various ways to unhook hooks Implemented your own hooks Implemented your own hooks Module Summary In this module, we discussed several reasons as to why you might want to unhook functions that were already being hooked by something else or someone else’s malware. Many AV solutions will also hook functions that they think are commonly used in malware. They will also pay attention to the call order of APIs because that could be

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: detection avoidance, evasion methods, good and bad of methods
Summary: The unit outlines the learning objectives for a module focused on evasion techniques. It covers reasons for avoiding detection, various implementation methods for evasion, and an analysis of the defense-evasion trade-offs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 64 Objectives Our objectives for this module are: Discuss reasons to avoid detection Explore various methods to avoid detection Discuss the good and the bad Objectives The objectives for this module are to discuss some of the reasons why you would want to avoid detection, explore some of the various implementations that have been created to assist you in avoiding detection, and discuss the good and the bad of some of those methods. 64 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: detection avoidance, red team tactics, module objectives
Summary: The unit outlines the learning objectives for a module on avoiding detection during red teaming operations. It covers reasons for evasion, various implementation methods, and an analysis of the advantages and disadvantages of different techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 64 Objectives Our objectives for this module are: Discuss reasons to avoid detection Explore various methods to avoid detection Discuss the good and the bad Objectives The objectives for this module are to discuss some of the reasons why you would want to avoid detection, explore some of the various implementations that have been created to assist you in avoiding detection, and discuss the good and the bad of some of those methods. 64 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV/EDR avoidance, detection complexity, function hooking, unhooking hooks
Summary: The text discusses the importance of avoiding detection by AV and EDR solutions during a red team engagement. It introduces the concept of multiple levels of evasion techniques to counter blue team detections. The section specifically mentions exploring methods like unhooking functions and other advanced bypass techniques.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 65 Why Avoid Detection? Why would you want to be detected? Unless you are intentionally trying to test an AV solution, you want to remain undetected for as long as possible. To do that, you must find a method that enables you to bypass whatever solution is being used on the target. AV/EDR solutions can give away your presence. AV/EDR solutions can give away your presence. Why Avoid Detection? Nobody wants to be detected immediately after gaining access to the target system, unless that is your goal. Perhaps though, you have several levels of avoidance you want to implement against your blue team so they c

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV/EDR evasion, detection avoidance, hooking functions, unhooking hooks
Summary: The unit discusses the importance of avoiding detection by AV and EDR solutions during a red team engagement. It introduces the concept of multiple levels of avoidance techniques to increase complexity for defenders. The text mentions that while no single bypass exists, specific methods like unhooking and other advanced techniques will be explored.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 65 Why Avoid Detection? Why would you want to be detected? Unless you are intentionally trying to test an AV solution, you want to remain undetected for as long as possible. To do that, you must find a method that enables you to bypass whatever solution is being used on the target. AV/EDR solutions can give away your presence. AV/EDR solutions can give away your presence. Why Avoid Detection? Nobody wants to be detected immediately after gaining access to the target system, unless that is your goal. Perhaps though, you have several levels of avoidance you want to implement against your blue team so they c

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: antivirus detection engines, static vs dynamic analysis, YARA rules, bypass techniques (delaying, encryption), Bitdefender example
Summary: The text describes the components of antivirus (AV) detection engines, specifically focusing on static and dynamic analysis methods. It discusses how static signatures like YARA rules are used to detect threats before execution, while dynamic analysis involves monitoring behavior in virtualized containers. The section also mentions specific AV features like Bitdefender's machine learning-based scanning modes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 66 Detection Engines There are multiple components that make up a solution. There are multiple components that make up a solution. Static Static Dynamic Dynamic Signature matching engine before runtime using rules similar to YARA Executing samples in a virtualized container to detect malicious behavior Scan Scan Some AVs offer a scanning engine with various modes like Automatic/Custom Detection Engines When it comes to protecting users and the system, it is best if the AV solution can detect the threat before it has a chance to execute, naturally. At this stage, this would fall under static analysis where

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: antivirus detection engines, static vs dynamic analysis, YARA rules, execution delay, Bitdefender scanning modes
Summary: The text discusses the components of antivirus (AV) detection engines, specifically focusing on static and dynamic analysis techniques. It describes how static rules like YARA are used to detect threats before execution, while dynamic analysis involves monitoring behavior in virtualized containers. The section also mentions specific AV features like Bitdefender's machine learning-based scanning modes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 66 Detection Engines There are multiple components that make up a solution. There are multiple components that make up a solution. Static Static Dynamic Dynamic Signature matching engine before runtime using rules similar to YARA Executing samples in a virtualized container to detect malicious behavior Scan Scan Some AVs offer a scanning engine with various modes like Automatic/Custom Detection Engines When it comes to protecting users and the system, it is best if the AV solution can detect the threat before it has a chance to execute, naturally. At this stage, this would fall under static analysis where

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Detection Engines, Static, Dynamic, Scan, Signature matching
Summary: The unit describes the components of antivirus detection engines, specifically highlighting static, dynamic, and scan engines. It details how signature matching is used for identification and mentions the used of virtualized containers for executing samples.
Excerpt:
Visual caption: A slide titled 'Detection Engines' describes the components of an antivirus solution, including static, dynamic, and scan engines. Visible text: Detection Engines; Static; Dynamic; Scan; Signature matching engine; Executing samples in a virtualized container; Some AVs offer a scanning engine Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Choose Your Parent Process, evade detection, slide
Summary: The unit describes a technique for evading detection by selecting specific parent processes when spawning new processes. It highlights thes importance of choosing appropriate parents to avoid security alerts.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Choose Your Parent Process' discussing techniques to evade detection by selecting appropriate parent processes. Visible text: Choose Your Parent Process; What if you could choose your parent process?; One method that can be used as an addition to avoid detection is to choose your parent process. There are certain processes that should never spawn other proces Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: parent process, evasion, explorer.exe, PowerShell, CMD prompt, process relationship
Summary: The text discusses the importance of selecting an appropriate parent process to evade detection during red teaming operations. It explains how certain processes, like browsers or office applications, spawning suspicious child processes (e.g., PowerShell) are flagged by security solutions. The section describes a basic Windows mechanism for choosing a specific parent process to blend in with normal system activity.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 Choose Your Parent Process One method that can be used as an addition to avoid detection is to choose your parent process. There are certain processes that should never spawn other processes, including PowerShell or CMD prompt; browsers, or office applications. What if you could choose your parent process? What if you could choose your parent process? Choose Your Parent Process If you were developing an AV solution, one of the checks you might implement is the relationship between processes. Watching explorer.exe spawn a number of processes of all kinds is fine but watching a browser process spawn a Po

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: parent process, evasion, explorer.exe, process relationship, security monitoring
Summary: The text discusses techniques for evading detection by selecting a legitimate parent process (e.g., explorer.exe) instead of suspicious ones like browsers or office applications when spawning new processes. It explains how security solutions monitor process relationships to identify anomalies, such as an Excel document spawning a command prompt.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 Choose Your Parent Process One method that can be used as an addition to avoid detection is to choose your parent process. There are certain processes that should never spawn other processes, including PowerShell or CMD prompt; browsers, or office applications. What if you could choose your parent process? What if you could choose your parent process? Choose Your Parent Process If you were developing an AV solution, one of the checks you might implement is the relationship between processes. Watching explorer.exe spawn a number of processes of all kinds is fine but watching a browser process spawn a Po

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Parent Process Implementation, Are you my parent?, two API calls, presentation slide
Summary: The unit describes a technique for manipulating process attributes to choose a parent process. It highlights that this method requires only two API calls and is intended to be used for evading detection.
Excerpt:
Visual caption: A presentation slide titled 'Choose Your Parent Process Implementation' showing a diagram and pseudo-code for manipulating process attributes. Visible text: Choose Your Parent Parent Process Implementation; Are you my parent?; Requires just two API calls; Helps avoid detection; SANS Institute 2024; SEC701 / Red Team Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: parent process, InitializeProcThreadAttributeList, UpdateProcThreadAttribute, buffer size, summary of API usage
Summary: The unit describes the implementation of a technique to choose a parent process for a new thread or process, specifically using the InitializeProcThreadAttributeList and UpdateProcThreadAttribute APIs. It explains how these APIs are used to avoid detection by ensuring that suspicious processes (like cmd.exe) are not spawned from common applications like Excel or Word. The text includes pseudo-code logic for buffer allocation and attribute list updates.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 68 Choose Your Parent Process: Implementation Are you my parent? Are you my parent? Requires just two API calls Requires just two API calls //// make pointer variable PPROC_THREAD_ATTRIBUTE_LIST pAttrList; //// get the buffer size needed InitializeProcThreadAttributeList(...); //// make the real call InitializeProcThreadAttributeList(...); //// update the attribute before creation UpdateProcThreadAttribute(...); Helps avoid detection Helps avoid detection Choose Your Parent Process: Implementation As with any new method, there will be a new set of APIs and/or structures to understand. Everything that is a

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV/EDR bypass, detection avoidance, cloud engine submission, reverse engineering, security tool development
Summary: This unit discusses the advantages and disadvantages of developing custom bypasses for AV/EDR solutions. It highlights that while bypassing allows for longer persistence, it requires significant time and effort in research and reverse engineering.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 71 The Pros and Cons Just like anything else, there is an upside and downside. Just like anything else, there is an upside and downside. Pros Pros Cons Cons Avoid detection and live longer Sample not submitted to cloud engine Time consuming Requires knowledge of inner workings Cons Cons Could lose sample to AV/EDR cloud engine if not properly cut off from internet The Pros and Cons Bypassing AV/EDR solutions is not an easy task. There are a few pros and cons with doing so and some of the pros might seem obvious. One obvious pro is that by finding a bypass, our presence on the target will not be detected. 

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV/EDR bypass, detection avoidance, summary of pros/cons, reverse engineering
Summary: The unit discusses the advantages and disadvantages of developing custom bypasses for AV/EDR solutions. It highlights that while bypassing detection allows for longer persistence, it requires significant time and effort in research and reverse engineering.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 71 The Pros and Cons Just like anything else, there is an upside and downside. Just like anything else, there is an upside and downside. Pros Pros Cons Cons Avoid detection and live longer Sample not submitted to cloud engine Time consuming Requires knowledge of inner workings Cons Cons Could lose sample to AV/EDR cloud engine if not properly cut off from internet The Pros and Cons Bypassing AV/EDR solutions is not an easy task. There are a few pros and cons with doing so and some of the pros might seem obvious. One obvious pro is that by finding a bypass, our presence on the target will not be detected. 

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV/EDR bypass, detection avoidance, publicly available methods
Summary: The unit provides a summary of the module covering techniques for bypassing antivirus (AV) and endpoint detection and response (EDR) systems. It emphasizes that avoiding detection is critical for maintaining persistence on a target system.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 72 Module Summary Learned bypassing AV/EDR should be a requirement Learned bypassing AV/EDR should be a requirement Discussed how avoiding detection allows you to remain on target longer Discussed how avoiding detection allows you to remain on target longer Discovered several publicly available methods exist to assist with avoidance Discovered several publicly available methods exist to assist with avoidance Module Summary In this module, we discussed a small number of methods that can be taken to help you bypass detection and stay on target longer. There are many more that are out there and perhaps you w

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV/EDR bypass, detection avoidance, persistence
Summary: The unit summarizes a module on bypassing AV/EDR systems to maintain persistence and avoid detection during an engagement. It notes that while only a few methods are used in the instance, many more exist publicly.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 72 Module Summary Learned bypassing AV/EDR should be a requirement Learned bypassing AV/EDR should be a requirement Discussed how avoiding detection allows you to remain on target longer Discussed how avoiding detection allows you to remain on target longer Discovered several publicly available methods exist to assist with avoidance Discovered several publicly available methods exist to assist with avoidance Module Summary In this module, we discussed a small number of methods that can be taken to help you bypass detection and stay on target longer. There are many more that are out there and perhaps you w

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: certificate pinning, Man-in-the-Middle (MITM), WinHttp, WinInet, CertFreeCertificateChain
Summary: The unit discusses the concept and implementation of certificate pinning in Windows-based implants to prevent Man-in-the-Middle (MITM) attacks. It provides specific API calls like CertGetNameString and CertFreeCertificateChain for handling certificate chains. The text also notes that both WinHttp and WinInet can be used for implementing this technique.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 109 Cert Pinning Let’s put a pin in it Let’s put a pin in it Windows, Apple, Android, and others all do certificate pinning Windows, Apple, Android, and others all do certificate pinning // ask for server’s cert chain context InternetQueryOption(INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEX T) // find first of common name, unit name, org name CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE) // get encrypted key hash for cert context CertGetCertificateContextProperty(CERT_HASH_PROP_ID) // convert hash to hex bytes std::stringstream ss; ss << std::hex; for (; i < hashLen; ) { ss << static_cast<INT>(certHash[i]);

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: strings, global variables, data section, IDAPro, Ghidra, array technique
Summary: The unit discusses techniques for avoiding detection by hiding strings and global variables in Windows implants. It explains how declaring string arrays of individual characters can prevent them from being stored in the data sections, but notes that static analysis tools like IDA Pro or Ghidra still allow manual identification.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 124 Avoiding Strings/Global Variables Strings can easily give you away. Strings can easily give you away. Avoid references to the data section. Avoid references to the data section. // change this char charName[] = “GetProcAddress”; // or this char* charName = “GetProcAddress” // to this char charName[] = {‘G’,‘e’,‘t’,‘P’,...,0}; // avoid global vars int g_c2port = 4444; char* g_charName = “LoadLibraryA”; Can still be found via static analysis in IDAPro or Ghidra Can still be found via static analysis in IDAPro or Ghidra Avoiding Strings/Global Variables Strings can be a dead giveaway as to what your impl

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: string obfuscation, global variables, static analysis, IDAPro, Ghidra
Summary: The unit describes techniques for obfuscating strings and avoiding global variables to prevent detection during static analysis. It highlights how these specific elements can be used by analysts using tools like IDAPro or Ghidra.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Avoiding Strings/Global Variables' showing code snippets and explanations for obfuscating strings. Visible text: Avoiding Strings/Global Variables; Strings can easily give you away; Avoid references to the data section; Can be found by static analysis in IDAPro or Ghidra; change this; use this; to this; avoid global vars Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: string obfuscation, data section avoidance, IDA Pro/Ghidra visibility, array of characters, NULL-terminated
Summary: The unit discusses techniques for avoiding detection by hiding strings and global variables in Windows implants. It explains how string arrays of individual characters can be used to bypass simple automated tools like the 'strings' utility. It also notes that while array methods may hide data from basic scanners, they remain visible to manual analysis in tools like IDA Pro or Ghidra.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 124 Avoiding Strings/Global Variables Strings can easily give you away. Strings can easily give you away. Avoid references to the data section. Avoid references to the data section. // change this char charName[] = “GetProcAddress”; // or this char* charName = “GetProcAddress” // to this char charName[] = {‘G’,‘e’,‘t’,‘P’,...,0}; // avoid global vars int g_c2port = 4444; char* g_charName = “LoadLibraryA”; Can still be found via static analysis in IDAPro or Ghidra Can still be found via static analysis in IDAPro or Ghidra Avoiding Strings/Global Variables Strings can be a dead giveaway as to what your impl

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AMSI, patching amsi.dll, PowerShell process, sourcing data for analysis
Summary: The unit describes Lab 5.4, 'AMSI No More', which focuses on patching the amsi.dll library within a PowerShell process to bypass AMSI protections.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 138 Lab 5.4: AMSI No More Patch a PowerShell process with amsi.dll loaded Observe how data is being passed in for analysis Explore various methods to patch amsi.dll Lab 5.4: AMSI No More Please refer to the eWorkbook for the details of this bootcamp challenge. 138 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AMSI No More, patching amsi.dll, PowerShell script, SANS SEC670
Summary: The unit describes a lab exercise focused on patching the amsi.dll library within PowerShell scripts. It outlines objectives such as observing data flow for analysis and exploring various methods to bypass AMSI protections.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 5.4: AMSI No More' outlining the objectives for patching amsi.dll. Visible text: Lab 5.4: AMSI No More; Patch a PowerShell script with amsi.dll loaded; Observe how data is being passed in for analysis; Explore various methods to patch amsi.dll; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 38 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: antivirus exclusions, Set -WyPreference, -ExclusionPath, registry key
Summary: The unit describes how to configure antivirus exclusion rules using specific command-line flags and registry keys. It focuses on technical configuration steps for bypassing or avoiding detection by security software.
Excerpt:
Visual caption: A screenshot of a documentation page explaining how to use exclusion rules for antivirus software. Visible text: Exclusions; Set -WyPreference -ExclusionPath "C:\\\Windows\System32"; If the exclusions are configured on an AV URL, you can find the corresponding registry key... Alt/source label:

=== UNIT 39 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerShell, Constrained Language Mode, CLM, ExecutionPolicy, SessionState.LanguageMode
Summary: The unit contains a screenshot of a PowerShell script used to check for Constrained Language Mode (CLM). It includes specific commands to verify the ExecutionPolicy and the current SessionState.LanguageMode.
Excerpt:
Visual caption: A screenshot of a PowerShell script and its corresponding output showing the execution of commands to check for Constrained Language Mode (CLM). Visible text: PowerShell Constrained Language Mode; ExecutionPolicy; powerShell -executionpolicy bypass -command "$(Get-ExecutionPolicy) -ExecutionContext.SessionState.LanguageMode"; powerShell -executionpolicy bypass -command "[Math]::Pow(2,10)" Alt/source label:

=== UNIT 40 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Malleable Command and Control, Beacon, network artifacts, http.get, uri, client, server, http.post
Summary: The unit describes a screenshot of a webpage or document regarding the ablebits Malleable C2 profile configuration for Cobalt Strike's Beacon.
Excerpt:
Visual caption: A screenshot of a webpage or document titled 'Malleable Command and Control' explaining how to configure Beacon's network artifacts. Visible text: Malleable Command and Control; http.get; uri; client; server; http.post Alt/source label:
