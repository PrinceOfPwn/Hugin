# Atlas Material — edr-evasion (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: evasion
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.95  Key cues: ntdll.dll, syscall table, CREATE_SUSPENDED, pattern scanning, .text section
Summary: The text describes a technique for overwriting a tampered syscall table with a clean one from a suspended process. It details the steps of creating a process in a suspended state, locating the .text section, and identifying the syscall table via pattern scanning.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 53 A Suspended Copy In memory In memory Ntdll - .text syscall table Call CreateProcess() with CREATE_SUSPENDED Call CreateProcess() with CREATE_SUSPENDED Find the .text section Find the .text section 1 2 Find the syscall table Find the syscall table Copy the table into the hooked process Copy the table into the hooked process Inject your shellcode at will Inject your shellcode at will 3 4 5 A Suspended Copy The process of grabbing the ntdll syscall tables from the suspended process is not very complicated because most of the logic you have seen already. The only new item with this technique is finding the

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: indirect syscalls, ntdll.dll, NtAllocateVirtualMemory, call stack evasion
Summary: The unit describes the technique of indirect syscalls to bypass security products by jumping into ntdll.dll's memory space for the syscall instruction. It explains that this method provides a cleaner call stack compared to direct syscalls and discusses the challenges of identifying correct syscall numbers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 35 Indirect Syscalls Shellcode blob jmp cool_edr!NtAllocateVirtualMemory jne ntdll!NtAllocateVirtualMemory+0x15 ret syscall ntdll.dll NtAllocateVirtualMemory mov r10, rcx mov eax, 0x18 jmp ntdll!NtAllocateVirtualMemory+0x10 Indirect Syscalls Hello operator, I would like to make an indirect call to NtAllocateVirtualMemory. Looking at the slide here, you may have noticed that not a lot has changed with our approach. The biggest difference to note here is that we are not going to invoke the syscall instruction inside our malware.exe. Instead, we are going to jump over into ntdll.dll where the syscall instruc

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: unhooking, Ntdll.dll, function byte comparison, Eicar-like detection logic (implied), AV evasion
Summary: The unit describes techniques for identifying and unhooking hooks in Windows system DLLs, specifically Ntdll.dll. It details the process of scanning function bytes to detect jumps or other modifications, comparing memory contents against disk versions to validate findings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 38 Unhooking Hooks: The Search Cannot unhook what you cannot find Cannot unhook what you cannot find Search criteria Search criteria Searching for bytes that should not be there. Function bytes should start with MOV EDI, EDI. Validation data Validation data Implementation Implementation Arguably best place to validate bytes is the version on disk, C:\Windows\Syst em32\Ntdll.dll Replace the patched bytes with original bytes or with your own patch (hook). Unhooking Hooks: The Search As discussed on the previous slide, you could come across functions that have already been hooked. You have a few options at t

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Hell's Gate, dynamically locate, syscalls, Ntdll.dll
Summary: The unit describes the 'Hell's Gate' technique for dynamically locating and invoking syscalls to bypass security measures. It highlights that the method is position-independent and relies on Ntdll.dll.
Excerpt:
Visual caption: A presentation slide titled 'Hell's Gate' explaining the technique of dynamically locating and invoking syscalls to bypass security measures. Visible text: Hell's Gate; Dynamically locate and invoke syscalls; Completely position independent; Relies on Ntdll.dll; SEC70 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Halo's Gate, direct syscalls, Ntdll.dll, hook detection, sequential syscall IDs
Summary: The text describes 'Halo's Gate', a technique for using direct syscalls to bypass EDR hooks in Ntdll.dll. It explains how the method addresses the limitations of Hell's Gate by leveraging sequential syscall IDs to find valid IDs even if a function is hooked. It also mentions a reference link to Reenz0h's blog.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 43 Halo’s Gate Find your neighbor, find yourself Find your neighbor, find yourself 0 1 2 3 SSN Halo’s Gate Halo’s gate offers a refreshing twist on using direct syscalls. The downside to Hell’s gate is that it does not account for the possibility that the function in Ntdll.dll is already hooked. Should the function be hooked, then Hell’s gate will fail. Where Halo’s gate helps with this is taking advantage of the fact that the syscall IDs in Ntdll.dll are in numerical order. So, you will not find syscall 4F first. 4F will come immediately after 4E, and so on. Knowing this, if a function is already hooked,

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: unhook hooks, AV solutions, hooked functions, call order of APIs
Summary: The unit discusses the rationale and techniques for unhooking functions that have been hooked by security software or other malware. It covers why AV solutions hook common APIs and how they monitor call orders to detect suspicious activity.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 58 Module Summary Discussed why we would unhook hooks Discussed why we would unhook hooks Found hooked functions Found hooked functions Explored various ways to unhook hooks Explored various ways to unhook hooks Implemented your own hooks Implemented your own hooks Module Summary In this module, we discussed several reasons as to why you might want to unhook functions that were already being hooked by something else or someone else’s malware. Many AV solutions will also hook functions that they think are commonly used in malware. They will also pay attention to the call order of APIs because that could be

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: unhooking hooks, security products, Unit Review Answers
Summary: The unit contains a review question and its corresponding answers regarding the effectiveness of unhooking hooks to blind security products. It discusses whether such an action blinds a security product entirely or depends on other factors like kernel modules.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a unit review question about unhooking hooks and security products. Visible text: Unit Review Answers; Does unhooking hooks truly blind a Security Product?; Yes, because it will no longer have introspection into that process; Depends, there could be a kernel module still watching; Only if it's Defender Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: unhooking hooks, blind a Security Product, introspection into that process
Summary: This unit contains a review question regarding the effectiveness of unhooking hooks to blind security products. It presents multiple-choice options concerning whether such actions bypass detection by removing process introspection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 62 Unit Review Answers Does unhooking hooks truly blind a Security Product? Does unhooking hooks truly blind a Security Product? A Yes, because it will no longer have introspection into that process A Yes, because it will no longer have introspection into that process B Depends, there could be a kernel module still watching B Depends, there could be a kernel module still watching C Only if it's Defender C Only if it's Defender Unit Review Answers Q: Does unhooking hooks truly blind a Security Product? A: Yes, because it will no longer have introspection into that process B: Depends, there could be a kerne

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: InitializeProcThreadAttributeList, UpdateProcThreadAttribute, parent process, process heap, detection avoidance
Summary: The unit describes the implementation of a technique to choose a parent process for a new thread or process, specifically using the InitializeProcThreadAttributeList and UpdateProcThreadAttribute APIs. It explains how these APIs are used to avoid detection by ensuring that suspicious processes (like cmd.exe) are not spawned from unexpected sources like Office applications.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 68 Choose Your Parent Process: Implementation Are you my parent? Are you my parent? Requires just two API calls Requires just two API calls //// make pointer variable PPROC_THREAD_ATTRIBUTE_LIST pAttrList; //// get the buffer size needed InitializeProcThreadAttributeList(...); //// make the real call InitializeProcThreadAttributeList(...); //// update the attribute before creation UpdateProcThreadAttribute(...); Helps avoid detection Helps avoid detection Choose Your Parent Process: Implementation As with any new method, there will be a new set of APIs and/or structures to understand. Everything that is a

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: AV/EDR bypass, detection avoidance, publicly available methods, SEC670
Summary: The unit contains a summary slide from a SANS course regarding techniques for bypassing antivirus (AV) and endpoint detection and response (EDR) systems. It highlights the importance of learning these methods to maintain persistence on target networks.
Excerpt:
Visual caption: A summary slide from a SANS Institute course on bypassing AV/EDR systems. Visible text: Module Summary; Learned bypassing AV/EDR should be a requirement; Discussed how avoiding detection allows you to remain on target longer; Discovered several publicly available methods exist to assist with avoidance; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.9  Key cues: AV detection, sourcing capabilities, minimal access
Summary: The unit describes the trade-offs between full functionality and minimal access in the context of AV detection. It highlights the risks associated with scanning by antivirus software.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Being Scanned' discussing the risks of AV detection and the trade-offs between full functionality and minimal access. Visible text: Being Scanned; All tool capabilities; Bare minimum for access; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: CNG APIs, AES encryption, BC128, BCryptOpenAlgorithmProvider, BCryptGetProperty, BCryptSetProperty, BCryptGenerateSymmetricKey, BCryptDecrypt
Summary: The unit describes the process of using CNG (Cryptography Next Generation) APIs to encrypt and decrypt shellcode. It details a specific sequence of calls, including BCryptOpenAlgorithmProvider, BCryptGetProperty, BCryptSetProperty, BCryptGenerateSymmetricKey, and BCryptDecrypt.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 128 Encrypting/Decrypting Your Shellcode: AES (2) AES Encryption AES Encryption Using CNG APIs Using CNG APIs // make an AES decrypting function void AESDecryptCNG( args go here ) { BCryptOpenAlgorithmProvider(); BCryptGetProperty(); BCryptGetProperty(); BCryptSetProperty(); BCryptGenerateSymmetricKey(); BCryptDecrypt(); } More advanced and extensible More advanced and extensible Encrypting/Decrypting Your Shellcode: AES (2) All of the APIs on the previous slide have all been deprecated, but you can still use them in your code thanks to Microsoft’s tremendous effort for backwards compatibility. It is rare

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: indirect syscall, ntdll.dll, NtAllocateVirtualMemory, call stack, security product evasion
Summary: The unit describes the technique of indirect syscalls to bypass security products by jumping into ntdll.dll's memory space where the syscall instruction is located. It explains that this method improves call stack appearance and can bypass basic inspection of return addresses. The text also notes that finding the correct syscall number remains a requirement.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 35 Indirect Syscalls Shellcode blob jmp cool_edr!NtAllocateVirtualMemory jne ntdll!NtAllocateVirtualMemory+0x15 ret syscall ntdll.dll NtAllocateVirtualMemory mov r10, rcx mov eax, 0x18 jmp ntdll!NtAllocateVirtualMemory+0x10 Indirect Syscalls Hello operator, I would like to make an indirect call to NtAllocateVirtualMemory. Looking at the slide here, you may have noticed that not a lot has changed with our approach. The biggest difference to note here is that we are not going to invoke the syscall instruction inside our malware.exe. Instead, we are going to jump over into ntdll.dll where the syscall instruc

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: Inline Hooking, GetProcAddress API, jump instruction, relative offset calculation, patching
Summary: The unit describes the mechanics of inline hooking, a technique where function bytes are modified to insert a jump instruction for redirection. It outlines a 6-step process involving memory address retrieval via GetProcAddress, saving original bytes, patching with a jump, executing the hook, and restoring the original state. The text focuses on local inline hooking as a foundational skill for developing Windows implants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 40 Inline Hooking Modifies bytes of function Modifies bytes of function Inserts jmp instruction Inserts jmp instruction 1. Obtain memory address of function 2. Read and save 5+ bytes of the function 3. Patch in the jmp 4. Your function executes 5. Clean up patched bytes 6. Execute original function Hook beginning of function Hook mid function Hook end of function Hook beginning of function Hook mid function Hook end of function Inline Hooking Perhaps the easiest way to learn how to implement an inline hook is to do so locally in the target process. External hooking is completely possible, but it is much m

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: unhooking hooks, suspended state, CreateProcess API, Ntdll.dll .text section, EDR/AV evasion
Summary: The text describes a technique for unhooking hooks by creating a process in a suspended state to retrieve an unhooked version of Ntdll.dll's .text section. This method leverages the fact that EDR/AV solutions cannot hook functions during the initial loading phase of a process. The content focuses on how and why this works as a simple and effective way to evade detection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 52 Unhooking Hooks: A Suspended Copy Yet another way to unhook hooks Yet another way to unhook hooks What modules are loaded when you create a process in the suspended state? A debugger can show you that only Ntdll.dll should be implicitly loaded because it is getting ready to load the image into memory. If a process is created in the suspended state, its thread does not execute yet, thus no AV/EDR hooks can be implemented yet. Unhooking Hooks: A Suspended Copy Grabbing the .text section of Ntdll.dll from disk is not the only option. For this one, think back to when we created a process in the suspended s

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: ntdll.text, syscall table, CREATE_SUSPENDED, pattern scanning, overwriting tampered tables
Summary: The text describes a technique for bypassing syscall monitoring by copying the syscall table from a suspended process's ntdll.text section into a hooked process. It explains that since there than no perfect way to find boundaries, pattern scanning is used to locate the syscall table.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 53 A Suspended Copy In memory In memory Ntdll - .text syscall table Call CreateProcess() with CREATE_SUSPENDED Call CreateProcess() with CREATE_SUSPENDED Find the .text section Find the .text section 1 2 Find the syscall table Find the syscall table Copy the table into the hooked process Copy the table into the hooked process Inject your shellcode at will Inject your shellcode at will 3 4 5 A Suspended Copy The process of grabbing the ntdll syscall tables from the suspended process is not very complicated because most of the logic you have seen already. The only new item with this technique is finding the

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: unhooking hooks, blind security product, multiple choice questions
Summary: The unit contains a review question regarding the effectiveness of unhooking hooks to blind security products. It presents multiple-choice options concerning whether such actions bypass detection by removing process introspection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 61 Unit Review Questions Does unhooking hooks truly blind a Security Product? Does unhooking hooks truly blind a Security Product? A Yes, because it will no longer have introspection into that process A Yes, because it will no longer have introspection into that process B Depends, there could be a kernel module still watching B Depends, there could be a kernel module still watching C Only if it's Defender C Only if it's Defender Unit Review Questions Q: Does unhooking hooks truly blind a Security Product? A: Yes, because it will no longer have introspection into that process B: Depends, there could be a k

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: unhooking hooks, blind security product, multiple choice questions
Summary: This unit contains a review question regarding the effectiveness of unhooking hooks to blind security products. It presents three multiple-choice options concerning whether such actions provide complete introspection removal.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 62 Unit Review Answers Does unhooking hooks truly blind a Security Product? Does unhooking hooks truly blind a Security Product? A Yes, because it will no longer have introspection into that process A Yes, because it will no longer have introspection into that process B Depends, there could be a kernel module still watching B Depends, there could be a kernel module still watching C Only if it's Defender C Only if it's Defender Unit Review Answers Q: Does unhooking hooks truly blind a Security Product? A: Yes, because it will no longer have introspection into that process B: Depends, there could be a kerne

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.9  Key cues: parent process, evasion, detection avoidance
Summary: The unit discusses techniques for evading detection by selecting specific parent processes when spawning new processes. It highlights the importance of choosing appropriate parents to avoid security alerts.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Choose Your Parent Process' discussing techniques to evade detection by selecting appropriate parent processes. Visible text: Choose Your Parent Process; What if you could choose your parent process?; One method that can be used as an addition to avoid detection is to choose your parent process. There are certain processes that should never spawn other proces Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: advanced implant features, shellcode execution
Summary: The unit discusses the necessity and trade-offs of developing advanced implant features like shellcode execution, C2 callbacks, and manual memory loading. It emphasizes that complex techniques requiring deep OS knowledge should be used as a last resort when basic methods fail.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Enhancing Your Implant: Shellcode, Evasion, and C2 When you’ve met your match. When facing a tech savvy admin. When stealth is desired. When normal (basic) techniques fail. Manually load an image into memory Re-implement API hooks C2 callbacks Shellcode execution 11 Enhancing Your Implant: Shellcode, Evasion, and C2 Sometimes you will be forced to produce a more advanced tool to get the job done. These should be a last resort option because, depending on what capability you are developing, it can take a while to develop and release. Plus, do you want to spend a few months developing an advanced capability

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NtQuerySystemInventory, SYSTEM_INFORMATION_CLASS, Undocumented Methods
Summary: The unit describes the use of undocumented Native APIs like NtQuerySystemInformation for process enumeration in a red team context. It highlights specific system information classes used to find processes.
Excerpt:
Visual caption: A presentation slide titled 'Undocumented Methods' discussing the use of Native APIs like NtQuerySystemInformation for process enumeration. Visible text: Undocumented Methods; NtQuerySystemInformation; SYSTEM_INFORMATION_CLASS; SECT07 / Red Team_Tools. Developing Windows, Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: open-source, freeware, commercial tools, PE-sieve, Sysinternals, ProcMon, Sysmon
Summary: The unit discusses the landscape of existing tools, categorizing them into open-source, freeware, 100% commercial products, and specific examples like PE-sieve and Sysinternals Suite.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Current State of the Art Tools There are many categories of tools out there: open-source, freeware, and commercial. Profit driven Community driven Huntress Labs PE-sieve 26 Current State of the Art Tools Open-source tools are great and sites like GitHub are full of them. There is nothing wrong with closed-source, commercial tools but when you can see the code like you can on GitHub, you can fork the project and modify it to fit your needs. Granted you will need to check the license the author put on it, but often the license is not that restrictive. Freeware tools are tools that are, well, free! One possi

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE-sieve, malware detection, injected PEs, hooks, dumping implants
Summary: This unit introduces the PE-sieve tool for detecting and analyzing malware on a Windows system. It describes the tool's capabilities, including identifying injected PEs, hooks, and dumping implants from processes.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.1: PE-sieve Observe how a defensive tool can catch injection methods. Observe how a defensive tool can catch injection methods. Please refer to the eWorkbook for the details of this lab. 29 Lab 1.1: PE-sieve PE-sieve, according to hasherezade’s GitHub repo, “is a tool that helps detect malware running on the system, as well as to collect the potentially malicious material for further analysis.” The tool is designed to scan a single process, but it does a great job at detecting various items like injected PEs and hooks. It also has the ability to dump an implant should one be discovered injected into

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE-sieve, malware detection, injected PEs, hooks, implant dumping
Summary: This unit introduces the PE-sieve tool, which is used to detect malware and collect malicious material for analysis. It highlights its capabilities in scanning a single process to identify injected PEs and hooks while also dumping implants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.1: PE-sieve Observe how a defensive tool can catch injection methods. Observe how a defensive tool can catch injection methods. Please refer to the eWorkbook for the details of this lab. 29 Lab 1.1: PE-sieve PE-sieve, according to hasherezade’s GitHub repo, “is a tool that helps detect malware running on the system, as well as to collect the potentially malicious material for further analysis.” The tool is designed to scan a single process, but it does a great job at detecting various items like injected PEs and hooks. It also has the ability to dump an implant should one be discovered injected into

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE-sieve, defensive tools, detection capabilities, Windows implants, Command and Control
Summary: The unit discusses the purpose of learning about defensive tools like PE-sieve to understand how offensive tools are detected. It highlights the security implications of developing Windows implants and command and control infrastructure.
Excerpt:
What’s the Point? The point of the lab was to become familiar with defensive tools that were made to detect the effects our offensive tools. PE-sieve is one of many tools that has this kind of capability. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 30 30 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Registry Watch Dogs, RegNotifyChangeKey, antivirus product installation, situational awareness
Summary: The unit discusses the use of Registry Watch Dogs to monitor for changes in Windows Registry keys. It covers scenarios where implants might monitor for AV installation or self-deletion, and highlights the limitations of RegNotifyChangeKey.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Registry Watch Dogs (1) You can be notified about changes in the Registry. You can be notified about changes in the Registry. Don’t poll too often Don’t poll too often Perhaps it might be necessary for your code to be notified as soon as a change in the Registry happens. Maybe you want to know if an antivirus product was just installed after your implant was dropped. There could be several reasons you determine. Choose your trigger Choose your trigger 153 Registry Watch Dogs (1) At times, it might serve your program well to be notified when certain changes happen in the Registry. As mentioned earlier, thi

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_SECURITY, REG_NOTIFY_THREAD_AGNOSTIC
Summary: The text describes various REG_NOTIFY_CHANGE_* filters used to monitor registry key changes, including name, attributes, security descriptors, and value modifications. It also explains the REG_NOTIFY_THREAD_AGNOSTIC flag for ensuring notification persistence across different threads.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Registry Watch Dogs (3) There are several REG_NOTIFY_CHANGE_* filters that could trigger a change to be reported. There are several REG_NOTIFY_CHANGE_* filters that could trigger a change to be reported. NAME NAME Notifies caller if subkey is created or deleted ATTRIBUTES ATTRIBUTES LAST_SET LAST_SET Notifies caller if attributes change Notifies caller of value changes. Includes creating, deleting, modifying. SECURITY SECURITY Notifies caller if security descriptor changes Thread agnostic Thread agnostic Notification is not tied to the calling thread 155 Registry Watch Dogs (3) REG_NOTIFY_CHANGE_NAME if s

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process injection, userland process, execution of shellcode, detection avoidance, summary of definitions
Summary: The unit defines process injection as a method of forcing code from one userland process into another to execute arbitrary code. It discusses the motivations for using injection, specifically focusing on avoiding detection by leveraging legitimate processes. The text distinguishes between true process injection and other pre-execution techniques like DLL hijacking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 Process Injection What exactly is process injection and what are some reasons for injecting into a process? Forcefully making a process execute arbitrary code Avoid detection by having a legit process execute your shellcode Process Injection Depending on what blog post you read or what YouTube video you watch, you might get a different definition of what process injection is. For this course, we define process injection as a method of forcing code from one userland process, say malware, into another userland process to execute arbitrary code. We will discuss other techniques that are not true to that d

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: fileless malware, static detection bypass, memory scanning, security software limitations
Summary: The text discusses the advantages of fileless malware, specifically focusing on how not being present on disk avoids static analysis and detection by AV/EDR solutions. It highlights that while EDRs have improved behavior detection, it remains difficult to scan all memory regions constantly due to resource constraints.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 8 Advantages It sure is great to not be on disk. It sure is great to not be on disk. No files to be analyzed No files to be analyzed Bypass static detection Bypass static detection Since files are not dropped to disk, there is nothing for an analyst to retrieve. Files on disk are prone to static analysis before execution. By not being on disk, there is no risk of static detection. Advantages The biggest advantage for fileless malware is the fact that nothing is dropped to disk. The fact that certain programs, system files, tools, etc. cannot be blocked by IT staff without hindering support keeps enabling 

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: fileless malware, bypass static detection, not on disk
Summary: The unit describes the advantages of fileless malware techniques, specifically focusing on how they bypass static analysis. It highlights that not being present on disk allows for easier evasion.
Excerpt:
Visual caption: A slide from a presentation about fileless malware techniques, highlighting the advantages of not being on disk. Visible text: Advantages; It sure is great to not be on disk.; No files to be analyzed; Bypass static detection; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: fileless malware, static detection bypass, memory scanning, behavior detection
Summary: The text discusses the advantages of fileless malware techniques, specifically focusing on how staying off-disk avoids static analysis by AV/EDR solutions. It highlights that because no files are dropped to disk, there is nothing for analysts or forensic tools to scan or hash.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 8 Advantages It sure is great to not be on disk. It sure is great to not be on disk. No files to be analyzed No files to be analyzed Bypass static detection Bypass static detection Since files are not dropped to disk, there is nothing for an analyst to retrieve. Files on disk are prone to static analysis before execution. By not being on disk, there is no risk of static detection. Advantages The biggest advantage for fileless malware is the fact that nothing is dropped to disk. The fact that certain programs, system files, tools, etc. cannot be blocked by IT staff without hindering support keeps enabling 

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: memory forensics, Volatility
Summary: The unit discusses memory forensics tools such as Volatility, PE-sieve, and Moneta for detecting implants and injection methods. It highlights the limitations of security products in scanning all memory regions due to performance constraints. The text emphasizes that while being in memory is not a guarantee of safety from detection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 11 Memory Forensics Being in memory is not a get out of jail free card. Being in memory is not a get out of jail free card. Volatility Volatility From the Volatility Foundation, ingests memory dumps with numerous plug-ins PE-sieve PE-sieve From Hasherzade, scans a process and can dump implants detecting all kinds of injection methods Moneta Moneta From forrest-orr, user-mode Windows memory analysis tool, similar to PE- sieve Memory Forensics Almost everything you do on a Windows system can be logged by something. Even if a certain Windows tool does not catch your activity, highly motivated memory analysts

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: System32 folder, blending in, file naming conventions, timestamp matching
Summary: The text discusses techniques for blending in with existing files on a Windows system, specifically within the System32 folder. It highlights strategies such as choosing a location with many items to avoid detection and selecting filenames that match the surrounding file naming conventions and timestamps.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 16 Blending In On this Windows 10 VM, there are over 4,200 items in the System32 folder. Plenty of options to blend in with files around you. Blending In When it comes to blending in, it can be somewhat easy with the proper level of permissions. As one possible example, a prime spot could be the System32 folder where there are well over 4,200 items to surround yourself. You would not necessarily want to be the first or the last entry in the folder but pick a spot that would require the user to scroll down for quite some time. Users are notorious for scrolling right past something unless they are specifica

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: System32 folder, blending in, blending-in tactics, filename selection, timestamp alignment
Summary: The unit discusses techniques for blending in with existing files on a Windows system to avoid detection. It covers selecting appropriate locations like System32, choosing filenames that match surrounding entries, and aligning timestamps with local files.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 16 Blending In On this Windows 10 VM, there are over 4,200 items in the System32 folder. Plenty of options to blend in with files around you. Blending In When it comes to blending in, it can be somewhat easy with the proper level of permissions. As one possible example, a prime spot could be the System32 folder where there are well over 4,200 items to surround yourself. You would not necessarily want to be the first or the last entry in the folder but pick a spot that would require the user to scroll down for quite some time. Users are notorious for scrolling right past something unless they are specifica

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: antivirus detection, cloud-based analysis, feature discovery, custom implant risk
Summary: The text discusses the risks and implications of being detected by antivirus (AV) solutions when deploying custom-made implants. It highlights considerations regarding cloud-based analysis engines and the fact that common system files are often pre-cleared, while unique binaries may be flagged.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 17 Being Scanned If you get scanned, what will they find out? If you get scanned, what will they find out? All tool capabilities All tool capabilities Bare minimum for access Bare minimum for access Will you lose months or years of effort if your binary gets picked up by an AV solution? Or will the functionality required to maintain access across reboots be the only thing discovered? Being Scanned Another risk you must consider is should there be some AV solution installed like Defender, will that deter you from dropping to disk? If not, are you okay with it possibly being scanned? Some AV solutions requi

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AV detection, trade-offs, full functionality vs minimum access
Summary: The unit describes the trade-offs between full functionality and minimal detection risk in malware tools. It highlights the user's choice between having a robust tool with high visibility or a minimal tool for stealthier access.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Being Scanned' discussing the risks of AV detection and the trade-offs between full functionality and minimal access. Visible text: Being Scanned; All tool capabilities; Bare minimum for access; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: antivirus scanning, implant detection, 100% unique binary, cloud-based analysis, trade secrets
Summary: The text discusses the risks and implications of being scanned by antivirus (AV) solutions when deploying custom-made implants. It highlights considerations regarding what information might be revealed to AV vendors during cloud analysis, and the potential impact on trade secrets or operational security.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 17 Being Scanned If you get scanned, what will they find out? If you get scanned, what will they find out? All tool capabilities All tool capabilities Bare minimum for access Bare minimum for access Will you lose months or years of effort if your binary gets picked up by an AV solution? Or will the functionality required to maintain access across reboots be the only thing discovered? Being Scanned Another risk you must consider is should there be some AV solution installed like Defender, will that deter you from dropping to disk? If not, are you okay with it possibly being scanned? Some AV solutions requi

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DRM, Themida, Skrull, anti-copy, process ghosting
Summary: The unit discusses techniques for protecting implants from analysis and detection by reverse engineers and security software. It highlights commercial tools like Themida for code block protection and the Skrull malware DRM which utilizes process ghosting to prevent automatic sample submission.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 18 Protecting Yourself What can you do to protect your implant? What can you do to protect your implant? You could get extremely creative and DRM your implant like the PoC Skrull did. According to the author, the malware launchers are anti-copy and are thus broken if, and when, they are submitted for analysis. Protecting Yourself There are several public techniques and tools that are out there today that aid your efforts to protect yourself. There are commercial tools like packers and encryptors that do a tremendous job annoying reverse engineers. One such tool is Themida, which is made by the company Ore

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DRM for malware, Themida, Skrull, Process Ghosting, anti-copy launchers
Summary: The unit discusses techniques for protecting implants from analysis and detection by reverse engineers and security software. It mentions specific tools like Themida for code block protection and Skrull, which uses process ghosting to prevent automatic sample submission.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 18 Protecting Yourself What can you do to protect your implant? What can you do to protect your implant? You could get extremely creative and DRM your implant like the PoC Skrull did. According to the author, the malware launchers are anti-copy and are thus broken if, and when, they are submitted for analysis. Protecting Yourself There are several public techniques and tools that are out there today that aid your efforts to protect yourself. There are commercial tools like packers and encryptors that do a tremendous job annoying reverse engineers. One such tool is Themida, which is made by the company Ore

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: binary patching, NTDLL modification, system stability, memory vs disk patching, AV/EDR behavior
Summary: The unit describes the concept of building binary patches to modify how a program's execution flow is altered. It discusses the risks and consequences of patching system files like NTDLL, highlighting potential instability and detection. It also mentions that AV/EDR solutions use memory patching for function hooking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 22 What Is Binary Patching? Modifying binaries to achieve results Modifying binaries to achieve results What would happen if you patch a system file like NTDLL where it sits in System32? Your hooks would be implemented all over the place and it could draw way too much attention to you. Instead, you could patch a secondary or tertiary DLL that NTDLL loads. What Is Binary Patching? Binary patching is often referred to as modifying a binary as it resides on disk or in memory with the intention of changing how it executes. In memory patching is often done by AV/EDR solutions to change how functions of interes
