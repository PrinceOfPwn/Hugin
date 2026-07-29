# Atlas Material — edr-evasion (part 5)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: evasion
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: IAT Hooking, Inline Hooking, user mode, security software, game hacking
Summary: The text introduces the concept of hooking functions, specifically focusing on IAT and inline hooking methods in user mode. It discusses various use cases for hooking, such as debugging, reverse engineering, and antivirus development, while noting its prevalence in game hacking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 36 Hooking Functions Various types of hooking at our disposal Various types of hooking at our disposal IAT Hooking IAT Hooking Inline Hooking Inline Hooking IAT stores addresses of imported functions that we can possibly overwrite Modifies first six bytes of function to jump to controlled location. Detours, EasyHook. Hooking Functions Before jumping into restoring hooks, we need to discuss the two most used hooking methods out there: IAT and inline hooking. There could be several reasons why someone might want to hook, or intercept function calls. Perhaps a developer wants to verify their API is working a

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: IAT Hooking, Inline Hooking, Hooking Functions
Summary: The unit describes a comparison between IAT Hooking and Inline Hooking techniques for function hooking.
Excerpt:
Visual caption: A presentation slide titled 'Hooking Functions' comparing IAT Hooking and Inline Hooking. Visible text: Hooking Functions; IAT Hooking; Inline Hooking; SANS SEC-701 Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unhooking Hooks, NtMapViewOfSection, security product monitoring, reconnaissance on hooked APIs
Summary: The text discusses the rationale and risks associated with unhooking functions in a red teaming context. It explains how security products and nation-states may use hooks to monitor or modify behavior, and describes the method of restoring original function functionality.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 37 Unhooking Hooks: Why? Restore intended use of a function Restore intended use of a function Hooks are, by design, implemented to change the behavior of a function. If we are trying to clean up and restore items of interest, it would be a good idea to also restore the original, intended use of a function like NtMapViewOfSection. Unhooking Hooks: Why? Perhaps a better question is who else out there might be hooking functions besides us? As mentioned previously, nation states and security products could be a solid bet. Security products might not be changing the behavior of a function but instead, looking

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unhooking Hooks, Restore intended use, security research
Summary: The unit discusses the rationale for unhooking hooks in security research. It explains that hooks are designed to change function behavior and restoring original functionality is necessary when cleaning up an area of interest.
Excerpt:
Visual caption: A presentation slide titled 'Unhooking Hooks: Why?' discussing the rationale for restoring original function behavior in security research. Visible text: Unhooking Hooks: Why?; Restore intended use of a function; Hooks are, by design, implemented to change the behavior of a function. If we are trying to clean up an area of interest, it would be a good idea to also restor; SANS SEC407: Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unhooking Hooks, tldns.org, VLD_version.Systs, replace patched bytes
Summary: The unit describes a methodology for identifying and restoring original function bytes to bypass hooks in Windows environments. It covers search criteria, validation data like VLD_version.Systs, and the process of replacing patched bytes.
Excerpt:
Visual caption: A presentation slide titled 'Unhooking Hooks: The Search' outlining the methodology for identifying and restoring original function bytes. Visible text: Unhooking Hooks: The Search; Search criteria; tldns.org; Validation data; VLD_version.Systs; Implementation; Replace the patched bytes with original bytes or with your own patch (hook). Alt/source label:

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: unhooking, Ntdll.dll, function hooking, memory vs disk comparison, AV evasion
Summary: The unit describes techniques for identifying and unhooking hooks in Windows system DLLs, specifically Ntdll.dll. It details a method of scanning function headers to detect jumps or unexpected bytes, comparing memory contents against the disk version of the DLL to validate findings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 38 Unhooking Hooks: The Search Cannot unhook what you cannot find Cannot unhook what you cannot find Search criteria Search criteria Searching for bytes that should not be there. Function bytes should start with MOV EDI, EDI. Validation data Validation data Implementation Implementation Arguably best place to validate bytes is the version on disk, C:\Windows\Syst em32\Ntdll.dll Replace the patched bytes with original bytes or with your own patch (hook). Unhooking Hooks: The Search As discussed on the previous slide, you could come across functions that have already been hooked. You have a few options at t

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: IAT Hooking, Function pointer hooking, DataDirectory, VirtualProtect API, Kernel32.dll, Ntdll.dll, PAGE_READWRITE
Summary: This unit describes the process of IAT (Import Address Table) hooking, which involves identifying and overwriting function pointers in a PE header structure. It details the technical steps for locating modules like Kernel32.dll or Ntdll.dll and modifying page protections using VirtualProtect to allow writing to read-only memory.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 IAT Hooking An array of addresses An array of addresses AKA: Function pointer hooking AKA: Function pointer hooking 1. Parse PE headers to find import table 2. Locate module that implements the hooked function 3. Locate the function in the found module 4. Change page protections to PAGE_READWRITE, save old permissions 5. Overwrite function pointer 6. Restore previous page protections IAT is typically read-only Must make it writeable IAT is typically read-only Must make it writeable IAT Hooking If you recall from the PE header module, the IAT is one of 16 entries in the array named DataDirectory. The ta

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: inline hooking, jmp instruction, memory address, patching
Summary: The unit describes the inline hooking technique used to intercept functions. It details steps such as modifying function bytes, inserting jump instructions, and managing memory addresses for redirection.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the concept and steps of inline hooking. Visible text: Inline Hooking; Modifies bytes of function; Inserts jmp instruction; Hook beginning of function; Hook mid function; Hook end of function; Obtain memory address of function; Read and save 5+ bytes of the function; Patch in the jump; Your function executes; Clean up patched bytes; Execute original function; SANS SEC679 | Red-Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Heaven's Gate, Hell's Gate, Halo's Gate, syscall stub, position independent, Wow64 application
Summary: The unit discusses three types of syscall gates: Heaven's Gate, Hell's Gate, and Halo's Gate. It explains how these techniques are used to bypass hooks by invoking system calls directly or dynamically identifying syscall numbers. Each gate provides a different level of evasion for 64-bit code execution.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 41 Meet the Gates The gatekeepers to kernel mode The gatekeepers to kernel mode Heaven’s gate Heaven’s gate Hell’s gate Hell’s gate The gate that enables Wow64 application to jump back to 64-bit code Dynamically finds and executes syscalls while being position independent Halo’s gate Halo’s gate Determines the syscall ID of the hooked version by looking at its neighbors Meet the Gates The general idea with these gates is to evade your intentions by not making direct Nt* API calls, but instead, invoking the system call yourself. This can be done by creating your own syscall stub, identifying the proper sys

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Meet the Gates, system calls, evading detection, Heaven's gate, Hell's gate, Halo's gate
Summary: The unit describes three specific techniques (Heaven's Gate, Hell's Gate, Hell's Gate, and Halo's Gate) for evading detection by directly invoking system calls. It focuses on these methods as ways to bypass security measures when transitioning to kernel mode.
Excerpt:
Visual caption: A presentation slide titled 'Meet the Gates' describing three different methods for evading detection by directly invoking system calls. Visible text: Meet the Gates; Heaven's gate; Hell's gate; Halo's gate; The gatekeepers to kernel mode Alt/source label:

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Hell's Gate, dynamically locate, syscalls, position independent, Ntdll.dll
Summary: This unit describes the Hell's Gate technique for dynamically locating and invoking syscalls to bypass security monitoring. It highlights that it does not rely on static syscall IDs and is position-independent. The text includes code snippets and references to research by j00ru, RtlMateusz, and am0nsec.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 42 Hell’s Gate Dynamically locate and invoke syscalls Dynamically locate and invoke syscalls Completely position independent Completely position independent PPEB pPeb = (PPEB)__readgsqword(0x60); //// hardcoded 2nd entry (pPeb‐> \ LoaderData‐> \ InMemoryOrderModuleList.Flink‐>Flink \ ‐ 0x10) //// check opcodes if ((*(PBYTE)TargetFunction + 3) == 0xB8) { // more opcode checks } Relies on Ntdll.dll Relies on Ntdll.dll Hell’s Gate Hell’s gate is impressive because it does not rely on static syscall IDs. Be very cautious about hard coding values in your tools. The syscall IDs can change with any update and ar

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Halo's Gate, direct syscalls, Ntdll.dll hooks, syscall ID search, neighboring addresses
Summary: The text describes 'Halo's Gate', a technique for using direct syscalls to bypass EDR hooks in Ntdll.dll. It explains how the method addresses the limitations of Hell's Gate by searching neighboring syscall IDs when a function is hooked. It also mentions that this approach allows for executing syscalls without repairing the hook, thus evading detection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 43 Halo’s Gate Find your neighbor, find yourself Find your neighbor, find yourself 0 1 2 3 SSN Halo’s Gate Halo’s gate offers a refreshing twist on using direct syscalls. The downside to Hell’s gate is that it does not account for the possibility that the function in Ntdll.dll is already hooked. Should the function be hooked, then Hell’s gate will fail. Where Halo’s gate helps with this is taking advantage of the fact that the syscall IDs in Ntdll.dll are in numerical order. So, you will not find syscall 4F first. 4F will come immediately after 4E, and so on. Knowing this, if a function is already hooked,

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Halo's Gate, syscall IDs, off_hooked, Renorth's blog
Summary: The unit describes a technique called 'Halo's Gate' for bypassing security checks by identifying syscall ID locations. It references a specific blog post and provides a snippet of code or configuration related to finding neighbor syscalls.
Excerpt:
Visual caption: A screenshot of a blog post or technical article titled 'Halo's Gate', describing a technique for bypassing security checks by identifying the location of syscall IDs. Visible text: Halo's Gate; Find your neighbor. find your self.; 0 .off_hooked(syscall); 1 .off_hooked(near_syscall); 2 .off_hooked(near_syscall); 3 .off_hooked(near_syscall); Halo's Gate; Check out Renorth's blog where he did an awesome job documenting everything. Alt/source label:

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Heaven's Gate, Wow64, 32-bit to 64-bit transition, system calls
Summary: The unit describes the 'Heaven's Gate' mechanism in Windows, specifically how 32-bit processes on 64-bit systems transition to 64-bit code for system calls. It explains the role of Wow64 in facilitating this process.
Excerpt:
Visual caption: A slide from a training course titled 'Heaven's Gate', explaining the transition between 32-bit and 64-bit code in Windows. Visible text: Heaven's Gate; Hooking Wow64 and the gate to 64-bit code; 32-bit processes on 64-bit systems have an interesting method when it comes to making syscalls. Thanks to Wow64, on Windows 64, this is all made possible. The t; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Heaven's Gate, Wow64, ntdll.dll, syscall transition, 32-bit to 64-bit
Summary: The text discusses the 'Heaven's Gate' mechanism where 32-bit processes on 64-bit Windows systems transition to 64-bit code for system calls. It explains how ntdll.dll is loaded in both 32-bit and 64-bit address spaces and describes the limitations of hooking Wow64 functions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 44 Heaven’s Gate Hooking Wow64 and the gate to 64-bit code Hooking Wow64 and the gate to 64-bit code 32-bit processes on 64-bit systems have an interesting method when it comes to making syscalls. Thanks to Windows 32 on Windows 64, this is all made possible. The transition from 32-bit code to 64-bit code has been dubbed Heaven’s Gate. Heaven’s Gate There might come a time when you need to implement some hooks in a 32-bit application, or more technically speaking, a Wow64 application. Ntdll.dll implements the logic for the system loader and thus is responsible for initializing the user mode portion of the

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Heaven's Gate, ntdll.dll, wow64cpu.dll, 32-bit to 64-bit transition, syscall execution
Summary: The text describes the 'Heaven's Gate' mechanism in Windows, which allows 32-bit applications to execute syscalls on a 64-bit system via transitions through ntdll.dll and wow64cpu.dll. It details the specific jump sequence from 32-bit mode to 64-bit mode required for these operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 45 Heaven’s Gate: The Transition With just a few jumps, 32-bit code can get back to 64-bit code. With just a few jumps, 32-bit code can get back to 64-bit code. mov eax, INT mov edx, ntdll+offset call edx ret nop x86 program x86 program jmp ntdll.Wow64Transition ntdll+offset ntdll+offset jmp 033:wow64cpu+offset jmp qword ptr [offset] wow64cpu.dll wow64cpu.dll 1 2 3 mov r10, rcx mov eax, INT test byte ptr [], 01 jne ntdll._offset syscall ret int 2e ntdll.dll ntdll.dll 4 Heaven’s Gate: The Transition Because Windows takes pride in their ability to retain backwards compatibility, 32-bit applications can stil

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Heaven's 100% Gate, ntdll.dll offset, 32-bit to 64-100% bit transition
Summary: The unit describes the mechanism of 'Heaven's Gate' where 32-bit code transitions to 64-bit mode in Windows. It specifically mentions ntdll.dll offsets and the transition process.
Excerpt:
Visual caption: A presentation slide titled 'Heaven's Gate: The Transition' explaining how 32-bit code can transition to 64-bit mode in Windows. Visible text: Heaven's Gate: The Transition; x86 program; ntdll.dll - offset; ntdll.dll; SEC/701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unhooking Hooks, 32-Bit Example, Wow64, assembly language, jmp +0x32
Summary: The unit describes a 32-bit assembly comparison between non-hooked and hooked functions to demonstrate how hooks are identified. It specifically highlights the difference in jump instructions for Wow64 environments.
Excerpt:
Visual caption: A slide titled 'Unhooking Hooks: 32-Bit Example' showing a comparison between non-hooked and hooked functions in assembly language. Visible text: Unhooking Hooks: 32-Bit Example; What a prolog hook might look like for 32-bit (Wow64); Non-hooked function; Hooked function; jmp +0x32; jmp 0xF8 (-5); SEC_70 | Red Team Tooling. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: 32-bit Wow64, prolog hook, MOV EDI, EDI, hot patches, short JMP
Summary: The text describes the mechanics of 32-bit (Wow64) function prologues and how they are used for hooking. It explains that MOV EDI, EDI instructions serve as 2-byte NOPs that can be replaced with short jumps to bypass hooks.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 46 Unhooking Hooks: 32-Bit Example What a prolog hook might look like for 32-bit (Wow64) What a prolog hook might look like for 32-bit (Wow64) Non-hooked function Non-hooked function Hooked function Hooked function nop nop nop nop nop mov edi, edi push ebp mov ebp, esp jmp rel32 E9 xx xx xx xx jmp 0xFB (‐5) EB F9 Unhooking Hooks: 32-Bit Example 32-bit functions are very interesting because they typically begin with several NOP instructions, or no operations. If you are not familiar with the NOP instruction, then do not worry because it literally does nothing but waste one CPU cycle. It has no effect on re

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: 64-bit inline hook, MOV, JMP RAX, instruction length, absolute address
Summary: The unit describes the mechanics of 64-bit inline hooks and how they differ from 32-bit versions due to instruction length and addressing limitations. It specifically details a technique using MOV followed by JMP RAX to bypass absolute address constraints in 64-bit environments.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 47 Unhooking Hooks: 64-Bit Example What a prolog hook might look like for 64-bit What a prolog hook might look like for 64-bit Non-hooked function Non-hooked function Hooked function Hooked function mov r10, rcx mov eax, 41 .... mov rax, 1122334455667788 jmp rax nop nop nop Unhooking Hooks: 64-Bit Example Just like the previous slide that covered 32-bit inline hook, we have a visualization for a 64-bit inline hook. Even though there is no typical prolog like what you might normally see for x86, the JMP instruction is used in a similar fashion. The JMP instruction is quite interesting for both 32-bit and 6

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: assembly, unhooking hooks, 64-bit example, prologue hook
Summary: The unit contains an assembly language comparison between non-hooked and hooked functions in a 64-bit environment. It illustrates what a typical prologue hook looks like for 64-bit code.
Excerpt:
Visual caption: A slide titled 'Unhooking Hooks: 46-Bit Example' showing a comparison between non-hooked and hooked functions in assembly language. Visible text: Unhooking Hooks: 46-Bit Example; Non-hooked function; Hooked function; What a prolog hook might look like for 46-bit; SANS SEC70 Alt/source label:

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Trampolines, hooked functions, NtQuerySystemInformation, loop prevention
Summary: The unit describes the concept of trampolines as jump points used to navigate out of hooked functions. It specifically addresses how they prevent infinite loops when executing code after a hook.
Excerpt:
Visual caption: A slide titled 'Trampolines' explains the concept of jump points in hooked functions to avoid infinite loops. Visible text: Trampolines; What happens after your hooked function executes?; Hooked NtQuerySystemInformation; Could get stuck in a loop; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Trampoline Steps, Original func, Hook func, Trampoline
Summary: The unit describes the flow of execution between an original function and a hook function using a trampoline mechanism. It illustrates how shellcode evasion techniques are enhanced through this specific architectural method.
Excerpt:
Visual caption: A slide titled 'Trampoline Steps' illustrating the flow of execution between an original function and a hook function using a trampoline. Visible text: Trampoline Steps; Original func; content; Hook func; Trampoline; SEC.703 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unhooking Hooks, C:\Windows\System32, restoring original function, copying from disk
Summary: The unit describes a method for unhooking hooks by restoring original function functionality by copying data from system libraries on disk. It specifically mentions using files in C:\Windows\System32 as a source for integrity checks.
Excerpt:
Visual caption: A presentation slide titled 'Unhooking Hooks: A Fresh Copy' discussing methods for restoring original function functionality by copying from disk. Visible text: Unhooking Hooks: A Fresh Copy; There is another way to unhook hooks.; The system libraries that are stored in C:\Windows\System32 can serve as a validation for your integrity checks, instead of copying the first several bytes from Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: unhooking hooks, Ntdll.dll, C:\Windows\System32, TEXT section, fresh copy
Summary: The text describes a technique for unhooking hooks by replacing the in-memory version of system libraries, such as Ntdll.dll, with a intended copy from disk. This 'fresh copy' method involves reading the entire TEXT section of a library from the C:\Windows\System32 folder to restore original functionality. The text also notes that while detections for this specific action exist but are unlikely common, an attacker could potentially patch on-disk files.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 50 Unhooking Hooks: A Fresh Copy There is another way to unhook hooks. There is another way to unhook hooks. The system libraries that are stored in C:\Windows\System32 can serve as a validation for your integrity checks, but instead of copying the first several bytes from disk to memory, just copy in the entire TEXT section. Unhooking Hooks: A Fresh Copy When it comes to unhooking a function, there are several methods we can implement. One method is to use the original version of the function as found in the DLL on disk. This method has been dubbed “a fresh copy” where a clean copy of a system library fo

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: NTDLL.dll, CreateFileA, CreateFileMapping, MapViewOfFile, .text section, file mapping
Summary: The text describes a technique for restoring a fresh copy of NTDLL.dll on disk using file mapping APIs like CreateFileA, CreateFileMapping, and MapViewOfFile. It outlines the step-by-step process of obtaining a handle to the DLL, creating a mapping object, and copying the .text section from the disk version to memory.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 A Fresh Copy Visualization On disk On disk In memory In memory Ntdll.dll Ntdll.dll .text .text 1. CreateFileA(ntdll.dll, ...) 2. CreateFileMapping(hNtdll, ...) 3. MapViewOfFile(hNtdllMapping, ...) 4. Find NtHeader 5. Find .text section 6. memcpy() section over A Fresh Copy Visualization Perhaps the best way to copy over a fresh copy of NTDLL on disk is to create a file mapping. The process is not complicated at all once you become familiar with the few APIs involved. The first action to execute is to obtain a module handle to the DLL using the CreateFile API, which will return a handle to us. From the 

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Unhooking Hooks, Suspended Copy, SEC701, Red Teaming Tools
Summary: The unit describes a technique for bypassing security hooks by using a suspended copy of the process. This is part of a course on developing custom tools for Windows implants, shellcode, and C2.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Unhooking Hooks: A Suspended Copy' discussing techniques for bypassing security hooks. Visible text: Unhooking Hooks: A Suspended Copy; Yet another way to unhook hooks; SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: CreateProcess() with CREATE_SUSPENDED, syscall table, NtDll - text, hooked process
Summary: The unit describes a technique for obtaining syscall tables from suspended processes to facilitate shellcode execution. It details steps such as creating a process in a suspended state, locating the text section, and copying the syscall table into a hooked process.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'A Suspended Copy' describing the process of obtaining syscall tables from suspended processes. Visible text: A Suspended Copy; Call CreateProcess() with CREATE_SUSPENDED; Find the text section; Find the syscall table; Copy the table into the hooked process; Inject your shellcode at will; In memory; NtDll - text; syscall table; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: UnhookTheHook, Bitdefender, eWorkbook
Summary: The text describes Lab 5.2, titled 'UnhookTheHook', which focuses on testing unhooking skills against antivirus software like Bitdefender. It directs students to the eWorkbook for specific lab details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 55 Lab 5.2: UnhookTheHook Test your unhooking skills against Bitdefender and others. Test your unhooking skills against Bitdefender and others. Please refer to the eWorkbook for the details of the lab. Lab 5.2: UnhookTheHook Please refer to the eWorkbook for the details of this lab. 55 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: user mode hooks, clearing hooks, security tools, implants
Summary: The unit describes a presentation slide titled 'What's the Point?' which explains techniques for clearing user-mode hooks. It is part of a module on developing Windows implants, shellcode, and C2.
Excerpt:
Visual caption: A presentation slide titled 'What's the Point?' explaining a method for clearing user mode hooks. Visible text: What's the Point?; SEC701: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: user mode hooks, EDR DLL, kernel mode, SEC770
Summary: The text describes a lab exercise focused on identifying and clearing user-mode hooks implemented by EDR DLLs. It notes that kernel-mode EDR components will be covered in subsequent courses.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 56 What’s the Point? What’s the point? 56 What’s the Point? The point of this lab was to explore one of several methods of clearing out user mode hooks that an EDR’s DLL might implement. The kernel mode side of an EDR will be discussed in follow-on courses like SEC770. 56 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Syswhispers3, WoW64, EGGs, direct syscall jumps, ssyscalls, MASM support, assembly files
Summary: The unit discusses the Syswhispers3 tool for generating header, source, and assembly files to facilitate syscall execution in Windows environments. It covers techniques like egg-hunting and direct syscall jumps to bypass detection. The text also provides specific instructions on configuring Visual Studio project settings for MASM support.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 57 More Techniques Never just one way to do a thing Never just one way to do a thing Syswhispers3: WoW64, EGGs, direct syscall jumps in both WoW64 and x64, direct syscall jumps to random syscalls Syswhispers1, 2, 3 Syswhispers1, 2, 3 py syswhispers.py --preset common -o syscalls_common -m egg_hunter More Techniques As with all things programming, there is never just one single way to get something done. Some methods might seem similar when you look at the source code, but they can still produce a different signature. The beauty of programming! The same thing goes for how we invoke syscalls, how we find th

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Sywshipers, system call detection bypass, WoW4, EGGs, direct syscall jumps
Summary: The unit describes the Sywshipers tool used for bypassing system call detection. It highlights specific techniques such as WoW4, EGGs, and direct syscall jumps in both WoW4 and x64 architectures.
Excerpt:
Visual caption: A slide titled 'More Techniques' describing the Sywshipers tool for bypassing system call detection. Visible text: More Techniques; Sywshipers1, 2, 3; Sywshipers3: WoW4, EGGs, direct syscall jumps in both WoW4 and x64, direct syscall jumps to random syscalls Alt/source label:

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: unhook hooks, AV solutions, call order of APIs, suspicious activity
Summary: The unit discusses the rationale and techniques for unhooking functions that have been hooked by security software or other malware. It covers why AV solutions hook common APIs and how they monitor call orders to detect suspicious activity.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 58 Module Summary Discussed why we would unhook hooks Discussed why we would unhook hooks Found hooked functions Found hooked functions Explored various ways to unhook hooks Explored various ways to unhook hooks Implemented your own hooks Implemented your own hooks Module Summary In this module, we discussed several reasons as to why you might want to unhook functions that were already being hooked by something else or someone else’s malware. Many AV solutions will also hook functions that they think are commonly used in malware. They will also pay attention to the call order of APIs because that could be

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: unhooking, hooked functions, custom hooks, SEC679
Summary: The unit describes a summary slide for a module on unhooking hooks in red teaming tools. It covers the reasons for unhooking, identifying hooked functions, and exploring various methods to implement custom hooks.
Excerpt:
Visual caption: A summary slide for a module on unhooking hooks in the context of red teaming tools. Visible text: Module Summary; Discussed why we would unhook hooks; Found hooked functions; Explored various ways to unhook hooks; Implemented your own hooks; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: unhooking hooks, security product, evasion
Summary: The unit contains a review question and answer regarding the effectiveness of unhooking hooks to blind security products. It discusses whether this action removes all visibility for security software.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a unit review question about unhooking hooks and security products. Visible text: Unit Review Answers; Does unhooking hooks truly blind a Security Product?; Yes, because it will no longer have introspection into that process; Depends, there could be a kernel module still watching; Only if it's Defender Alt/source label:

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: detection avoidance, red team tactics, module objectives
Summary: The unit outlines the learning objectives for a module on avoiding detection during red teaming operations. It covers reasons for evasion, various implementation methods, and an analysis of the pros and cons of each method.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 64 Objectives Our objectives for this module are: Discuss reasons to avoid detection Explore various methods to avoid detection Discuss the good and the bad Objectives The objectives for this module are to discuss some of the reasons why you would want to avoid detection, explore some of the various implementations that have been created to assist you in avoiding detection, and discuss the good and the bad of some of those methods. 64 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: AV/EDR evasion, function hooking, unhooking, red team operations
Summary: The text discusses the importance of avoiding detection by AV and EDR solutions during a red team engagement. It introduces the concept that while no single bypass exists for all products, specific techniques like unhooking and other methods to counter function hooking are necessary.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 65 Why Avoid Detection? Why would you want to be detected? Unless you are intentionally trying to test an AV solution, you want to remain undetected for as long as possible. To do that, you must find a method that enables you to bypass whatever solution is being used on the target. AV/EDR solutions can give away your presence. AV/EDR solutions can give away your presence. Why Avoid Detection? Nobody wants to be detected immediately after gaining access to the target system, unless that is your goal. Perhaps though, you have several levels of avoidance you want to implement against your blue team so they c

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Why Avoid Detection?, AV/EDR solutions, SEC701
Summary: The unit contains a slide discussing the importance of avoiding detection by antivirus (AV) and endpoint detection and response (EDR) systems. It highlights how these solutions can reveal an attacker's presence during operations.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Why Avoid Detection?' discussing AV/EDR solutions. Visible text: Why Avoid Detection?; AV/EDR solutions can give away your presence.; SEC701 | Red-Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Detection Engines, Static, Dynamic, Scan, signature matching, virtualized container
Summary: The unit describes the components of antivirus detection engines, specifically highlighting static, dynamic, and scan engines. It details how these engines use signature matching and virtualized containers for sample execution.
Excerpt:
Visual caption: A slide titled 'Detection Engines' describes the components of an antivirus solution, including static, dynamic, and scan engines. Visible text: Detection Engines; Static; Dynamic; Scan; Signature matching engine; Executing samples in a virtualized container; Some AVs offer a scanning engine Alt/source label:
