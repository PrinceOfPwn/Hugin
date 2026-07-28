# Atlas Material — binary-analysis (part 5)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: binary patching, NTDLL, system file stability, memory patching, function hooking, AV/EDR modification
Summary: This unit defines binary patching as the modification of binaries on disk or in memory to change their execution behavior. It discusses the risks and consequences of patching system files like NTDLL, highlighting potential instability and detection. The text also mentions that AV/EDR solutions use memory patching for function hooking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 22 What Is Binary Patching? Modifying binaries to achieve results Modifying binaries to achieve results What would happen if you patch a system file like NTDLL where it sits in System32? Your hooks would be implemented all over the place and it could draw way too much attention to you. Instead, you could patch a secondary or tertiary DLL that NTDLL loads. What Is Binary Patching? Binary patching is often referred to as modifying a binary as it resides on disk or in memory with the intention of changing how it executes. In memory patching is often done by AV/EDR solutions to change how functions of interes

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DOS stub, PE signature, PE\0\0, COFF, IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_RELOCS_STRIPPED, Optional header, Section headers
Summary: The unit describes the structure of Portable Executable (PE) files, specifically focusing on components like the DOS stub, PE signature, COFF header, and section headers. It details various file characteristics and explains the requirements for optional headers and sections.
Excerpt:
Dynamic-linked Libraries (2) DOS stub: This stub has been around since MS-DOS version 2 and the only reason it is still present is to alert the user that the program cannot be run in DOS mode. Simple! PE signature: Simple marker of PE followed by 2 NULL bytes: PE\0\0. COFF: Common object file format. Used for holding various information like what machine types the program should execute, how many sections are in it, when it was created, pointer to the symbol table, how many entries are in the symbol table, what the size of the optional header is, and what characteristics the file has. Below is a short list of some characteristics a file could have. • IMAGE_FILE_EXECUTABLE_IMAGE :: 0x0002 :: 

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked libraries, DLL structure, DOS stub, PE header, SEC670
Summary: The unit describes the internal structure of Dynamic-linked Libraries (DLLs), specifically focusing on1. The text highlights components like stubs, PE headers, and various file sections containing code, data, and resources.
Excerpt:
Visual caption: A presentation slide titled 'Dynamic-linked Libraries (2)' explaining the internal structure of a DLL file. Visible text: Dynamic-linked Libraries (2); What is inside of a DLL?; stub; DOS stub; useless today; PE; PE0; COFF; Common object file format; optional; Image-specific file headers; section; Information about the sections; sections; Actual code, data, resources Alt/source label:

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, Dumpbin utility, PEview, PE-bear, CFF Explorer
Summary: The unit describes various tools used for analyzing and inspecting the contents of dynamic-linked libraries (DLLs). It specifically lists Dumpbin, PEview, PE-bear, and CFF Explorer.
Excerpt:
Visual caption: A presentation slide titled 'Dynamic-linked Libraries (3)' listing tools for analyzing DLL files. Visible text: Dynamic-linked Libraries (3); How do you see what is inside of a DLL?; Dumpbin utility; PEview; PE-bear; CFF Explorer Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: DLL analysis, PE file structure, Dump10000, PE-bear, CFF Explorer, WinDbg !dh command
Summary: The text describes various tools for analyzing the internal structure of DLL and PE files, including Dumpbin, PEview, PE-bear, CFF Explorer, and WinDbg.
Excerpt:
Dynamic-linked Libraries (3) There are a few tools available today that let you look at what is inside of a DLL. The tools do not just parse the structure of DLL files, but they can parse almost any type of PE file you throw at it. The dumpbin utility is a command-line tool that is typically available with a standard installation of Visual Studio. PEview is a GUI application with the bare necessities for viewing the file’s structure. The headers are easily identified allowing for simple navigation through them. PE-bear is a rich GUI application that is full of great features. You can load several PE files at the same time and manually browse the file of interest. Tabs organize the structure 

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: dumpbin /headers, PE header parsing, IMAGE_FILE_MACHINE_I386, optional header size, DLL file type
Summary: The text describes the use of the dumpbin utility to parse and display information from PE headers in DLL files. It details specific fields such as machine architecture, number of sections, and optional header size for custom tool development.
Excerpt:
Dynamic-linked Libraries (4) As mentioned previously, the dumpbin utility ships with the SDK and as such, it is only available on your Dev-VM. Dumpbin offers a wide array of commands, everything from dumping headers to showing the disassembly of an image’s section, like the TEXT section. Running the dumpbin /headers headers command will direct dumpbin to parse the entire image’s PE header. The tool will provide verbose output similar to the output shown on the slide. The output shown indicates that it checks the validity of the image being parsed to ensure it knows the file format. If you were to give dumpbin a file it does not know the format of, like a Windows header file, it will return t

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: dumpbin, DLL, PE signature, header values
Summary: The unit contains a screenshot of the `dumpbin` command output for a DLL file named 'hello.dll'. It displays technical details such as the PE signature, file type, and header values.
Excerpt:
Visual caption: A screenshot of a terminal window displaying the output of the `dumpbin` command on a DLL file. Visible text: Dynamic-linked Libraries (4); dumpbin /headers hello.dll; Dump of file hello.dll; PE signature found; File Type: DLL; FILE HEADER VALUES; 0E2A1355 time date stamp from Feb 19, 09:26:45 2021; SEC6070 | Red-Teaming Tools. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SERVICE_FAILURE_ACTIONS, typedef struct, SANS Institute 2024, SEC701
Summary: The unit describes the technical structure of 'SERVICE_FAILURE_ACTIONS' within a Windows environment as part of a red teaming tools course. It references specific internal structures used in system services.
Excerpt:
Visual caption: A slide from a technical presentation or manual describing the 'SERVICE_FAILURE_ACTIONS' structure in a Windows environment. Visible text: SERVICE_FAILURE_ACTIONS; typedef struct; SANS Institute 2024; SEC701 / Red Team Tools Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Ace String Layout, ace_type, cc, cd, ca, cr, cn, cl
Summary: The unit describes the structure of an Access Control Entry (ACE) string, detailing specific attribute fields such as ace_type, ace_flags, and various rights types like generic_rights and registry_rights. It lists technical components related to ACE structures in a Windows environment.
Excerpt:
Visual caption: A slide titled 'Ace String Layout' detailing the structure of an ACE string, including various attribute fields like ace_type, ace_flags, generic_rights, and registry_rights. Visible text: Ace String Layout; ace_type; ace_flags; generic_rights; registry_rights; standard_rights; label_rights; file_system_rights; ACE.cc; ACE.cd; ACE.od; ACE.ad; ACE.al; CI; CC; CD; CA; CR; CN; CL Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SDDL string, S3DL Example #1, MSDN Example, NULL well-known SID, shellcode, command and control
Summary: The unit describes an example of an SDDL string breakdown for a security context. It highlights specific field types like the NULL well-known SID and mentions related topics such as shellcode and command and control.
Excerpt:
Visual caption: A slide titled 'S3DL Example #1' showing a breakdown of an SDDL string and its corresponding fields. Visible text: S3DL Example #1; MSDN Example; Several field types skipped; Uses the NULL well-known SID; SEC701 / Red Team_Tools, Developing Windows_Security. Shellcode, Command and Control Alt/source label:

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: dynamic-linked libraries, ELF file, GNU_EXEC_MEMORY, Windows Implants
Summary: The unit contains a visual caption describing a tool's output for analyzing dynamic-linked libraries in an ELF file. It includes technical headers like GNU_EXEC_MEMORY and mentions the context of developing Windows implants.
Excerpt:
Visual caption: A slide showing the output of a tool analyzing dynamic-linked libraries for an ELF file. Visible text: Dynamic-linked Libraries (5); OPTIONAL HEADER VALUES; ELF HEADER; GNU_EXEC_MEMORY; SEC070: Red Teaming Tools. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE32, magic number, entry point, DllMain(), figure out 32-bit vs 64-bit, NOENTRY, size of code, image base
Summary: This unit describes the structure and significance of fields within the Optional Header of a PE file, specifically focusing on Dynamic-linked Libraries (DLLs). It details key components such as the magic number for architecture identification, entry points, and various size and alignment parameters. The text also provides a specific example of header values for a DLL.
Excerpt:
Dynamic-linked Libraries (5) Note: Some output was removed to fit on the slide. The two more important fields in the optional header are the magic number and the entry point. The magic number here will either indicate if the binary is a 32-bit compilation or a 64-bit compilation. The hex value 10Bh indicates 32-bit compilation, or simply PE32. For a 64-bit compilation, the hex value 20Bh would be shown, or simply PE32+. Again, the optional header is not optional for PE files because the loader depends on information found within this header. Import information it needs from this section is, for starters, the PE type or the optional header type. The slide output shows a PE32 file, meaning an 

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNamedSecurityInfoA, SECURITY_INFORMATION, NTFS objects, services, keys, shares
Summary: The unit describes the Windows API function GetNamedSecurityInfoA and its applicable targets such as NTFS objects, services, keys, and shares. It is part of a training module on developing custom tools for Windows.
Excerpt:
Visual caption: A presentation slide explaining the Windows API function GetNamedSecurityInfoA and its parameters. Visible text: GetNamedSecurityInfoA; SECURITY_INFORMATION; NTFS objects, services, keys, shares, file-mapping objects; SEC70 / Red Teaming Tools: Deepviewing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EXPLICIT_ACCESS_A, C programming, Windows security, access control
Summary: The unit describes the C programming structure EXPLICIT_ACCESS_A used for defining access control information in Windows security. It specifically mentions its application to users, groups, and programs.
Excerpt:
Visual caption: A screenshot of a technical slide or document detailing the EXPLICIT_ACCESS_A structure in C programming for Windows security. Visible text: EXPLICIT_ACCESS_A; Defines access control information for a trustee; The user, group, program to apply it against; SEC70 / Red Team Tactics...; explicit_access.ee Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Relative Virtual Address (RVA), DLL structure, memory address calculation, export directory, base relocation directory
Summary: The text explains the structure of Dynamic-linked Libraries (DLLs), specifically focusing on Relative Virtual Addresses (RVAs) and their relationship to virtual addresses in memory. It details various directory types within a DLL, such as export, import, resource, and base relocation directories, providing specific offsets for these components.
Excerpt:
Dynamic-linked Libraries (6) The last portion of the optional header is the number of directories. This is going to be important to understand as the course progresses because tools will be developed to parse through this section and modifications will be made here. Before we begin, let us first understand RVAs. RVAs are relative virtual addresses from the beginning of the file. In other words, they are simply offsets from the beginning of the file. Since DLLs can be loaded at any random address, by design, it is much easier to deal with offsets. Once a DLL is loaded, the virtual address in memory can be calculated with some simple math. Take the base address of the DLL and add the RVA to it

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Relative Virtual Address (RVA), base address, DLL loading, export directory, base relocation directory
Summary: The text explains the concept of Relative Virtual Addresses (RVAs) and their relationship to base addresses in DLL loading. It details the structure of the PE header's directory table, specifically highlighting export, import, and relocation directories.
Excerpt:
Dynamic-linked Libraries (6) The last portion of the optional header is the number of directories. This is going to be important to understand as the course progresses because tools will be developed to parse through this section and modifications will be made here. Before we begin, let us first understand RVAs. RVAs are relative virtual addresses from the beginning of the file. In other words, they are simply offsets from the beginning of the file. Since DLLs can be loaded at any random address, by design, it is much easier to deal with offsets. Once a DLL is loaded, the virtual address in memory can be calculated with some simple math. Take the base address of the DLL and add the RVA to it

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Relative Virtual Address, Virtual Address, Base Address, calculation formula
Summary: The unit describes the mathematical relationship between Relative Virtual Addresses (RVA) and Virtual Addresses for dynamic-linked libraries in a Windows environment. It includes formulas for calculating both values based on the assumption of a base address.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the calculation of Relative Virtual Addresses (RVA) and Virtual Addresses for dynamic-linked libraries. Visible text: Dynamic-linked Libraries (6); 10 number of Directories; Virtual Address = Base Address + RVA; RVA = Virtual Address - Base Address; SEC402: Red Teaming Tools. Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: AddMonitor, local port monitor, BOOL return type, _MONITOR_INFO_2
Summary: The unit describes the `AddMonitor` function used for installing local port monitors. It details technical specifications including its boolean return type and the associated `_MONITOR_INFO_2` data structure.
Excerpt:
Visual caption: A slide from a technical presentation or manual describing the AddMonitor function and its associated data structure. Visible text: AddMonitor; Used to install a local port monitor; Has a BOOL return type; typedef struct _MONITOR_INFO_2; SANS Institute 2024 Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: memory layout, dynamic-linked libraries, DLL base, DLL rebase, thread mapping
Summary: The unit contains a diagram illustrating the memory layout of dynamic-linked libraries (DLLs) and threads within a process. It details base addresses and rebase information for multiple DLLs.
Excerpt:
Visual caption: A diagram illustrating the memory layout of dynamic-linked libraries (DLLs) and threads within a process, showing different base addresses and rebase information. Visible text: Dynamic-linked Libraries (7); EXE; hello.dll; Thread 1; Thread 2; Thread 1; Thread 3; Thread 4; 0x00000000; 10000000 DLL base; DLL rebase 00000000; pages; SEC670 | Red Teaming Tools. Developing Windows Implants, Shellcode, Command and Control; 57 Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, .TEXT section, PAGE_EXECUTE_READ, RVA, rawdata, disasm
Summary: The unit describes the structure and permissions of the .TEXT section in a PE file, specifically highlighting how executable code is stored and protected by missing Write permissions. It details technical specifications like virtual size, RVA, and raw data locations for this section.
Excerpt:
Dynamic-linked Libraries (8) The section headers should immediately follow the optional header and the number of sections can be found in the file header. The first one, TEXT, is where the executable code is located. Please pay special attention to the permissions of this section and you might notice how the Write permission flag is missing. The TEXT section is only Execute and Read because the processor must be allowed to read the instructions and execute them. If the section had the Write permission, then an attacker would be free to make changes to program code. The loader will make sure this section is mapped into a page of memory with only PAGE_EXECUTE_READ permissions set. The virtual 

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, .TEXT section, PAGE_EXECUTE_READ, RVA, rawdata /section:.text, disasm /security
Summary: This unit describes the structure and permissions of the .TEXT section in a PE file, specifically focusing on why it is typically restricted to Execute and Read permissions. It details how the loader maps these sections into memory and provides specific example values for virtual size, RVA, and raw data sizes.
Excerpt:
Dynamic-linked Libraries (8) The section headers should immediately follow the optional header and the number of sections can be found in the file header. The first one, TEXT, is where the executable code is located. Please pay special attention to the permissions of this section and you might notice how the Write permission flag is missing. The TEXT section is only Execute and Read because the processor must be allowed to read the instructions and execute them. If the section had the Write permission, then an attacker would be free to make changes to program code. The loader will make sure this section is mapped into a page of memory with only PAGE_EXECUTE_READ permissions set. The virtual 

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, .TEXT section, executable code
Summary: The unit describes the structure of a .TEXT section within a dynamic-linked library. It highlights that this section contains the executable code for the library.
Excerpt:
Visual caption: A slide from a cybersecurity course showing the structure of a .TEXT section in a dynamic-linked library. Visible text: Dynamic-linked Libraries (8); .TEXT section; The executable code; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: .rdata section, initialized data, Optional Header Directories, RVA (Relative Virtual Address), Export Directory, Debug Directory
Summary: The unit describes the .rdata section of a PE file, specifically focusing on how it contains initialized data and directory information from the optional header. It details the location of Export and Debug directories within this section and provides specific RVA values for these locations.
Excerpt:
Dynamic-linked Libraries (9) The .rdata section is a Read only section that holds any data that has been initialized, like setting the variable best_sans_class to 670. The other interesting tidbit here is that the directories that were noted in the optional header reside specifically within the .rdata section. This can be observed and verified by looking at the RVAs listed for the Export and Debug directories. The RVAs are clearly within the .rdata section. Just like with the .text section, the raw data can be viewed to see what is actually being held in the .rdata section. After all, it should have some information because initialized data should be here. SEC670 | Red Teaming Tools: Develop

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, .rdata name, SECTION NUMBER 20, OPTIONAL HEADER Directories
Summary: The unit contains a visual caption describing an analysis of dynamic-linked library (DLL) section headers and optional header directories. It specifically mentions the .rdata section and various technical specifications.
Excerpt:
Visual caption: A screenshot of a slide or document showing the analysis of a dynamic-linked library's section headers and optional header directories. Visible text: Dynamic-linked Libraries (9); .rdata name; SECTION NUMBER 20; Read only, initialized data; .rdata section; OPTIONAL HEADER Directories; SEC076 | Red Teaming Tools Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: .rdata section, initialized data, OPTIONAL_HEADER Directories, Export Directory, Debug Directory, RVA
Summary: The unit describes the .rdata section of a PE file, specifically focusing on how it contains initialized data and directory information from the optional header. It details the location of Export and Debug directories within this section and provides specific RVA values for these locations.
Excerpt:
Dynamic-linked Libraries (9) The .rdata section is a Read only section that holds any data that has been initialized, like setting the variable best_sans_class to 670. The other interesting tidbit here is that the directories that were noted in the optional header reside specifically within the .rdata section. This can be observed and verified by looking at the RVAs listed for the Export and Debug directories. The RVAs are clearly within the .rdata section. Just like with the .text section, the raw data can be viewed to see what is actually being held in the .rdata section. After all, it should have some information because initialized data should be here. SEC670 | Red Teaming Tools: Develop

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, RVA, /exports switch, /disasm switch, EAX register, __cdecl calling convention
Summary: The unit describes the analysis of a Dynamic-linked Library (DLL) using tools like /exports and /disasm. It details how to identify function RVA, verify calling conventions, and interpret assembly code for a simple string return.
Excerpt:
Dynamic-linked Libraries (10) It was discovered on the previous slide that the RVA for the PrintHello function was 1000. The output from the /exports switch verified what was found with a manual lookup. Checking the output from the /disasm switch along with /section:.text, the code for the function can be seen. Understanding the assembly for the function is simple because the function only does one thing—return the pointer to a string. The __cdecl calling convention specified for this function uses the EAX register to hold the return values. Here, EAX will end up holding the RVA 2000. The data at RVA 2000 was previously seen already and is indeed the address to the string “Welcome to DLL Hel

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, RVA, /exports switch, /disasm switch, EAX register, assembly analysis
Summary: The unit describes the analysis of a Dynamic-linked Library (DLL) function named PrintHello. It details how to use tools like /exports and /disasm to identify RVA values and examine assembly code for return values in the EAX register.
Excerpt:
Dynamic-linked Libraries (10) It was discovered on the previous slide that the RVA for the PrintHello function was 1000. The output from the /exports switch verified what was found with a manual lookup. Checking the output from the /disasm switch along with /section:.text, the code for the function can be seen. Understanding the assembly for the function is simple because the function only does one thing—return the pointer to a string. The __cdecl calling convention specified for this function uses the EAX register to hold the return values. Here, EAX will end up holding the RVA 2000. The data at RVA 2000 was previously seen already and is indeed the address to the string “Welcome to DLL Hel

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Ntdll.dll, Kernel32.10, Kernelbase.dll, User32.dll, system DLLs, re-exported functions
Summary: The text describes the role and characteristics of core system DLLs including Ntdll.dll, Kernel32.dll, Kernelbase.dll, and User32.dll. It explains how these libraries are mapped into processes and their relationship to each other, such as re-exports from NTDLL.
Excerpt:
Dynamic-linked Libraries (11) There are several system DLLs that will be mapped into almost every process: Ntdll.dll, Kernel32.dll, and Kernelbase.dll. Despite them practically always being mapped, Ntdll.dll is the only one required, but the OS will take care of that for you. NTDLL exports many functions that act as a gateway of sorts before making the jump into kernel land. KERNEL32 also exports many functions and a large number of which are simply re-exported functions from NTDLL. Some functions might not have any code in them at all but are simply jumps or forwarders to a function in NTDLL. USER32 is a primary component for GUI applications as it holds various functions for creating graph

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Ntdll.dll, Kernel32.dll, Kernelbase.dll, User32.dll, gateway to kernel land, unloading system DLLs, user-mode hooks
Summary: The text describes the role and characteristics of core Windows system DLLs including Ntdll.dll, Kernel32.dll, Kernelbase.dll, and User32.dll. It explains how these libraries are mapped into processes and their relationship to each other as gateways to kernel land or GUI components. The section also mentions a project aimed at bypassing user-mode hooks by unloading system DLLs.
Excerpt:
Dynamic-linked Libraries (11) There are several system DLLs that will be mapped into almost every process: Ntdll.dll, Kernel32.dll, and Kernelbase.dll. Despite them practically always being mapped, Ntdll.dll is the only one required, but the OS will take care of that for you. NTDLL exports many functions that act as a gateway of sorts before making the jump into kernel land. KERNEL32 also exports many functions and a large number of which are simply re-exported functions from NTDLL. Some functions might not have any code in them at all but are simply jumps or forwarders to a function in NTDLL. USER32 is a primary component for GUI applications as it holds various functions for creating graph

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: implicit linking, explicit linking, DLL linkage
Summary: The unit describes the technical differences between implicit and explicit linking of Dynamic Link Libraries (DLLs). It explains that a program requires a link to function with a DLL.
Excerpt:
Visual caption: A presentation slide explaining the difference between implicit and explicit linking of DLLs. Visible text: DLLs: Linking (I); Implicit linking; Explicit linking; A DLL does nothing for you unless you link your program to it. Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Classic vs RDI, DLL injection, loadLibraryA, position independent function, memory-based loading
Summary: The unit compares Classic and Reflective DLL Injection (RDI) methods, highlighting differences in memory handling, disk requirements, and loader dependencies. It details the technical steps for both methods, including buffer allocation, section copying, and execution paths.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 11 RDI: Differences Noting the differences between Classic and RDI methods of injection Noting the differences between Classic and RDI methods of injection 1. Allocate local buffer and read in raw DLL bytes 2. Obtain process handle 3. Allocate remote memory 4. Copy over all sections keeping section permissions 5. Apply fixups for “rebasing” 6. Execute AddressOfEntryPoint 1. Obtain process handle 2. Allocate memory for DLL path 3. Write the DLL path 4. Create remote thread to load the library into target process RDI: Differences Now that we have discussed what RDI is and how to implement it programmaticall

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Unit Review Answers, native application function signature, s1, s2, s3 options
Summary: The unit contains a review question and its corresponding answer regarding the function signature for a native application. It identifies the correct option among three choices provided.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a question about native application function signatures. Visible text: Unit Review Answers; What is the function signature for a native application?; A: NTSTATUS NT_main(int argc, const char* argv[]); B: DWORD NT_main(int argc, const char* argv[]); C: INT main(int argc, const char* argv[]) Alt/source label:

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: system call numbers, Windows XP, Windows 10, github link
Summary: The unit contains a screenshot of a webpage or document listing system call numbers for various Windows versions, including XP and 10.
Excerpt:
Visual caption: A screenshot of a webpage or document containing information about system call numbers for different versions of Windows. Visible text: What's Your Number; Syscall my number; System Call Symbol; Windows XP (beta); Windows 10 (beta); MC679 / EL Team; What's Your Number?; Reference: http://github.com/00y/windows-syscall/tree/master Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: user mode, kernel mode, kernel transition, NtAllocateVirtualMemory
Summary: The unit describes the transition from user mode to kernel mode during a system call. It specifically highlights how memory addresses are handled during this process.
Excerpt:
Visual caption: A slide explaining the transition from user mode to kernel mode during a system call, illustrating how memory addresses are handled. Visible text: Hello Operator?; Syscall NtAllocateVirtualMemory please; User mode; Kernel mode; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IAT Hooking, Function pointer hooking, PE header parsing, VirtualProtect API, DataDirectory, Kernel32.dll, Ntdll.dll
Summary: This unit describes the technical process of IAT (Import Address Table) hooking, specifically for manipulating function pointers in Windows environments. It details a multi-step procedure involving parsing PE headers, locating modules like Kernel32.dll or Ntdll.dll, and using VirtualProtect to change page permissions before overwriting entries.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 IAT Hooking An array of addresses An array of addresses AKA: Function pointer hooking AKA: Function pointer hooking 1. Parse PE headers to find import table 2. Locate module that implements the hooked function 3. Locate the function in the found module 4. Change page protections to PAGE_READWRITE, save old permissions 5. Overwrite function pointer 6. Restore previous page protections IAT is typically read-only Must make it writeable IAT is typically read-only Must make it writeable IAT Hooking If you recall from the PE header module, the IAT is one of 16 entries in the array named DataDirectory. The ta

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IAT Hooking, Function pointer hooking, PE header parsing, VirtualProtect API, VirtualAlloc API, Kernel32.dll, Ntdll.dll
Summary: This unit describes the technical process of IAT (Import Address Table) hooking, specifically for manipulating function pointers in Windows environments. It details a multi-step procedure involving parsing PE headers, locating modules like Kernel32.dll or Ntdll.dll, and using VirtualProtect to change page permissions before overwriting entries.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 39 IAT Hooking An array of addresses An array of addresses AKA: Function pointer hooking AKA: Function pointer hooking 1. Parse PE headers to find import table 2. Locate module that implements the hooked function 3. Locate the function in the found module 4. Change page protections to PAGE_READWRITE, save old permissions 5. Overwrite function pointer 6. Restore previous page protections IAT is typically read-only Must make it writeable IAT is typically read-only Must make it writeable IAT Hooking If you recall from the PE header module, the IAT is one of 16 entries in the array named DataDirectory. The ta

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Linux shared objects, ELF format, dlopen/dlclose, dlsym
Summary: The unit describes characteristics of Linux shared objects, including their ELF format, lack of specific export syntax, and dynamic loading capabilities via dlopen/dlclose. It also notes thats they are typically extended as .so or .a files.
Excerpt:
Visual caption: A presentation slide titled 'Shared Objects' detailing characteristics of Linux shared objects. Visible text: Shared Objects; Linux shared objects have the ELF format; Linux SOs do not have a specific export syntax; Extensions are a .so or .a; Can be dynamically loaded/unloaded with dlopen/dlclose; Resolve symbols with dlsym Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: shellcode, C language, Unit Review Answers, heap, external references
Summary: The unit contains a slide presenting answers to review questions regarding the technical constraints of shellcode creation in C. It specifically mentions avoiding bugs, external references, and heap usage.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a unit review question about shellcode creation in C. Visible text: Unit Review Answers; When creating shellcode using C, what do you want to avoid?; Bugs; External references; The heap Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows APIs, calling conventions, __cdecl convention, critical functionality
Summary: The unit discusses the naming conventions and calling conventions of Windows APIs, highlighting their specific behavior compared to standard cdecl conventions. It notes that while API names may be long, they provide critical system functionality.
Excerpt:
Visual caption: A presentation slide titled 'Windows APIs' discussing the calling conventions and naming of Windows APIs. Visible text: Windows APIs; Windows APIs and their calling conventions; This is a Windows-specific calling convention that behaves differently from __cdecl convention.; API names can be very descriptive and lengthy.; Critical functionality is provided via these APIs. Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: explicit linking, DLLs at compile time, sourcing from SEC679
Summary: The unit contains a multiple-choice question regarding the types of linking for DLLs in Windows environments. It specifically covers compile-time and runtime linking via Windows APIs.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about explicit linking. Visible text: Unit Review Answers; What is explicit linking?; Linking to DLLs at compile time; Linking to DLLs at runtime via Windows APIs; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:
