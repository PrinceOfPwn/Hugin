# Atlas Material — binary-analysis (part 8)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateFile, Windows programming, Multiple-choice question, Unit Review Answers
Summary: The unit contains a multiple-choice question regarding the Windows programming function CreateFile and its specific return values during an error state.
Excerpt:
Visual caption: A screenshot of a study guide page for the SANS SEC670 course, showing a multiple-choice question about the CreateFile function in Windows programming. Visible text: Unit Review Answers; What does CreateFile return upon error?; A: A handle to the file; B: ERROR_INVALID_PARAMETER; C: INVALID_HANDLE_VALUE Alt/source label:

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateFile, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE, Unit Review
Summary: This unit contains a review section for the CreateFile function in Windows programming. It lists multiple choice options for identifying the error return values of the CreateFile function.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What does CreateFile return upon error? What does CreateFile return upon error? A A handle to the file A A handle to the file B ERROR_INVALID_PARAMETER B ERROR_INVALID_PARAMETER C INVALID_HANDLE_VALUE C INVALID_HANDLE_VALUE 191 Unit Review Answers Q: What does CreateFile return upon error? A: A handle to the file B: ERROR_INVALID_PARAMETER C: INVALID_HANDLE_VALUE 191 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateFile, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE, Unit Review
Summary: This unit contains a review section for the CreateFile function in Windows programming. It lists multiple choice options for identifying the handle returned when an error occurs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What does CreateFile return upon error? What does CreateFile return upon error? A A handle to the file A A handle to the file B ERROR_INVALID_PARAMETER B ERROR_INVALID_PARAMETER C INVALID_HANDLE_VALUE C INVALID_HANDLE_VALUE 191 Unit Review Answers Q: What does CreateFile return upon error? A: A handle to the file B: ERROR_INVALID_PARAMETER C: INVALID_HANDLE_VALUE 191 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: HRESULT, SUCCEEDED, FAILED, GetLastError, STATUS_OK
Summary: The unit contains review questions regarding the use of macros for checking HRESULT function return types in Windows programming. It lists multiple options for identifying successful or failed operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What macro(s) can be used to check HRESULT function return types? What macro(s) can be used to check HRESULT function return types? A SUCCEEDED / FAILED A SUCCEEDED / FAILED B GetLastError B GetLastError C STATUS_OK / STATUS_FAILED C STATUS_OK / STATUS_FAILED 192 Unit Review Questions Q: What macro(s) can be used to check HRESULT function return types? A: SUCCEEDED / FAILED B: GetLastError C: STATUS_OK / STATUS_FAILED 192 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: entries_used, total_entries, resume_end_handle
Summary: The unit contains a list of variables and identifiers related to a technical manual or study guide, specifically mentioning 'entries_used', 'total_entries', and 'resume_handle'. It appears to be part of a documentation for Windows API programming.
Excerpt:
Visual caption: A page from a technical manual or study guide describing the parameters for a function, likely related to Windows API programming. Visible text: entries_used; total_entries; resume_handle; OffsecExam Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: C programming, MIB_IPSTATS_LH, GetIfStatistics, SEC401
Summary: The unit contains a C programming structure definition for the MIB_IPSTATS_LH struct. It includes technical identifiers like 'GetIfStatistics' and 'SEC401'.
Excerpt:
Visual caption: A screenshot of a C programming structure definition for the MIB_IPSTATS_LH struct. Visible text: MIB_IPSTATS_Structure; typedef struct _MIB_IPSTATS_LH; GetIfStatistics; SEC401; 121 Alt/source label:

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: ERROR_SUCCESS, ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_NOT_ENUGH_MEMORY, ERROR_NO_DATA
Summary: The text describes the return codes and error conditions for a specific function, likely related to device address retrieval or buffer management.
Excerpt:
Upon success, the function will return ERROR_SUCCESS. Should the function ever fail it will return one of the following error codes: - ERROR_ADDRESS_NOT_ASSOCIATED: An address has yet to be associated with the device. - ERROR_BUFFER_OVERFLOW: The buffer size indicated is not large enough to hold the requested information. - ERROR_INVALID_PARAMETER: SizePointer is NULL, Family was not a valid family option. - ERROR_NOT_ENOUGH_MEMORY: Literally not enough memory to complete the function. - ERROR_NO_DATA: No addresses found. 123 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: ERROR_SUCCESS, ERROR_BUFFER_OVER_FLOW, ERROR_INVALID_PARAMETER
Summary: The unit contains a list of common Windows API error codes and their corresponding descriptions. It specifically lists several constants used in programming to handle success or failure states.
Excerpt:
Visual caption: A slide containing a list of error codes and their descriptions for a function that returns ERROR_SUCCESS if successful. Visible text: ERROR_SUCCESS; ERROR_ADDRESS_NOT_ASSOCIATED; ERROR_BUFFER_OVERFLOW; ERROR_INVALID_PARAMETER; ERROR_NOT_ENOUGH_MEMORY; ERROR_NO_DATA Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: RegEnumValue, C code snippet, ERROR_NO_MORE_ITEMS
Summary: The unit contains a C code snippet and associated error codes for enumerating registry values using the RegEnumValue function.
Excerpt:
Visual caption: A screenshot of a C code snippet demonstrating the use of the RegEnumValues function. Visible text: Example: RegEnumValue; RegEnumValue; ERROR_NO_MORE_ITEMS Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: MS-DOS 2.0 EXE Header, e_magic (4D 5A), e_lfanew offset 0x3C, Total PE tool
Summary: The text describes the structure of the MS-DOS 2.0 EXE header within a PE file, specifically focusing on fields like e_magic and e_lfanew.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 10 MS-DOS 2.0 EXE Header: kernelbase.dll MS-DOS 2.0 EXE Header: kernelbase.dll Now that you know the structure of the DOS header, we can start to make sense of the hexdump of kernelbase.dll. The screenshot is from Visual Studio Code to see the structures and Total PE, a tool written by Pavel Yosifovich. A side-by-side layout like this can help make your way through the various PE headers and the fields inside each structure. For this IMAGE_DOS_HEADER structure, almost each field is a WORD size. Now that you know this, it is easier to identify each field and move on to the next field, you just jump two (2)

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: MS-DOS 2.0 EXE Header, e_magic (4D 5A), e_lfanew offset 0x3C, Total PE tool
Summary: The text describes the structure of the MS-DOS 2.0 EXE header within a PE file, specifically focusing on identifying fields like e_magic and e_lfanew using tools like Total PE.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 10 MS-DOS 2.0 EXE Header: kernelbase.dll MS-DOS 2.0 EXE Header: kernelbase.dll Now that you know the structure of the DOS header, we can start to make sense of the hexdump of kernelbase.dll. The screenshot is from Visual Studio Code to see the structures and Total PE, a tool written by Pavel Yosifovich. A side-by-side layout like this can help make your way through the various PE headers and the fields inside each structure. For this IMAGE_DOS_HEADER structure, almost each field is a WORD size. Now that you know this, it is easier to identify each field and move on to the next field, you just jump two (2)

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Lab 3.1, GetFunctionAddress, eWorkbook reference
Summary: The unit contains instructions for Lab 3.1 regarding 'GetFunctionAddress'. It specifies that students should refer to an eWorkbook for detailed lab instructions.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Lab 3.1: GetFunctionAddress' providing instructions to refer to an eWorkbook for details. Visible text: Lab 3.1: GetFunctionAddress; Parse a PE file to obtain the address of a given function; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: MS-DOS header, multiple-choice question, 0x00, 0x90, SEC601
Summary: The unit contains a multiple-choice question regarding the structure of MS-DOS headers in the context of offtensive security. It specifically asks for the identifying byte following the header.
Excerpt:
Visual caption: A slide from a cybersecurity course showing a multiple-choice question about the MS-DOS header. Visible text: Unit Review Questions; What is typically the next byte comes after the MS-DOS header?; 0x00; 0x90; 005A; SEC601 | Red Team Tactics, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: MS-DOS header, Unit Review Answers, 0x00, 0x90, 005A
Summary: The unit contains a review question and answer regarding the structure of MS-DOS headers. It specifically identifies the bytes following the header, such as 0x00, 0x90, or 005A.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a unit review question about MS-DOS headers. Visible text: Unit Review Answers; What is typically the next byte comes after the MS-DOS header?; 0x00; 0x90; 005A Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE32+, magic value, optional header, binary format
Summary: The unit contains a review question regarding the identification of PE32+ binary magic values in the optional header. It specifically asks for the difference between 32-bit and 64-bit executable formats.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 31 Unit Review Questions In the optional header, what magic value indicates a PE32+ binary? In the optional header, what magic value indicates a PE32+ binary? A 0x20B A 0x20B B 0x10B B 0x10B C 0x00B C 0x00B Unit Review Questions Q: In the optional header, what magic value indicates a PE32+ binary? A: 0x20B B: 0x10B C: 0x00B © 2024 Jonathan Reiter 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE32+, magic value, optional header, 0x20B
Summary: The unit contains a review question regarding the identification of PE32+ binary magic values in the optional header. It specifically asks for the user to identify which hex value corresponds to PE32+.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 31 Unit Review Questions In the optional header, what magic value indicates a PE32+ binary? In the optional header, what magic value indicates a PE32+ binary? A 0x20B A 0x20B B 0x10B B 0x10B C 0x00B C 0x00B Unit Review Questions Q: In the optional header, what magic value indicates a PE32+ binary? A: 0x20B B: 0x10B C: 0x00B © 2024 Jonathan Reiter 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE32+, magic value, multiple-choice, 0x20B, 0x10B, 00B
Summary: The unit contains a multiple-choice question regarding the identification of PE32+ binaries based on their magic value. It specifically asks for the difference between standard and extended headers.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the magic value for PE32+ binaries. Visible text: Unit Review Questions; In the optional header, what magic value indicates a PE32+ binary?; 0x20B; 0x10B; 0x00B Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE32+, magic value, optional header, 0x20B
Summary: The unit contains a review question regarding the magic value for PE32+ binaries in the optional header of a Portable Executable file. It provides multiple-choice options and the correct answer.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 32 Unit Review Answers In the optional header, what magic value indicates a PE32+ binary? In the optional header, what magic value indicates a PE32+ binary? A 0x20B A 0x20B B 0x10B B 0x10B C 0x00B C 0x00B Unit Review Answers Q: In the optional header, what magic value indicates a PE32+ binary? A: 0x20B B: 0x10B C: 0x00B 32 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: DWORD64, R11-R15, Rip, LaufExceptionTop, CONTEXT, *CONTEXT
Summary: The unit contains a snippet of assembly-like code or data structure definitions involving 64-bit registers and context pointers.
Excerpt:
Visual caption: A snippet of assembly-like code or data structure definitions showing DWORD64 variables and a context pointer. Visible text: DWORD64 R11;; DWORD64 R12;; DWORD64 R13;; DWORD64 R14;; DWORD64 R15;; DWORD64 Rip;; .SNP; ; DWORD64 LaufExceptionTop; ; DWORD64 LaufExceptionBottom; ; CONTEXT, *CONTEXT Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: thread hijacking, thread context, multiple choice questions
Summary: The unit contains a review question regarding the specific construct that must be modified when hijacking a thread. It provides multiple-choice options for 'Thread state', 'Thread context', and 'Thread priority'.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 77 Unit Review Questions When hijacking a thread, what construct must be modified? When hijacking a thread, what construct must be modified? A Thread state A Thread state B Thread context B Thread context C Thread priority C Thread priority Unit Review Questions Q: When hijacking a thread, what construct must be modified? A: Thread state B: Thread context C: Thread priority © 2024 Jonathan Reiter 77 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: thread hijacking, thread context
Summary: The unit contains a review question regarding the specific construct that must be modified when hijacking a thread. It provides multiple-choice options for 'Thread state', 'Thread context', and 'Thread priority'.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 77 Unit Review Questions When hijacking a thread, what construct must be modified? When hijacking a thread, what construct must be modified? A Thread state A Thread state B Thread context B Thread context C Thread priority C Thread priority Unit Review Questions Q: When hijacking a thread, what construct must be modified? A: Thread state B: Thread context C: Thread priority © 2024 Jonathan Reiter 77 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: thread hijacking, thread context, multi-choice question
Summary: The unit contains a review question regarding the specific construct that must be modified when hijacking a thread. It provides multiple-choice options for 'Thread state', 'Thread context', and 'Thread priority'.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 78 Unit Review Answers When hijacking a thread, what construct must be modified? When hijacking a thread, what construct must be modified? A Thread state A Thread state B Thread context B Thread context C Thread priority C Thread priority Unit Review Answers Q: When hijacking a thread, what construct must be modified? A: Thread state B: Thread context C: Thread priority 78 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: lpBinaryPathName, lpAudit_DelayGroup, lpDcTagId, lpDependency, lpServiceAccountName, lpPassword
Summary: The unit contains a list of variable names associated with service configuration in a Windows environment. These variables include paths, audit delays, domain tags, dependencies, and account credentials.
Excerpt:
Visual caption: A slide containing a list of descriptions for various variables related to service configuration. Visible text: lpBinaryPathName; lpAuditDelayGroup; lpDcTagId; lpDependency; lpServiceAccountName; lpPassword Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows API, OpenProcessToken, OpenToken, OpenProcess
Summary: The unit contains a review question regarding specific Windows API functions used to obtain handles to process tokens.
Excerpt:
Visual caption: A slide from a SANS course showing a multiple-choice question about Windows API functions for process tokens. Visible text: Unit Review Questions; What API gives you a handle to a process' token?; OpenProcessToken(); OpenToken(); OpenProcess() Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Dynamic-linked Libraries, PE32 / PE32+, shared files, .lib, .dll
Summary: The unit describes the fundamental characteristics of Dynamic-linked Libraries (DLLs), including their file formats (PE32/PE32+) and common file extensions like .lib and .dll.
Excerpt:
Visual caption: A presentation slide titled 'Dynamic-linked Libraries (1)' describing the characteristics of DLL files. Visible text: Dynamic-linked Libraries (1); PE32 / PE32+ format; Designed to be shared; Various extensions: .lib and .dll Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: binary patching, objectives, security course content
Summary: The unit contains a slide outlining the learning objectives for a module on binary patching. It lists goals such as defining binary patching and discussing its benefits.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing the goals for the module on binary patching. Visible text: Objectives; Our objectives for this module are:; Define binary patching; Discuss benefits of binary patching; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: in-memory patching, Import Address Table, process enumeration, MZ signature (\x4d\x5a), PE header parsing, PE header parsing, patching AmsiScanBuffer, patching AmsiScanString
Summary: The unit discusses in-memory patching techniques where changes are made to a process's memory rather than its disk image. It covers identifying target processes via enumeration and locating the start of an executable' using the MZ signature. The text also mentions specific use cases like patching out calls to AMSI functions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 23 In-Memory Patching The patch is not permanent; will not survive reboots The patch is not permanent; will not survive reboots Once you are injected into a process, how do you find what it is you are trying to patch? How about walking the Import Address Table? How about enumerating processes and obtaining handles to a process of concern? These are valid questions that could be answered either during your op or beforehand. In-Memory Patching Patching an image as it sits in memory is often referred to as in-memory patching. This is relatively safe since no changes are made to the binary on disk, so if the 

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: SetNamedSecurityInfoA, SANS Institute, SEC701, SECURITY_INFORMATION
Summary: The unit describes a slide from a SANS course regarding the 'SetNamedSecurityInfoA' function. It details the function signature and its parameters for security information.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'SetNamedSecurityInfoA' detailing the function signature and its parameters. Visible text: SetNamedSecurityInfoA; SANS Institute; SEC701; SECURITY_INFORMATION; DWORD SetNamedSecurityInfo Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: dynamic-linked libraries, disassembled code, hello.dll, .text section
Summary: The unit contains a visual caption describing a screenshot of tool output showing dynamic-slinked libraries and disassembled code for a binary. It specifically mentions the number of DLLs, the export 'hello.dll', and the disassembly of the section .text.
Excerpt:
Visual caption: A screenshot of a tool output showing dynamic-linked libraries and disassembled code for a binary. Visible text: Dynamic-linked Libraries (10); exports hello.dll; disasm /section: .text; PrintHello Alt/source label:

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Unit Review Questions, function signature, native application
Summary: The unit contains a multiple-choice question regarding the identification of function signatures for native applications in a Windows environment.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about the function signature for a native application. Visible text: Unit Review Questions; What is the function signature for a native application?; A. NTSTATUS NT_main(PEB); B. DWORD NT_main(int argc, const char* argv[]); C. INT main(int argc, const char* argv[]) Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows executable headers, IMAGE_OPTIONAL_HEADER, ImageBase, PointerToSymbolTable, AddressOfEntryPoint
Summary: The unit contains a multiple-choice question regarding Windows executable headers and the specific structure/field for the program' main function.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows executable headers. Visible text: Unit Review Questions; What structure and field member refers to the program's main function?; IMAGE_OPTIONAL_HEADER.ImageBase; IMAGE_FILE_HEADER.PointerToSymbolTable; IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Alt/source label:

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: IMAGE_OPTIONAL_HEADER, ImageBase, PointerToSymbolTable, AddressOfEntryPoint
Summary: This unit contains review questions regarding the structure and field members of Windows executable headers, specifically identifying the entry point for a program's main function.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 24 Unit Review Questions What structure and field member refers to the program’s main function? What structure and field member refers to the program’s main function? A IMAGE_OPTIONAL_HEADER.ImageBase A IMAGE_OPTIONAL_HEADER.ImageBase B IMAGE_FILE_HEADER.PointerToSymbolTable B IMAGE_FILE_HEADER.PointerToSymbolTable C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Unit Review Questions Q: What structure and field member refers to the program’s main function? A: IMAGE_OPTIONAL_HEADER.ImageBase B: IMAGE_FILE_HEADER.PointerToSymbolTable C: IMAGE_OPTIONAL_HEADER.AddressOf

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: IMAGE_OPTIONAL_HEADER, ImageBase, PointerToSymbolTable, AddressOfEntryPoint
Summary: The unit contains a review question regarding the structure and field member that identifies the program's main function in a Windows executable.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 24 Unit Review Questions What structure and field member refers to the program’s main function? What structure and field member refers to the program’s main function? A IMAGE_OPTIONAL_HEADER.ImageBase A IMAGE_OPTIONAL_HEADER.ImageBase B IMAGE_FILE_HEADER.PointerToSymbolTable B IMAGE_FILE_HEADER.PointerToSymbolTable C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Unit Review Questions Q: What structure and field member refers to the program’s main function? A: IMAGE_OPTIONAL_HEADER.ImageBase B: IMAGE_FILE_HEADER.PointerToSymbolTable C: IMAGE_OPTIONAL_HEADER.AddressOf

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: IMAGE_OPTIONAL_HEADER, ImageBase, PointerToSymbolTable, AddressOfEntryPoint
Summary: This unit contains a review section for the SEC670 course, specifically focusing on identifying the correct structure and field member that points to the program's main function in Windows binaries.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 25 Unit Review Answers What structure and field member refers to the program’s main function? What structure and field member refers to the program’s main function? A IMAGE_OPTIONAL_HEADER.ImageBase A IMAGE_OPTIONAL_HEADER.ImageBase B IMAGE_FILE_HEADER.PointerToSymbolTable B IMAGE_FILE_HEADER.PointerToSymbolTable C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Unit Review Answers Q: What structure and field member refers to the program’s main function? A: IMAGE_OPTIONAL_HEADER.ImageBase B: IMAGE_FILE_HEADER.PointerToSymbolTable C: IMAGE_OPTIONAL_HEADER.AddressOfEntr

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: IMAGE_OPTIONAL_HEADER, ImageBase, PointerToSymbolTable, AddressOfEntryPoint
Summary: This unit contains a review section for the SEC670 course, specifically focusing on identifying the correct structure and field member that points to the program's main function in Windows binaries.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 25 Unit Review Answers What structure and field member refers to the program’s main function? What structure and field member refers to the program’s main function? A IMAGE_OPTIONAL_HEADER.ImageBase A IMAGE_OPTIONAL_HEADER.ImageBase B IMAGE_FILE_HEADER.PointerToSymbolTable B IMAGE_FILE_HEADER.PointerToSymbolTable C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint C IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Unit Review Answers Q: What structure and field member refers to the program’s main function? A: IMAGE_OPTIONAL_HEADER.ImageBase B: IMAGE_FILE_HEADER.PointerToSymbolTable C: IMAGE_OPTIONAL_HEADER.AddressOfEntr

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows executable structures, IMAGE_OPTIONAL_HEADER.ImageBase, IMAGE_FILE_HEADER.PointerToSymbolTable, IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
Summary: The unit contains a multiple-choice question and its corresponding answer regarding Windows executable structures, specifically identifying the field for the program's main function.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a multiple-choice question about Windows executable structures. Visible text: Unit Review Answers; What structure and field member refers to the program's main function?; IMAGE_OPTIONAL_HEADER.ImageBase; IMAGE_FILE_HEADER.PointerToSymbolTable; IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint Alt/source label:

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: dumpbin, exports, symbols, dependencies, hello.lib
Summary: The unit describes a command-line output of the dumpbin tool used to analyze executable dependencies and exported functions in a library file.
Excerpt:
Visual caption: A screenshot of a command-line output showing the results of a dumpbin tool used to analyze an executable's dependencies and exported functions. Visible text: dumpbin -exports hello.lib; dumpbin -symbols hello.lib; Image has the following dependencies:; hello.dll; KERNEL32.dll; PrintHello Alt/source label:

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Unit Review Questions, PROC_THREAD_ATTRIBUTE_LIST, KPROCESS, KUSER_SHARED_DATA
Summary: The unit contains a multiple-choice question regarding Windows process structures. It specifically asks which structure is used to change the parent process.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows process structures. Visible text: Unit Review Questions; What is the structure that can be used to change your parent process?; PROC_THREAD_ATTRIBUTE_LIST; KPROCESS; KUSER_SHARED_DATA Alt/source label:

=== UNIT 39 ===
Source: MalDevAcademy - Malware Development Course Extra - shared by Tamarisk OffsecExam.html
Value: 0.8  Key cues: metadata.src, VERSIONINFO, FILEVERSION, StringFileInfo, Google Chrome
Summary: The unit contains a screenshot of a C source file named metadata.src which includes version information and resource strings for the Google Chrome browser.
Excerpt:
Visual caption: A screenshot of a C source file named metadata.src containing version information and resource strings for Google Chrome. Visible text: metadata.src; FileAttributes.c; VERSIONINFO; FILEVERSION 112.0.5615.88; PRODUCTVERSION 1.0.0.0; StringFileInfo; CompanyName; Google LLC.; FileDescription; Google Chrome; InternalName; Chrome; LegalCopyright; Copyright 2023 Google LLC.; OriginalFilename; chrome.exe; ProductName; Google Chrome; ProductVersion; 112.8.0.5615.86 Alt/source label: Image

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: HKEY, HHINSTANCE, HRSRC, HANDLE
Summary: The unit contains a multiple-choice question regarding Windows programming data types (HKEY, HINSTANCE, HRSRC). It identifies these types as being of the type HANDLE.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows programming types. Visible text: Unit Review Answers; What do the types HKEY, HINSTANCE, HRSRC have in common?; Nothing.; They are all of type HANDLE.; They all refer to GUI applications. Alt/source label:
