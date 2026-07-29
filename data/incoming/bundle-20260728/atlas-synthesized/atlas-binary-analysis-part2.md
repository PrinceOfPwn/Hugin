# Atlas Material — binary-analysis (part 2)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateProcess, STARTUPINFO, PROCESS_INFORMATION, notepad process
Summary: The unit provides a basic example of using the CreateProcess function to launch a notepad process. It details the necessary structure types, STARTUPINFO and PROCESS_INFORMATION, and explains how variables are passed as parameters.
Excerpt:
Example: CreateProcess For this example of how to use CreateProcess, we are simply creating the notepad process with bare minimum effort, meaning, we are not taking full advantage of what the CreateProcess function has to offer. The previous slide went over the parameters so there is no need to go over them again here, rather the relevant ones will be discussed. First up, there is some standard housekeeping that must be done by the way of creating some variables with specific structure types: STARTUPINFO and PROCESS_INFORMATION. Each of those structures will have information filled out after CreateProcess returns. There is the commandLine variable that is simply holding the name of the proce

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PROCESS_INFORMATION, typedef struct _PROCESS_INFORMATION, C code, CreateProcess
Summary: The unit contains a C code snippet defining the PROCESS_INFORMATION structure. It describes how this structure holds information about a new process and its primary thread.
Excerpt:
Visual caption: A slide from a SANS course titled 'Create APIs (4)' showing the definition of the PROCESS_INFORMATION structure in C code. Visible text: Create APIs (4); PROCESS_INFORMATION; Holds information about the new process and its primary thread; typedef struct _PROCESS_INFORMATION; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Support, CreateToolhelp32Snapshot, Process32First, Process32Next
Summary: The unit describes the specific Windows API functions for process enumeration, specifically focusing on used to create a statement of processes, heaps, threads, and loaded modules. It details the mention of CreateToolhelp32Snapshot, CreateProcess32First, and Process32Next.
Excerpt:
Visual caption: A presentation slide titled 'Create APIs (5)' detailing the CreateToolhelp32Snapshot function and related functions for process enumeration. Visible text: Create APIs (5); CreateToolhelp32Snapshot; Used to create a statement of a process; Also, can be used for heaps, threads, and loaded modules; HANDLE CreateToolhelp32Snapshot(IN DWORD dwFlags, IN DWORD th32ProcessID);; BOOL Process32First(; BOOL Process32Next( Alt/source label:

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateFile, NtCreateFile, executive file object, handle table, Kernelbase.dll
Summary: The text describes the process of creating a file object in Windows, specifically detailing the transition from user-mode CreateFile API calls to kernel-mode NtCreateFile system calls. It explains how the kernel creates an executive file object and returns a handle to the application.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (3) Example flow of creating an object Example flow of creating an object User application calls CreateFile User application calls CreateFile CreateFile calls NtCreateFile CreateFile calls NtCreateFile Executive object is created Executive object is created Handle is returned to caller Handle is returned to caller 167 Windows Objects (3) There are many reasons why a user mode application might want to create a file. Perhaps the program is creating an error log file to maintain a record of any errors that are encountered during its execution time frame. The application will need an object r

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Object Manager, object header, object body, kernel debugger, ObTypeIndexTable
Summary: The text describes the internal structure of Windows objects, specifically focusing on the role of the object manager in managing headers and bodies. It details how the object header contains metadata like handle counts and types, while the body is specific to the object type. The section also mentions that these structures can be viewed using a kernel debugger.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (4) Every object has the same structure Every object has the same structure object header object header This means that there can be one portion of the system that manages all objects. The appropriately named object manager has the role of maintaining all objects. object body object body - type - name - directory - security descriptor - handle count and list - optional subheaders - unique to the object type 168 Windows Objects (4) The object manager can perform several tasks, such as following: - Create objects and validate that a process has the rights to use that object. - Create the obj

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetLastError, Win32 API, error handling, CreateProcess
Summary: The text describes the GetLastError API function in Windows, explaining its purpose and usage for identifying errors in Win32 API calls. It highlights that GetLastError must be called immediately after a target function to capture the correct error code.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Handling Errors (2) GetLastError GetLastError Gets the last error for calling thread Gets the last error for calling thread // defined in errhandlingapi.h WINBASEAPI _Check_return_ _Post_equals_last_error_ DWORD WINAPI GetLastError( ..... ); 177 Handling Errors (2) The GetLastError API function does not take a single parameter, as you can see with VOID being specified inside the parentheses. Typically, the best and perhaps only times to call this function are when using functions that have a BOOL return type like CreateProcess. If you are checking to see if a Boolean function failed or succeeded based sol

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Handling Errors (2), GetLastError, user-word function
Summary: The unit describes a technical manual page regarding 'Handling Errors (2)' specifically focusing on the user-word function in a Windows environment. It references the GetLastError API for retrieving error information from the calling thread.
Excerpt:
Visual caption: A screenshot of a technical manual page discussing the 'Handling Errors (2)' section, specifically focusing on the user-word function. Visible text: Handling Errors (2); GetLastError; Gets the last error for calling thread; SECO7.3 | Red Teaming: Developing Windows Implants, Shellcode, Command and Control; 177 Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HRESULT, winerror.h, SUCCESSED(hr), FAILED(hr)
Summary: The unit describes how to handle HRESULT error codes in C programming for Windows. It specifies the success and failure conditions using macros from winerror.h.
Excerpt:
Visual caption: A slide from a technical training course about handling HRESULT error codes in C programming. Visible text: Handling Errors (4); Checking HRESULT return types; macros are from winerror.h; SUCCESSED(hr) ((HRESULT)(hr)) == 0; FAILED(hr) ((HRESULT)(hr)) < 0; OFFSECEXAM; 179 Alt/source label:

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: nSize, buffer to allocate, format string, buffer in TCHARS, NULL
Summary: The text describes the API parameters for a buffer allocation and message formatting function, likely related to programming or system interaction.
Excerpt:
nSize is the minimum size of the buffer to allocate if the allocate buffer flag is passed. If the flag is not set, then this should be the size of the receiving buffer in TCHARS. *Arguments are for insert values for a formatted message. %1 is the first argument, %2 would be the second, and so on. Most of the time you can just pass NULL here. 184 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FormatMessage, Handling Errors, FORMAT_MESSAGE_ARGUMENT_ARRAY, FORMAT_MESSAGE_FROM_1MODULE, FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_FROM_SYSTEM
Summary: The unit describes the technical specifications for handling errors in a Windows API context. It specifically details various flags used with the function FormatMessage to manage different types of message sources.
Excerpt:
Visual caption: A slide from a technical presentation or manual detailing the 'Handling Errors' section of a Windows API documentation, specifically focusing on additional flags for the FormatMessage function. Visible text: Handling Errors (8); Additional flags for FormatMessage function; FORMAT_MESSAGE_ARGUMENT_ARRAY; FORMAT_MESSAGE_FROM_1MODULE; FORMAT_MESSAGE_FROM_STRING; FORMAT_MESSAGE_FROM_SYSTEM; A pointer to array of arguments; Module handle with message-table; Pointer to string message definition; System message-table; SEC07 | Red Team Tactics, Developing Windows, Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FormatMessage, dwFlags parameter, FORMAT_MESSAGE_ARGUMENT_ARRAY, FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_FROM_SYSTEM
Summary: This unit describes the various flags available for the FormatMessage function in Windows programming. It details specific flags like FORMAT_MESSAGE_ARGUMENT_ARRAY, FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_STRING, and FORMAT_MESSAGE_FROM_SYSTEM.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Handling Errors (8) Additional flags for FormatMessage function Additional flags for FormatMessage function FORMAT_MESSAGE_ARGUMENT_ARRAY FORMAT_MESSAGE_ARGUMENT_ARRAY A pointer to array of arguments A pointer to array of arguments FORMAT_MESSAGE_FROM_HMODULE FORMAT_MESSAGE_FROM_HMODULE FORMAT_MESSAGE_FROM_STRING FORMAT_MESSAGE_FROM_STRING FORMAT_MESSAGE_FROM_SYSTEM FORMAT_MESSAGE_FROM_SYSTEM Module handle with message-table Module handle with message-table Pointer to string message definition Pointer to string message definition Search system message-table Search system message-table 185 Handling Errors 

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, format message error code lookup, LocalFree
Summary: The unit describes the correct implementation of the FormatMessageA function for system error lookups. It explains the specific flags (FORMAT_MESSAGE_ALLOCATE_BUFFER and FORMAT_MESSAGE_FROM_SECONDARY_SOURCE) required to handle buffer allocation and ignore insertions. It also emphasizes the importance of use-case specific memory management, such as calling LocalFree when a buffer is allocated by the system.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: FormatMessage LPSTR messageBuffer; FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ErrorCode, 0, (LPSTR)&messageBuffer, 0, NULL); printf("%s\n", messageBuffer); LocalFree(messageBuffer); 186 Example: FormatMessge When doing a system error lookup, say from some LRESULT function, you need to make sure you call this function correctly like in the example code above. Since you do not control a system message, you must pass in the FORMAT_MESSAGE_IGNORE_INSERTS flag. The reason for this is the fact that FormatMessage can expect insertio

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateFile, Lab 1.6, sentence: 'Using the CreateFile function create a file and write data to it.'
Summary: The unit describes a laboratory exercise (Lab 1.6) focused on using the CreateFile function in Windows to create a file and write data to it. It references an eWorkbook for further details.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 1.6: CreateFile' describing an exercise to use the CreateFile function. Visible text: Lab 1.6: CreateFile; Using the CreateFile function create a file and write data to it.; Please refer to the eWorkbook for the details of this lab.; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: HRESULT, SUCCEEDED, FAILED, Unit Review
Summary: The unit contains a multiple-choice question and its corresponding answer regarding the correct macros for checking HRESULT function return types in Windows programming. It specifically identifies SUCCEEDED and FAILED as the valid macros.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a multiple-choice question about HRESULT function return types. Visible text: Unit Review Answers; What macro(s) can be used to check HRESULT function return types?; SUCCEEDED / FAILED; GetLastError; STATUS_OK / STATUS_FAILED Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WinDbg, Kernel and User mode structures, user mode process, SANS Institute
Summary: The unit describes the learning objectives for Lab 1.9, which focuses on using the WinDbg debugger. It covers familiarizing with the interface, exploring kernel and user mode structures, and breaking into a user-mode process.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 1.9: It's Me, WinDbg', outlining learning objectives for using the WinDbg debugger. Visible text: Lab 1.9: It's Me, WinDbg; Become familiar with the WinDbg interface.; Explore several Kernel and User mode structures.; Break into a user mode process.; SANS Institute 2024; SEC673 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetVersionEx, OSVERSIONINFO, Windows API, Shellcode
Summary: The unit describes the GetVersionEx function in Windows programming, specifically for retrieving the OS version number. It includes technical details like return types and a C-style structure definition (OSVERSIONINFO).
Excerpt:
Visual caption: A slide from a technical presentation or training material explaining the GetVersionEx function in Windows programming. Visible text: GetVersionEx; GetVersionExA/W; Gathers the OS version number; Has BOOL return type; SEC07 / Red Team Tools: Developing Windows, Shellcode, Command and Control; GetVersionEx(); typedef struct OSVERSIONINFO { ... } Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNativeSystemInfo, SYSTEM_INFO, VOID return type
Summary: The unit describes the 'GetNativeSystemInfo' function in a Windows programming context. It identifies its purpose as gathering system information and notes its return type.
Excerpt:
Visual caption: A slide from a technical presentation or manual explaining the 'GetNativeSystemInfo' function in Windows programming. Visible text: GetNativeSystemInfo; Gathers current system information; Has VOID return type; SYSTEM_INFO; SEC701 / Red Teaming Tools: Developing Windows Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: VirtualAlloc, dwPageSize, lpMinimumApplicationAddress, dwAllocationGranularity, GetLogicalProcessorInformation
Summary: The text describes various system memory and processor information parameters, such as page size, application address ranges, and processor counts. It details specific technical constants used by functions like VirtualAlloc and GetLogicalProcessorInformation.
Excerpt:
wReserved; reserved for supposedly something amazing in the future? Who knows? dwPageSize; the page size along with the granularity of page protection and the commitment. VirtualAlloc relies on this value for its operations. lpMinimumApplicationAddress; this is a pointer to the lowest memory address that will be made accessible to programs and their DLLs. lpMaximumApplicationAddress; the exact opposite as the previous member. dwActiveProcessorMask; the set of processors that are configured on the system in the form of a mask, 0-31 bits each one indicating the processor. dwNumberOfProcessors; how many logical processors are in the current group. GetLogicalProcessorInformation relies on this v

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: VirtualAlloc, dwPageSize, lmimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask, dwNumberOfProcessors, dwAllocationGranularity
Summary: The text describes various system memory and processor information parameters, such as page size, address ranges, and processor counts. It details specific technical constants used by functions like VirtualAlloc and GetLogicalProcessorInformation.
Excerpt:
wReserved; reserved for supposedly something amazing in the future? Who knows? dwPageSize; the page size along with the granularity of page protection and the commitment. VirtualAlloc relies on this value for its operations. lpMinimumApplicationAddress; this is a pointer to the lowest memory address that will be made accessible to programs and their DLLs. lpMaximumApplicationAddress; the exact opposite as the previous member. dwActiveProcessorMask; the set of processors that are configured on the system in the form of a mask, 0-31 bits each one indicating the processor. dwNumberOfProcessors; how many logical processors are in the current group. GetLogicalProcessorInformation relies on this v

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: w_Reserved, w_pageSize, w_memory_information_address, w_limit_address, w_distanceToProcessorMask, w_distanceToProcessor, w_legacy_processor_information, w_memory_region_type
Summary: The unit contains a list of system-level variables and constants related to memory management and processor information. These include terms like page size, memory region types, and processor revisions.
Excerpt:
Visual caption: A page from a technical document or exam solution manual containing definitions of various system-level variables and constants. Visible text: https://linkr.me/offsecexam; w_Reserved; w_pageSize; w_memory_information_address; w_limit_address; w_distanceToProcessorMask; w_distanceToProcessor; w_legacy_processor_information; w_memory_region_type; w_processorLevel; w_processorRevision Alt/source label:

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: KUSER_SHARED_DATA, Undocumented Method, Same VA, Dumping Windows Implants
Summary: The unit describes the KUSER_SHARED_DATA structure in Windows systems as an undocumented method for accessing data. It notes that this structure has a similar virtual address (VA) across most processes and contains many elements.
Excerpt:
Visual caption: A presentation slide titled 'Undocumented Method' describing the KUSER_SHARED_DATA structure in Windows systems. Visible text: Undocumented Method; KUSER_SHARED_DATA; Same VA in almost every process; Holds large number of elements; SEC701 / Red Teaming Tools: Dumping Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: VA 0x7FFE0000, EPROCESS, KPROCESS, KUSER_SHARED_DATA
Summary: The unit contains a review question regarding the memory address 0x7FFE0000 and the associated kernel structures (EPROCESS, KPROCESS, KUSER_SHARED_DATA).
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What structure can be found at VA 0x7FFE0000? What structure can be found at VA 0x7FFE0000? A EPROCESS A EPROCESS B KPROCESS B KPROCESS C KUSER_SHARED_DATA C KUSER_SHARED_DATA 17 Unit Review Questions Q: What structure can be found at VA 0x7FFE0000? A: EPROCESS B: KPROCESS C: KUSER_SHARED_DATA 17 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows kernel, VA 0x7FFE0000, EPROCESS, KPROCESS, Unit Review Questions
Summary: The unit contains a multiple-choice question regarding Windows kernel structures, specifically identifying the location of certain data structures. It lists options such as EPROCESS and KPROCESS.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about Windows kernel structures. Visible text: Unit Review Questions; What structure can be found at VA 0x7FFE0000?; EPROCESS; KPROCESS; KUSER_SHARED_DATA Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: _KPROCESS, Kernel object, thread scheduling, DirectoryTableBase, Virtual Address Translation, EPROCESS
Summary: The text describes the _KPROCESS structure in the Windows kernel, detailing its role in thread scheduling and memory management. It highlights specific members like ThreadListHead and DirectoryTableBase used for internal kernel operations. The section notes that KPROCESS is not exposed via the Object Manager unlike EPROCESS.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control _KPROCESS KPROCESS KPROCESS Kernel object representing processes Kernel object representing processes //0x438 bytes (sizeof) struct _KPROCESS { struct _DISPATCHER_HEADER Header; //0x0 struct _LIST_ENTRY ProfileListHead; //0x18 ULONGLONG DirectoryTableBase; //0x28 struct _LIST_ENTRY ThreadListHead; //0x30 ULONG ProcessLock; //0x40 ULONG ProcessTimerDelay; //0x44 ULONGLONG DeepFreezeStartTime; //0x48 struct _KAFFINITY_EX Affinity; //0x50 ULONGLONG AffinityPadding[12]; //0xf8 struct _LIST_ENTRY ReadyListHead; //0x158 [..snip..] } Used by the lower layer of the Kernel Used by the lower layer of the Kernel 41 

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: KPROCESS, Windows kernel programming, kernel object, lower layer
Summary: The unit describes the KPROCESS structure in the Windows kernel programming context. It identifies it as a kernel object representing processes used by the lower layer of the kernel.
Excerpt:
Visual caption: A slide from a technical presentation about the KPROCESS structure in Windows kernel programming. Visible text: KPROCESS; Kernel object representing processes; Used by the lower layer of the Kernel; SEC.70 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: _KPROCESS, Kernel object, thread scheduling, DirectoryTableBase, Virtual Address Translation, EPROCESS
Summary: The unit describes the _KPROCESS structure in the Windows kernel, detailing its role in thread scheduling and memory management. It highlights specific members like ThreadListHead and DirectoryTableBase used for internal kernel operations. The text notes that KPROCESS is not exposed via the Object Manager unlike EPROCESS.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control _KPROCESS KPROCESS KPROCESS Kernel object representing processes Kernel object representing processes //0x438 bytes (sizeof) struct _KPROCESS { struct _DISPATCHER_HEADER Header; //0x0 struct _LIST_ENTRY ProfileListHead; //0x18 ULONGLONG DirectoryTableBase; //0x28 struct _LIST_ENTRY ThreadListHead; //0x30 ULONG ProcessLock; //0x40 ULONG ProcessTimerDelay; //0x44 ULONGLONG DeepFreezeStartTime; //0x48 struct _KAFFINITY_EX Affinity; //0x50 ULONGLONG AffinityPadding[12]; //0xf8 struct _LIST_ENTRY ReadyListHead; //0x158 [..snip..] } Used by the lower layer of the Kernel Used by the lower layer of the Kernel 41 

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumProcesses, dwRealSize, OpenProcess, PID calculation, C2 infrastructure
Summary: The unit provides a code snippet and explanation for using the EnumProcesses API to retrieve process IDs (PIDs) from memory. It describes how to calculate the number of processes found and iterate through them, while noting that results should be used for logging or C2 communication rather than direct printing.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: EnumProcesses 44 if ( !EnumProcesses(dwProcList, sizeof(dwProcList), &dwRealSize) ) { // fail and bail code here goto fail_and_bail; } // iterate over the results for ( DWORD i = 0; i < dwCount; i++ ) { HANDLE hProc = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcList[i] ); // do something with the handle if OpenProcess succeeds } Example: EnumProcesses This example of EnumProcesses is a small snippet for how to call this API. There is not a lot of code here to make this work because it is a very simple API to use, and it does not return a lot of information. The API will fill out 

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumProcesses, system processes, handle acquisition
Summary: The unit contains a code snippet demonstrating the use of EnumProcesses to iterate through system processes and obtain handles. It is part of a section on developing custom tools for Windows.
Excerpt:
Visual caption: A code snippet showing the use of EnumProcesses to iterate through system processes and obtain their handles. Visible text: Example: EnumProcesses; SEC701 / Red-Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, tlhelp32.h
Summary: The text describes a code snippet using the CreateToolhelp32Snapshot function to capture process information from Windows. It explains how to iterate through processes using Process32First and Process32Next within a do-while loop. The content focuses on technical implementation details of the PROCESSENTRY32 structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: CreateToolhelp32Snapshot 48 Example: CreateToolhelp32Snapshot The example here intentionally omits error checking and the call to Process32First, due to size limitations on the slide. Regardless, the main points are represented here, starting with the call to the CreateToolhelp32Snapshot function on the second line. We are only interested in capturing processes in this snapshot and we are not specifying a process ID as indicated by NULL. The function returns a handle value which is saved off in the snapShot variable. In the full code, this would be error checked against INVALID_HANDLE_VALUE to en

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WTS_EnumerateProcessesAx, Windows Terminal Services, BOOL return type
Summary: The unit describes the WTS_EnumerateProcessesAx API function within the context of Windows Terminal Services. It is part of a course module on developing custom tools for Windows environments.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the WTS_EnumerateProcessesAx API function. Visible text: WTS_EnumerateProcessesAx API; Windows Terminal Services; Has BOOL return type; SEC701 / Red Teaming Tools, Developing Windows Shells, Fileless, Command and Control Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: C code, WTS_EnumProcessSessions, cross-session process injection
Summary: The unit contains a code snippet in C language demonstrating the use of the WTS_EnumProcessSessions API. It is intended to demonstrate how to identify cross-session process injection.
Excerpt:
Visual caption: A screenshot of a C code snippet demonstrating the use of the `WTS_EnumProcessSessions` API for identifying cross-session process injection. Visible text: Example: WTSEnumProcessSessionsE; SEC07 - Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION, NTSTATUS return type, buffer allocation
Summary: The text describes the NtQuerySystemInformation API, a native function used to retrieve system information including process details. It explains the technical parameters of the function, such as SystemInformationClass and the buffer management required for calling it.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NtQuerySystemInformation API NtQuerySystemInformation NtQuerySystemInformation Grabs specific information about the system Grabs specific information about the system NTSTATUS NtQuerySystemInformation( _In_ SYSTEM_INFORMATION_CLASS InfoCls, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength ); // enum entry SystemProcessInformation // SYSTEM_PROCESS_INFORMATION struct Has NTSTATUS return type Has NTSTATUS return type 56 NtQuerySystemInformation API As mentioned on the previous slide, the NtQuerySystemInformation function is a native function as annotated by 

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION, buffer size calculation, native API
Summary: The unit describes the NtQuerySystemInformation API, a native function used to retrieve system and process information. It details the parameters of the function, including SystemInformationClass and the system information buffer management.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NtQuerySystemInformation API NtQuerySystemInformation NtQuerySystemInformation Grabs specific information about the system Grabs specific information about the system NTSTATUS NtQuerySystemInformation( _In_ SYSTEM_INFORMATION_CLASS InfoCls, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength ); // enum entry SystemProcessInformation // SYSTEM_PROCESS_INFORMATION struct Has NTSTATUS return type Has NTSTATUS return type 56 NtQuerySystemInformation API As mentioned on the previous slide, the NtQuerySystemInformation function is a native function as annotated by 

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: C programming, SYSTEM_PROCESS_INFORMATION struct, definition of members
Summary: The unit contains a C programming code snippet defining the structure of SYSTEM_PROCESS_INFORMATION. It describes the member definitions within this specific data structure.
Excerpt:
Visual caption: A screenshot of a C programming structure definition for SYSTEM_PROCESS_INFORMATION struct. Visible text: SYSTEM_PROCESS_INFORMATION Struct; typedef struct _SYSTEM_PROCESS_INFORMATION; Here is the definition of the members... Alt/source label:

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SYSTEM_PROCESS_INFORMATION, x64dbg documentation, C-style struct, process information
Summary: The unit provides a C-style struct definition for SYSTEM_PROCESS_INFORMATION, as documented by x64dbg developers. It lists various fields such as thread counts, memory sizes, and process identifiers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control SYSTEM_PROCESS_INFORMATION Struct typedef struct _SYSTEM_PROCESS_INFORMATION { ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; // Since Vista ULONG HardFaultCount; // Since Windows 7 ULONG NumberOfThreadsHighWatermark; // Since Windows 7 ULONGLONG CycleTime; // Since Windows 7 LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; UNICODE_STRING ImageName; [..SNIP..] HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId; SYSTEM_THREAD_INFORMATION Threads[1]; [..SNIP..] 57 SYSTEM_PROCESS_INFORMATION Struct Here is the struct as documented by the

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SYSTEM_PROCESS_INFORMATION, x64dbg documentation, memory offsets, stronger-typed data structures
Summary: The text defines the SYSTEM_PROCESS_INFORMATION structure used in Windows memory forensics and debugging. It provides a technical definition of fields such as thread counts, memory usage, and process identifiers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control SYSTEM_PROCESS_INFORMATION Struct typedef struct _SYSTEM_PROCESS_INFORMATION { ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; // Since Vista ULONG HardFaultCount; // Since Windows 7 ULONG NumberOfThreadsHighWatermark; // Since Windows 7 ULONGLONG CycleTime; // Since Windows 7 LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; UNICODE_STRING ImageName; [..SNIP..] HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId; SYSTEM_THREAD_INFORMATION Threads[1]; [..SNIP..] 57 SYSTEM_PROCESS_INFORMATION Struct Here is the struct as documented by the

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SYSTEM_PROCESS_INFORMATION, SIZE_T, LARGE_INTEGER, memory usage metrics
Summary: The text contains a C-style struct definition for SYSTEM_PROCESS_INFORMATION, which includes various memory and operation counters like QuotaPeakNonPagedPoolUsage and ReadOperationCount.
Excerpt:
SIZE_T QuotaPeakNonPagedPoolUsage; SIZE_T QuotaNonPagedPoolUsage; SIZE_T PagefileUsage; SIZE_T PeakPagefileUsage; SIZE_T PrivatePageCount; LARGE_INTEGER ReadOperationCount; LARGE_INTEGER WriteOperationCount; LARGE_INTEGER OtherOperationCount; LARGE_INTEGER ReadTransferCount; LARGE_INTEGER WriteTransferCount; LARGE_INTEGER OtherTransferCount; SYSTEM_THREAD_INFORMATION Threads[1]; } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION; 58 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: C/C++ source code, memory management, thread management, system information structures
Summary: The unit contains a screenshot of C or C++ source code snippets related to memory and thread management. It lists several system-related variables such as QuotaPeakNonPagedPoolUsage, PageLifeSize, and various operation counts.
Excerpt:
Visual caption: A screenshot of a C or C++ source code snippet showing variable declarations for memory and thread management. Visible text: SIZE_T; QuotaPeakNonPagedPoolUsage; QuotaNonPagedPoolUsage; PageLifeSize; PeakPageLifeSize; FreePagesCount; LARGE_INTEGER; ReadOperationCount; WriteOperationCount; OtherOperationCount; ReadTransferCount; WriteTransferCount; OtherTransferCount; SYSTEM_THREAD_INFORMATION; SYSTEM_PROCESS_INFORMATION Alt/source label:

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SYSTEM_PROCESS_INFORMATION, Quotas, PagefileUsage, ReadOperationCount, WriteOperationCount
Summary: The text contains a C-style struct definition for system process information, including memory usage metrics and I/O operation counts. It lists various `SIZE_T` and `LARGE_INTEGER` types used to represent resource consumption data.
Excerpt:
SIZE_T QuotaPeakNonPagedPoolUsage; SIZE_T QuotaNonPagedPoolUsage; SIZE_T PagefileUsage; SIZE_T PeakPagefileUsage; SIZE_T PrivatePageCount; LARGE_INTEGER ReadOperationCount; LARGE_INTEGER WriteOperationCount; LARGE_INTEGER OtherOperationCount; LARGE_INTEGER ReadTransferCount; LARGE_INTEGER WriteTransferCount; LARGE_INTEGER OtherTransferCount; SYSTEM_THREAD_INFORMATION Threads[1]; } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION; 58 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FindFirstFileA, search handle, HANDLE return type
Summary: The unit describes the FindFirstFileA API function used for obtaining search handles in Windows. It includes syntax details and a usage example.
Excerpt:
Visual caption: A presentation slide describing the FindFirstFileA API function, including its syntax and usage example. Visible text: FindFirstFile API; FindFirstFileA(); Used to obtain a search handle; Has HANDLE return type; SEC701 / Red Team Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:
