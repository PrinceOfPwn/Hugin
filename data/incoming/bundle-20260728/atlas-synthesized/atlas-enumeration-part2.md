# Atlas Material — enumeration (part 2)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: enum
Units: 20

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: COM, ITaskScheduler, IEnumWorkItems, Enum, Next, TaskScheduler
Summary: The unit describes the use of COM interfaces (ITaskScheduler and IEnumWorkItems) to enumerate scheduled tasks on a Windows system. It outlines the specific methods, such as Enum and Next, and provides a high-level step-by-step process for implementation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Enumerating Tasks v. 1.0 Using COM to enumerate Tasks Using COM to enumerate Tasks ITaskScheduler::Enum ITaskScheduler::Enum IEnumWorkItems::Next IEnumWorkItems::Next HRESULT Enum( _Out_ IEnumWorkItems **ppEnumWorkItems ); HRESULT Next( _In_ ULONG celt, _Out_ LPWSTR **rgpwszNames, _Out_ ULONG *pceltFetched ); 107 Enumerating Tasks v. 1.0 For us to enumerate tasks on a system we must turn to COM. There is an exposed interface called TaskScheduler, specifically ITaskScheduler, that has a method called Enum, which will allow us to create an enumeration object. Then, with that object in hand, we can create IE

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, process enumeration
Summary: The text describes the CreateToolhelp32Snapshot API for enumerating processes, heaps, and threads. It details how to use Process32First and Process32Next functions in a loop to iterate through process information from a snapshot.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control CreateToolhelp32Snapshot API CreateToolhelp32Snapshot() CreateToolhelp32Snapshot() Creates a snapshot of a process Creates a snapshot of a process HANDLE CreateToolhelp32Snapshot( _In_ DWORD dwFlags, _In_ DWORD th32ProcessID ); BOOL Process32First( _In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe ); BOOL Process32Next( _In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe ); Can take snapshots of heaps and threads as well Can take snapshots of heaps and threads as well 47 CreateToolhelp32Snapshot API The CreateToolhelp32Snapshot API was discussed during the Create APIs module during Section 1, but it is be

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: CreateToolh32Snapshot, Process32Next, PROCESSENTRY32, TlHelp32.h
Summary: The unit describes the use of CreateToolhelp32Snapshot and Process32First/Next to enumerate processes on Windows. It explains how to iterate through a snapshot using a process entry structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: CreateToolhelp32Snapshot 48 Example: CreateToolhelp32Snapshot The example here intentionally omits error checking and the call to Process32First, due to size limitations on the slide. Regardless, the main points are represented here, starting with the call to the CreateToolhelp32Snapshot function on the second line. We are only interested in capturing processes in this snapshot and we are not specifying a process ID as indicated by NULL. The function returns a handle value which is saved off in the snapShot variable. In the full code, this would be error checked against INVALID_HANDLE_VALUE to en

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: WTSEnumerateProcess, enumerate processes, statement of lab purpose
Summary: The unit describes Lab 2.4, which focuses on using the WTSEnumerateProcesses function to enumerate processes on a Windows system. It references an eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.4: WTSEnum Using WTSEnumerateProcesses, enumerate processes on the system. Using WTSEnumerateProcesses, enumerate processes on the system. Please refer to the eWorkbook for the details of the lab. 53 Lab 2.4: WTSEnum Please refer to the eWorkbook for the details of the lab. 53 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: Meterpreter ls command, Windows API implementation, directory listing functionality, BFS article reference
Summary: The unit discusses the implementation of directory listing functionality in Windows implants, noting that it is a common feature in frameworks like Metasploit's Meterpreter. It explains that while not inherently malicious, it is easy to implement using standard Windows APIs and provides a link to technical documentation for BFS.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Directory Enumeration Directory listings is nothing new. Directory listings is nothing new. Many popular frameworks have implants that can perform directory listings. The famous Meterpreter session from the Metasploit Framework offers operators the ability for perform a directory listing. Native Windows binaries also perform directory listings, so it is not a behavior that should be categorized as malicious or suspicious. 75 Directory Enumeration Directory enumeration is a very simple feature to implement programmatically, and it can be done in a number of different ways. MSDN provides a few simple exampl

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: NetUserEnum, LPCWSTR servername, USER_INFO_0 through USER_INFO_20, NetApiBufferFree
Summary: The text describes the NetUserEnum API, which is used to retrieve information about all user accounts on a local or remote system. It details specific parameters such as servername, level (with various levels of detail), and buffer management for the function.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NetUserEnum API NetUserEnum() NetUserEnum() Used to obtain information about all user accounts Used to obtain information about all user accounts NET_API_STATUS NET_API_FUNCTION NetUserEnum( _In_ LPCWSTR servername, _In_ DWORD level, _In_ DWORD filter, _Out_ LPBYTE *bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ PDWORD resume_handle ); Has NET_API_STATUS return type Has NET_API_STATUS return type 93 NetUserEnum API Getting account information about a single user account is fine, but it is also great to get account information about all user accounts on a syst

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: EnumServicesStatusEx, SCM database, service enumeration, buffer size, pcbBytesNeeded
Summary: The text describes the EnumServicesStatusEx API used to enumerate services in the SCM database. It details specific parameters such as hSCManager, InfoLevel, dwServiceType, and dwServiceState for filtering and buffer management.
Excerpt:
EnumServicesStatusEx Before you can query the status of a service, you must first find a service to query, which can be done using the EnumServicesStatusEx API. All the services in the SCM database will be enumerated with this API. Let us take a look at the parameters for it. hSCManager is the SC_HANDLE returned from the OpenService or CreateService APIs. The handle should at least have the SC_MANAGER_ENUMERATE_SERVICE access mask. InfoLevel has only one option, SC_ENUM_PROCESS_INFO. dwServiceType is a filter for a certain service type. Typically, you would pass in SERVICE_WIN32 here to indicate that you want all service types. dwServiceState gives you the option to enable finer filtering by

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: EnumServicesStatusEx, SCM database, Windows API, debugging
Summary: The unit describes the `EnumServicesStatusEx` function within the Windows programming context. It highlights its purpose for enumerating services in the SCM database and notes its Boolean return type.
Excerpt:
Visual caption: A slide from a technical training course about the EnumServicesStatusEx function in Windows programming. Visible text: EnumServicesStatusEx; Enumerate services in SCM database; Has a Boolean return type; SEC701 | Red Team Toolkit: Debugging Windows API...; EnumServicesStatusEx() Alt/source label:

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: portgroup, filter services, term -NULL, enumerate all
Summary: The unit describes how to use the 'portgroup' parameter in a tool to filter services by group name or ignore filtering using a NULL value.
Excerpt:
Visual caption: A slide containing text describing the use of a 'portgroup' parameter to filter services by group name. Visible text: SANS Institute 2024; https://linktr.ee/offsecexam; portgroupName could be used to filter the services according to their group name. NULL, here means ignore any group a service is a part of and enumerate all gro Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: EnumProcesses, enumerate processes, procenum, Lab 2.2
Summary: This unit describes Lab 2.2, which focuses on using the EnumProcesses function to enumerate processes on a Windows system. It references an eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.2: ProcEnum Using EnumProcesses, enumerate the processes on the system. Using EnumProcesses, enumerate the processes on the system. Please refer to the eWorkbook for the details of the lab. 45 Lab 2.2: ProcEnum Please refer to the eWorkbook for the details of the lab. 45 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: ProcEnum, EnumProcesses, Lab 2.2
Summary: The unit describes a laboratory exercise involving the tool 'ProcEnum' and the use of 'EnumProcesses' to list system processes.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Lab 2.2: ProcEnum' which instructs the student to refer to an eWorkbook for details. Visible text: Lab 2.2: ProcEnum; Using EnumProcesses, enumerate the processes on the system.; Please refer to the eWorkbook for the details of the lab. Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: CreateToolhelp32Snapshot, enumerate processes, report to eWorkbook
Summary: The unit contains a slide from a SANS Institute course regarding Lab 2.3: CreateToolhelp. It instructs users to use the CreateToolhelp32Snapshot function to enumerate system processes and refers them to an eWorkbook for further details.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 2.3: CreateToolhelp' which instructs the user to refer to an eWorkbook for lab details. Visible text: Lab 2.3: CreateToolhelp; Using CreateToolhelp32Snapshot, enumerate the processes on the system.; Please refer to the eWorkbook for the details of the lab. Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WTSEnumerateProcesses, enumerate processes, Lab 2.4, WTSEnum
Summary: The unit describes Lab 2.4, which focuses on using the WTSEnumerateProcesses function to enumerate processes on a Windows system. It references an eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.4: WTSEnum Using WTSEnumerateProcesses, enumerate processes on the system. Using WTSEnumerateProcesses, enumerate processes on the system. Please refer to the eWorkbook for the details of the lab. 53 Lab 2.4: WTSEnum Please refer to the eWorkbook for the details of the lab. 53 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: WTSEnum, WTSEnumerateProcesses, lab instruction
Summary: The unit contains a slide from a SANS course regarding Lab 2.4: WTSEnum. It provides instructions for using the WTSEnumerateProcesses function to enumerate system processes.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 2.4: WTSEnum' providing instructions to refer to an eWorkbook for details. Visible text: Lab 2.4: WTSEnum; Using WTSEnumerateProcesses, enumerate processes on the system.; Please refer to the eWorkbook for the details of the lab.; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: undocumented API, process enumeration, EnumProcesses(), WTSEnumerateProcesses10(), NtQuerySystemInformation()
Summary: The unit contains a multiple-choice question regarding the identification of undocumented APIs for process enumeration. It lists three specific functions: EnumProcesses(), WTSEnumerateProcessesEx(), and NtQuerySystemInformation().
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about undocumented APIs for process enumeration. Visible text: Unit Review Questions; What undocumented API can be used to enumerate processes?; EnumProcesses(); WTSEnumerateProcessesEx(); NtQuerySystemInformation() Alt/source label:

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: pszGroupName, service filtering, group name, null value handling
Summary: The text describes a configuration parameter 'pszGroupName' used to filter services by group name during enumeration. It notes that a NULL value indicates ignoring the filter and enumerating all groups.
Excerpt:
pszGroupName could be used to filter the services according to their group name. NULL here means ignore any group a service is a part of and enumerate all groups. © 2024 Jonathan Reiter 107 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: combinator attack, wordlist merging, password candidate generation
Summary: The unit describes the common 'combinator' technique for generating password candidates by merging entries from two separate wordlists. It specifically illustrates this with examples like 'purplemonkey' and 'purple-monkey'.
Excerpt:
Visual caption: A tutorial page explaining the 'combinator' attack method for generating password candidates from two wordlists. Visible text: Combinator; The combinator attack combines the entries from two dictionaries into single-word candidates.; purplemonkey; purpledishwasher; purple-monkey Alt/source label:

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: EnumProcesses, enumerate processes, procenum
Summary: The unit describes a lab exercise involving the use of EnumProcesses to enumerate system processes. It references an eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.2: ProcEnum Using EnumProcesses, enumerate the processes on the system. Using EnumProcesses, enumerate the processes on the system. Please refer to the eWorkbook for the details of the lab. 45 Lab 2.2: ProcEnum Please refer to the eWorkbook for the details of the lab. 45 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: undocumented API, enumerate processes, EnumProcesses(), WTSEnumerateProcessEx(), NtQuerySystemInformation()
Summary: The unit contains a review section for the SEC670 course, specifically focusing on undocumented APIs used to enumerate processes in Windows. It lists three specific functions: EnumProcesses(), WTSEnumerateProcessEx(), and NtQuerySystemInformation().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What undocumented API can be used to enumerate processes? What undocumented API can be used to enumerate processes? A EnumProcesses() A EnumProcesses() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 62 Unit Review Answers Q: What undocumented API can be used to enumerate processes? A: EnumProcesses() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 62 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: lmaccess.h, lmuse.h, NetGroupGetUsers, NetUseEnum, NetLocalGroupGetMembers, NetUseGetInfo
Summary: The unit discusses additional headers and APIs, specifically lmaccess.h and lmuse.h, for querying user and group information. It notes that the list provided is a sample and suggests implementing logic to gather more robust survey tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Additional Information Additional headers and APIs that could be of interest Additional headers and APIs that could be of interest lmaccess.h lmaccess.h lmuse.h lmuse.h NetGroupGetUsers NetGroupGetUsers NetUseEnum NetUseEnum NetLocalGroupGetMembers NetLocalGroupGetMembers NetUseGetInfo NetUseGetInfo 96 Additional Information The lmaccess and the lmuse header files offer additional APIs that might be of interest when querying user and user group information. The listing on the slide is not an exhaustive list but merely a small sampling of what else is out there that can be used. Depending on the informatio
