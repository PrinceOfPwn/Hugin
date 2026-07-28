# Atlas Material — enumeration (part 1)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: enum
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.9  Key cues: Meterpreter ls command, Windows API usage, directory listing implementation, platform agnostic function
Summary: The unit describes the implementation of directory listing functionality in Windows implants, referencing Metasploit's Meterpreter 'ls' command as a model. It covers the use of standard Windows APIs for this purpose and explains why it is a necessary feature for operators to navigate file systems.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Directory Enumeration Directory listings is nothing new. Directory listings is nothing new. Many popular frameworks have implants that can perform directory listings. The famous Meterpreter session from the Metasploit Framework offers operators the ability for perform a directory listing. Native Windows binaries also perform directory listings, so it is not a behavior that should be categorized as malicious or suspicious. 75 Directory Enumeration Directory enumeration is a very simple feature to implement programmatically, and it can be done in a number of different ways. MSDN provides a few simple exampl

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.9  Key cues: NetLocalGroupEnum, local group information, level parameter, LOCALGROUP_INFO_0, LOCALGROUP_I1
Summary: The unit describes the NetLocalGroupEnum API, which is used to enumerate local or remote group information. It details the function's parameters, specifically highlighting the level parameter for retrieving different types of group data structures.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NetLocalGroupEnum API NetLocalGroupEnum() NetLocalGroupEnum() Used to obtain local group information Used to obtain local group information NET_API_STATUS NET_API_FUNCTION NetLocalGroupEnum( _In_ LPCWSTR servername, _In_ DWORD level, _Out_ LPBYTE *bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ PDWORD_PTR resumehandle ); Has NET_API_STATUS return type Has NET_API_STATUS return type 95 NetLocalGroupEnum API In addition to gathering user information, we can gather information about the groups that might be present on a local or remote system. The NetLocalGroupEn

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, process enumeration
Summary: The unit describes the CreateToolhelp32Snapshot API for enumerating processes, modules, and threads on a Windows system. It details specific flags like TH32CS_SNAPPROCESS and mentions related functions such as Process32First and Process32Next.
Excerpt:
Create APIs (5) The CreateToolhelp32Snapshot API can be used to aid in enumerating processes on the local system. It will create a snapshot of the process and return a handle to that snapshot. You can use the handle to perform your queries and extract the information you are looking for, like a specific process name or module name the process loaded. The function is relatively easy to call since it only takes two parameters of the same type. The dwFlags parameter is the most important as it dictates what data should be collected in the snapshot. There are seven flags that can be passed here, but the most interesting flag for us is TH32CS_SNAPPROCESS because, as the name implies, all processe

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, process enumeration
Summary: The unit describes the CreateToolhelp32Snapshot API for enumerating processes, modules, and threads on a Windows system. It details specific flags like TH32CS_SNAPPROCESS and associated functions such as Process32First and Process32Next.
Excerpt:
Create APIs (5) The CreateToolhelp32Snapshot API can be used to aid in enumerating processes on the local system. It will create a snapshot of the process and return a handle to that snapshot. You can use the handle to perform your queries and extract the information you are looking for, like a specific process name or module name the process loaded. The function is relatively easy to call since it only takes two parameters of the same type. The dwFlags parameter is the most important as it dictates what data should be collected in the snapshot. There are seven flags that can be passed here, but the most interesting flag for us is TH32CS_SNAPPROCESS because, as the name implies, all processe

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows API, process enumeration, EnumProcesses, CreateToolhelp32Snapshot, WTSEnum100
Summary: The unit contains a slide comparing three specific Windows API functions (EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumProcess) for the purpose of process enumeration.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Documented Methods' comparing three Windows API functions for process enumeration. Visible text: Documented Methods; EnumProcesses; CreateToolhelp32Snapshot; WTSEnumProcess; SANS Institute Alt/source label:

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumProcesses, process IDs, BOOL return type, SEC703
Summary: The unit describes the EnumProcesses API function used for identifying process IDs on a Windows system. It specifies the buffer size and required parameters for the enumeration.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the EnumProcesses API function and its parameters. Visible text: EnumProcesses API; EnumProcesses(); Used to obtain the process IDs on the system; Has BOOL return type; SEC703 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumProcesses API, process enumeration, lpidProcess, cb, lpcbNeeded, DWORD
Summary: This unit describes the EnumProcesses API used for retrieving process IDs on a Windows system. It details the function signature, its three arguments (lpidProcess, cb, lpcbNeeded), and explains that it returns only PIDs without detailed information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control EnumProcesses API EnumProcesses() EnumProcesses() Used to obtain the process IDs on the system Used to obtain the process IDs on the system BOOL EnumProcesses( _Out_ DWORD *lpidProcess, _In_ DWORD cb, _Out_ LPDWORD lpcbNeeded ); Has BOOL return type Has BOOL return type 43 EnumProcesses API As mentioned on the previous slide, the EnumProcesses API is incredibly easy to use when it comes to process enumeration. The API can be chosen over the other options if you do not care about getting detailed information about the processes on the system. The API will only return the process IDs of each process object 

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, process enumeration
Summary: The text describes the CreateToolhelp32Snapshot API for enumerating processes, heaps, and threads in Windows. It details how to use Process32First and Process32Next functions in conjunction with a snapshot handle to iterate through process information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control CreateToolhelp32Snapshot API CreateToolhelp32Snapshot() CreateToolhelp32Snapshot() Creates a snapshot of a process Creates a snapshot of a process HANDLE CreateToolhelp32Snapshot( _In_ DWORD dwFlags, _In_ DWORD th32ProcessID ); BOOL Process32First( _In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe ); BOOL Process32Next( _In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe ); Can take snapshots of heaps and threads as well Can take snapshots of heaps and threads as well 47 CreateToolhelp32Snapshot API The CreateToolhelp32Snapshot API was discussed during the Create APIs module during Section 1, but it is be

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, 32CS_SNAPPROCESS, process enumeration, static view
Summary: The unit describes the CreateToolhelp32Snapshot API for enumerating processes, heaps, and threads in Windows. It details how to use Process32First and Process32Next functions to iterate through a snapshot's contents. The text highlights the importance of the understanding that snapshots are static views.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control CreateToolhelp32Snapshot API CreateToolhelp32Snapshot() CreateToolhelp32Snapshot() Creates a snapshot of a process Creates a snapshot of a process HANDLE CreateToolhelp32Snapshot( _In_ DWORD dwFlags, _In_ DWORD th32ProcessID ); BOOL Process32First( _In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe ); BOOL Process32Next( _In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe ); Can take snapshots of heaps and threads as well Can take snapshots of heaps and threads as well 47 CreateToolhelp32Snapshot API The CreateToolhelp32Snapshot API was discussed during the Create APIs module during Section 1, but it is be

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TlHelp32.h
Summary: The unit describes the use of CreateToolhelp32Snapshot and Process32First/Next to enumerate processes on Windows. It explains how to capture a snapshot of all processes and iterate through them using the PROCESSENTRY32 structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: CreateToolhelp32Snapshot 48 Example: CreateToolhelp32Snapshot The example here intentionally omits error checking and the call to Process32First, due to size limitations on the slide. Regardless, the main points are represented here, starting with the call to the CreateToolhelp32Snapshot function on the second line. We are only interested in capturing processes in this snapshot and we are not specifying a process ID as indicated by NULL. The function returns a handle value which is saved off in the snapShot variable. In the full code, this would be error checked against INVALID_HANDLE_VALUE to en

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows Terminal Service, process enumeration, SEC701, label: What's the Point?
Summary: The unit describes a slide from a SEC701 course explaining why using Windows Terminal Service for process enumeration is beneficial. It highlights that this method provides an alternative way to enumerate processes.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'What's the Point?' explaining the purpose of using Windows Terminal Service to enumerate processes. Visible text: What's the Point?; SEC701: Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control; The point of the lab was to explore another method to enumerate processes. Using the Windows Terminal Service is nice because you have the potential to query re Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: process enumeration, kernel structures, module summary
Summary: The unit describes a summary slide of a module covering process enumeration techniques. It covers the reasons for enumerating processes, kernel structures used to represent them, and various methods for enumeration.
Excerpt:
Visual caption: A slide summarizing the content of a module on process enumeration techniques. Visible text: Module Summary; Discussed the reason for enumerating processes; Explored the structures the kernel uses to represent processes; Explored various methods for process enumeration; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: undocumented API, process enumeration, EnumProcesses(), WTS_enumerateProcessesEx(), NtQuerySystemInformation()
Summary: The unit contains a slide showing the answers to questions regarding undocumented APIs for process enumeration. It lists specific functions like EnumProcesses(), WTS_enumerateProcessesEx(), and NtQuerySystemInformation().
Excerpt:
Visual caption: A slide from a SANS Institute course showing the answer to a question about undocumented APIs for process enumeration. Visible text: Unit Review Answers; What undocumented API can be used to enumerate processes?; EnumProcesses(); WTS_enumerateProcessesEx(); NtQuerySystemInformation() Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NetLocalGroupEnum, local group information, level parameter, LOCALGROUP_INFO_0, LOCALGROUP_INFO_1
Summary: The unit describes the NetLocalGroupEnum API, which is used to enumerate local or remote group information. It details the function's parameters, specifically highlighting the level parameter for retrieving different types of group data structures.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NetLocalGroupEnum API NetLocalGroupEnum() NetLocalGroupEnum() Used to obtain local group information Used to obtain local group information NET_API_STATUS NET_API_FUNCTION NetLocalGroupEnum( _In_ LPCWSTR servername, _In_ DWORD level, _Out_ LPBYTE *bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ PDWORD_PTR resumehandle ); Has NET_API_STATUS return type Has NET_API_STATUS return type 95 NetLocalGroupEnum API In addition to gathering user information, we can gather information about the groups that might be present on a local or remote system. The NetLocalGroupEn

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NetLocalGroupEnum, local group information, level parameter, LOCALGROUP_INFO_0, LOCALGROUP_INFO_1
Summary: The unit describes the NetLocalGroupEnum API, which is used to enumerate local or remote group information. It details the function's parameters, specifically highlighting the level parameter for determining the type of structure returned.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control NetLocalGroupEnum API NetLocalGroupEnum() NetLocalGroupEnum() Used to obtain local group information Used to obtain local group information NET_API_STATUS NET_API_FUNCTION NetLocalGroupEnum( _In_ LPCWSTR servername, _In_ DWORD level, _Out_ LPBYTE *bufptr, _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_ PDWORD_PTR resumehandle ); Has NET_API_STATUS return type Has NET_API_STATUS return type 95 NetLocalGroupEnum API In addition to gathering user information, we can gather information about the groups that might be present on a local or remote system. The NetLocalGroupEn

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NetLocalGroupEnum, local group information, NET_API_STATUS
Summary: The unit describes the NetLocalGroupEnum API function used for retrieving local group information. It specifies the return type as NET_API_STATUS and references a course module on developing Windows implants.
Excerpt:
Visual caption: A slide from a SANS Institute course explaining the NetLocalGroupEnum API function. Visible text: NetLocalGroupEnum API; NetLocalGroupEnum(); Used to obtain local group information; Has NET_API_STATUS return type; SEC701 / Red-Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: imaccess.h, lmuse.h, lmuse.h, NetGetGroupUsers, NetUserEnum, NetLocalGroupGetMembers, NetUserGetInfo
Summary: The unit contains a list of specific Windows API headers and functions used for querying user and group information. It references the header files imaccess.h and lmuse.h and several network-related enumeration functions.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Additional Information' listing relevant headers and APIs for querying user and group information. Visible text: Additional Information; imaccess.h; lmuse.h; NetGetGroupUsers; NetUserEnum; NetLocalGroupGetMembers; NetUserGetInfo; SEC679 Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Service Enumeration, Awareness, Purpose, SEC679
Summary: The unit contains a presentation slide about service enumeration, detailing its importance and purpose in the context of security testing.
Excerpt:
Visual caption: A presentation slide titled 'Service Enumeration' outlining the reasons for enumerating services, specifically focusing on awareness and purpose. Visible text: Service Enumeration; Awareness; Purpose; Why enumerate services?; SEC679 Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServiceStatusEx, QueryServiceStatusEx, SC_QUERY_STATUS_PROCESS_INFO
Summary: The unit describes specific Windows API functions (EnumServiceStatusEx and QueryServiceStatusEx) used for querying service status information. It highlights the technical details of these APIs, including the SC_QUERY_STATUS_PROCESS_INFO bitmask.
Excerpt:
Visual caption: A slide titled 'Service Enumeration APIs' showing two C-style function signatures for querying service information. Visible text: Service Enumeration APIs; EnumServiceStatusEx; QueryServiceStatusEx; SC_QUERY_STATUS_PROCESS_INFO Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatusExA, QueryServiceStatusEx, Win32 APIs, service enumeration, C programming
Summary: The text describes two Win32 APIs, EnumServicesStatusExA and QueryServiceStatusEx, for programmatically enumerating and querying the status of Windows services in C. It explains that while command-line tools like sc.exe or Get-Service exist, these specific APIs provide more detailed information when used together.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Enumeration APIs EnumServicesStatusExA EnumServicesStatusExA BOOL EnumServicesStatusExA( SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName ); QueryServiceStatusEx QueryServiceStatusEx BOOL QueryServiceStatusEx( SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded ); 105 Service Enumeration APIs How exactly can we go about enumerating services? You might know how to do this via the

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatusExA, QueryServiceCusEx, Win32 API, service enumeration, SC_ENUM_PROCESS_INFO, SC_STATUS_PROCESS_INFO
Summary: The text describes two Win32 APIs, EnumServicesStatusExA and QueryServiceStatusEx, for programmatically enumerating and querying the status of Windows services in C. It explains that while command-line tools like sc.exe or Get-Service exist, these specific APIs provide more detailed information when used together.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Enumeration APIs EnumServicesStatusExA EnumServicesStatusExA BOOL EnumServicesStatusExA( SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName ); QueryServiceStatusEx QueryServiceStatusEx BOOL QueryServiceStatusEx( SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded ); 105 Service Enumeration APIs How exactly can we go about enumerating services? You might know how to do this via the

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: COM interface, ITaskScheduler::Enum, IEnumWorkItems::Next, CoInitialize, CoCreateInstance, Task Scheduler
Summary: The unit describes the technical process of enumerating scheduled tasks on a Windows system using COM interfaces. It details specific methods like ITaskScheduler::Enum and IEnumWorkItems::Next, along with a high-level step-by-step procedure for implementation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Enumerating Tasks v. 1.0 Using COM to enumerate Tasks Using COM to enumerate Tasks ITaskScheduler::Enum ITaskScheduler::Enum IEnumWorkItems::Next IEnumWorkItems::Next HRESULT Enum( _Out_ IEnumWorkItems **ppEnumWorkItems ); HRESULT Next( _In_ ULONG celt, _Out_ LPWSTR **rgpwszNames, _Out_ ULONG *pceltFetched ); 107 Enumerating Tasks v. 1.0 For us to enumerate tasks on a system we must turn to COM. There is an exposed interface called TaskScheduler, specifically ITaskScheduler, that has a method called Enum, which will allow us to create an enumeration object. Then, with that object in hand, we can create IE

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Enumerating Tasks v. 1.0, ITaskScheduler::Enum, IEnumWorkItems::Next, SANC SECF07
Summary: The unit describes a presentation slide about enumerating scheduled tasks using COM interfaces like ITaskScheduler::Enum and IEnumWorkItems::Next.
Excerpt:
Visual caption: A presentation slide titled 'Enumerating Tasks v. 1.0' describing the use of COM to enumerate tasks. Visible text: Enumerating Tasks v. 1.0; ITaskScheduler::Enum; IEnumWorkItems::Next; SANS SECF07 Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: network interface APIs, GetAdapterApps, GetNumberOfInterfaces, Unit Review
Summary: The unit contains a review question regarding network interface APIs used to enumerate network information. It lists specific functions like GetAdapterAddresses, GetNumberOfInterfaces, and GetIpStatistics.
Excerpt:
Visual caption: A screenshot of a study guide page showing a multiple-choice question about network interface APIs. Visible text: Unit Review Answers; What API includes logical interfaces in its results?; GetAdapterAddresses(); GetNumberOfInterfaces(); GetIpStatistics() Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatusEx, SCM database, service enumeration, API parameter breakdown
Summary: The text describes the EnumServicesStatusEx API for enumerating services in the SCM database. It details the specific parameters, such as hSCManager, InfoLevel, dwServiceType, and dwServiceState, required to query service status.
Excerpt:
EnumServicesStatusEx Before you can query the status of a service, you must first find a service to query, which can be done using the EnumServicesStatusEx API. All the services in the SCM database will be enumerated with this API. Let us take a look at the parameters for it. hSCManager is the SC_HANDLE returned from the OpenService or CreateService APIs. The handle should at least have the SC_MANAGER_ENUMERATE_SERVICE access mask. InfoLevel has only one option, SC_ENUM_PROCESS_INFO. dwServiceType is a filter for a certain service type. Typically, you would pass in SERVICE_WIN32 here to indicate that you want all service types. dwServiceState gives you the option to enable finer filtering by

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatusEx, SCM database, Boolean return type, SEC701
Summary: The unit describes the `EnumServicesStatusEx` function within the Windows programming context. It highlights its role in enumerating services from the System Control Manager (SCM) database and notes its Boolean return type.
Excerpt:
Visual caption: A slide from a technical training course about the EnumServicesStatusEx function in Windows programming. Visible text: EnumServicesStatusEx; Enumerate services in SCM database; Has a Boolean return type; SEC701 | Red Team Toolkit: Debugging Windows API...; EnumServicesStatusEx() Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: EnumServicesStatusEx, SCM database, service enumeration, buffer size, pcbBytesNeeded
Summary: The text describes the EnumServicesStatusEx API used to enumerate services in the SCM database. It details specific parameters such as hSCManager, InfoLevel, dwServiceType, and dwServiceState for filtering and buffer management.
Excerpt:
EnumServicesStatusEx Before you can query the status of a service, you must first find a service to query, which can be done using the EnumServicesStatusEx API. All the services in the SCM database will be enumerated with this API. Let us take a look at the parameters for it. hSCManager is the SC_HANDLE returned from the OpenService or CreateService APIs. The handle should at least have the SC_MANAGER_ENUMERATE_SERVICE access mask. InfoLevel has only one option, SC_ENUM_PROCESS_INFO. dwServiceType is a filter for a certain service type. Typically, you would pass in SERVICE_WIN32 here to indicate that you want all service types. dwServiceState gives you the option to enable finer filtering by

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: pszGroupName, filter services, enumerate all groups
Summary: The text describes a specific parameter, pszGroupName, used in the context of filtering services by their group name during enumeration.
Excerpt:
pszGroupName could be used to filter the services according to their group name. NULL here means ignore any group a service is a part of and enumerate all groups. © 2024 Jonathan Reiter 107 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: portgroup, filter services, term -NULL, enumerate all
Summary: The text describes how to use the 'portgroup' parameter in a tool to filter services by group name or list all services if set to NULL.
Excerpt:
Visual caption: A slide containing text describing the use of a 'portgroup' parameter to filter services by group name. Visible text: SANS Institute 2024; https://linktr.ee/offsecexam; portgroupName could be used to filter the services according to their group name. NULL, here means ignore any group a service is a part of and enumerate all gro Alt/source label:

=== UNIT 30 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: namemash.py, username generation, brute-force, SSH_MSG_USER_AUTHENTICATION_FAILURE
Summary: The unit describes a process for generating potential usernames from a list of full names using the namemash script and subsequently attempting to brute-force login credentials via SSH.
Excerpt:
Visual caption: A series of terminal screenshots showing the process of generating possible usernames from a list of full names using a script and then attempting to brute-force login credentials. Visible text: root@kali:~$ cat names.txt; namemash.py; root@kali:~$ /opt/namemash.py names.txt > possible-usernames.txt; PS C:\> pscp root@kali:/root/possible-usernames.txt .; SSH_MSG_USER_AUTHENTICATION_FAILURE Alt/source label:

=== UNIT 31 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Active Directory forest, NetBIOS name, parent domain, child domain, MailSniper, password spraying
Summary: The text describes how to identify users in different domains within an Active Directory forest. It explains the relationship between a parent domain (CYBER) and a child domain (DEV) based on NetBIOS names. The section also mentions using MailSniper for password spraying against identified accounts via OWA, EWS, and EAS.
Excerpt:
This output shows one valid result for CYBER\iyates. You can run this again and target -Domain DEV, which will also find valid results for: • DEV\bfarmer • DEV\jking • DEV\jadams This requires a little bit of explaining. cyberbotic.io is the root of the Active Directory forest, who's NetBIOS name is CYBER. But cyberbotic.io has a child domain called dev.cyberbotic.io, who's NetBIOS name is DEV. From this, we can ascertain that iyates is a user in the parent domain; whilst bfarmer, jking and jadams exist in the child domain. However, without just guessing at domain names, we don't have a reliable way of knowing DEV ever existed. You may be able to find some clues from your OSINT such as leake

=== UNIT 32 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Parent Child Relationships, Finding the Parent, parent_id, parent_id_field, query.all(), find_by(id: 1)
Summary: The unit describes technical documentation regarding identifying parent IDs for objects within a database or system. It highlights specific fields like 'parent_id' and 'parent_id_field' and mentions methods such as 'query.all()' and 'find_by(id: 1)'.
Excerpt:
Visual caption: A screenshot of a technical documentation page explaining how to find parent IDs for objects in a database or system. Visible text: Parent Child Relationships; Finding the Parent; Parent ID; parent_id; parent_id_field; query.all(); find_by(id: 1); Analytics; Overview Alt/source label:

=== UNIT 33 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Python Script, ENUMERATE, Local Enumeration, pycurl, requests, urllib.request
Summary: The unit contains a screenshot of a Python script used for local enumeration and information gathering. It lists several libraries such as pycurl, requests, and urllib.request.
Excerpt:
Visual caption: A screenshot of a Python script used for local enumeration and information gathering during a penetration testing engagement. Visible text: Python Script; ENUMERATE; Local Enumeration; print(f'\u001b[32m'); python-mpitch; pycurl; requests; urllib.request Alt/source label:

=== UNIT 34 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerView, domain enumeration, powershell -import
Summary: The unit describes a terminal screenshot showing the execution of a PowerShell command to import PowerView.ps1 into a session. It notes that PowerView is a standard tool for domain enumeration.
Excerpt:
Visual caption: A screenshot of a terminal window showing the execution of a PowerShell command to import PowerView.ps1. Visible text: PowerView; PowerView has long been the de-facto tool for domain enumeration.; beacon> powershell -import C:\Tools\PowerSploit\Becon\PowerView.ps1 Alt/source label:

=== UNIT 35 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerShell, Get-DomainOU, Active Directory, organization units, sort -Property Name
Summary: The unit contains a PowerShell command to list and enumerate organizational units (OUs) in an Active Directory environment. It includes specific properties like Name, Domain Controllers, and various server tiers.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of a PowerShell command to list and sort organizational units (OUs) in an Active Directory environment. Visible text: Get-DomainOU; Search for all organization units (OUs) or specific OU objects.; beacone. powershell Get-DomainOU -Properties Name | sort -Property Name; name; Domain Controllers; Servers; Tier 1; Tier 2; Workstations; COMPLETE & CONTINUE -> Alt/source label:

=== UNIT 36 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: PowerShell, Get-DomainGPOLocalGroup, GPO modification, local group membership
Summary: The unit describes a PowerShell script used to identify Group Policy Objects (GPOs) that modify local group memberships. It specifically highlights the output of `Get-DomainGPOLocalGroup` which lists GPOs and their associated groups.
Excerpt:
Visual caption: A screenshot of a command-line interface showing the output of a PowerShell script used to identify GPOs that modify local group memberships. Visible text: Get-DomainGPOLocalGroup; Returns all GPOs that modify local group membership through Restricted Groups or Group Policy Preferences.; beacon.e powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName; GPODisplayName; GroupName; Tier 1 Admins; DEV\User_peers; Tier 2 Admins; DEV\IT Line Support Alt/source label:

=== UNIT 37 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Hashcat, hybrid modes 6 and 7, wordlist, mask, combinator
Summary: The unit describes Hashcat's hybrid modes 6 and 7 for password cracking. It explains how these modes combine wordlists with masks to crack passwords.
Excerpt:
Visual caption: A screenshot of a tutorial page explaining Hashcat hybrid modes 6 and 7. Visible text: Hybrid; Hashcat modes 6 and 7 are hybrid's based on wordlists, masks and the combinator.; You specify a wordlist and mask on the command line...; Where:; The hybrid mask + wordlist, mode (-a 7) is practically identical... Alt/source label:

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, Process32First, Process32Next, process enumeration
Summary: This unit describes the CreateToolhelp32Snapshot API for enumerating processes, modules, and threads on a Windows system. It details the use of the TH32CS_SNAPPROCESS flag and mentions related functions like Process32First and Process32Next.
Excerpt:
Create APIs (5) The CreateToolhelp32Snapshot API can be used to aid in enumerating processes on the local system. It will create a snapshot of the process and return a handle to that snapshot. You can use the handle to perform your queries and extract the information you are looking for, like a specific process name or module name the process loaded. The function is relatively easy to call since it only takes two parameters of the same type. The dwFlags parameter is the most important as it dictates what data should be collected in the snapshot. There are seven flags that can be passed here, but the most interesting flag for us is TH32CS_SNAPPROCESS because, as the name implies, all processe

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Dynamic-linked Libraries, Dumpbin utility, PEview, PE-bear, CFF Explorer
Summary: The unit describes various tools used to analyze and inspect the contents of Dynamic-linked Libraries (DLLs). It specifically lists Dumpbin, PEview, PE-bear, and CFF Explorer.
Excerpt:
Visual caption: A presentation slide titled 'Dynamic-linked Libraries (3)' listing tools for analyzing DLL files. Visible text: Dynamic-linked Libraries (3); How do you see what is inside of a DLL?; Dumpbin utility; PEview; PE-bear; CFF Explorer Alt/source label:

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.85  Key cues: EnumServicesStatusExA, QueryServiceStatusEx, Win32 APIs
Summary: The text describes two Win32 APIs, EnumServicesStatusExA and QueryServiceStatusEx, for programmatically enumerating and querying the status of Windows services in C. It explains that while WMI queries can also be used, these specific service-specific APIs are preferred for this context.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Service Enumeration APIs EnumServicesStatusExA EnumServicesStatusExA BOOL EnumServicesStatusExA( SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName ); QueryServiceStatusEx QueryServiceStatusEx BOOL QueryServiceStatusEx( SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded ); 105 Service Enumeration APIs How exactly can we go about enumerating services? You might know how to do this via the
