# Atlas Material — recon (part 7)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 17

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: network information, gathering, SEC670, NIC configurations
Summary: The unit outlines the learning objectives for a module focused on gathering network information and NIC configurations. It serves as intended learning outcomes for students in a Red Teaming tools course.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Gather network information Gather NIC configurations 116 Objectives The objectives for this module are to determine how to gather any network information we can, as well as the target’s NIC configurations. 116 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: GetAdapterAddresses(), GetNumberOfInterfaces(), GetIpStatistics(), network adapter IP address
Summary: The unit contains a review question regarding Windows APIs for retrieving network adapter IP addresses. It lists three specific API functions: GetAdapterAddresses(), GetNumberOfInterfaces(), and GetIpStatistics().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What API will give you an IP address for a network adapter? What API will give you an IP address for a network adapter? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 126 Unit Review Questions Q: What API will give you an IP address for a network adapter? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 126 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: GetAdapterLetters(), GetNumberOfInterfaces(), GetIpStatistics(), Unit Review Answers
Summary: The unit contains a review section with questions and answers regarding Windows APIs for network adapter information. It specifically identifies GetAdapterAddresses() as the primary API for retrieving an IP address.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What API will give you an IP address for a network adapter? What API will give you an IP address for a network adapter? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 127 Unit Review Answers Q: What API will give you an IP address for a network adapter? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 127 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: VirtualAlloc, dwPageSize, lmimumApplicationAddress, lmMaximumApplicationAddress, dwActiveProcessorMask, dwAllocationGranularity
Summary: The text describes various system memory and processor information parameters, such as page size, address ranges, and processor counts. It lists specific Windows API-related constants and properties like dwAllocationGranularity and dwNumberOfProcessors.
Excerpt:
wReserved; reserved for supposedly something amazing in the future? Who knows? dwPageSize; the page size along with the granularity of page protection and the commitment. VirtualAlloc relies on this value for its operations. lpMinimumApplicationAddress; this is a pointer to the lowest memory address that will be made accessible to programs and their DLLs. lpMaximumApplicationAddress; the exact opposite as the previous member. dwActiveProcessorMask; the set of processors that are configured on the system in the form of a mask, 0-31 bits each one indicating the processor. dwNumberOfProcessors; how many logical processors are in the current group. GetLogicalProcessorInformation relies on this v

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: GetAdapterAddresses(), GetNumberOfInterfaces(), GetIpStatistics(), logical interfaces
Summary: The unit contains a review question regarding Windows network interface APIs. It specifically asks which API returns logical interfaces.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What API includes logical interfaces in its results? What API includes logical interfaces in its results? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 128 Unit Review Questions Q: What API includes logical interfaces in its results? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 128 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: registry information, learning objectives, SANS SEC670
Summary: The unit describes the learning objectives for a module focused on gathering registry information from Windows systems. It specifies that students will learn what types of data can be stored in and accessible via the Windows Registry.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Gather registry information 131 Objectives The objectives for this module are to understand what information can be found in the registry. 131 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: HKEY_USERS, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_CURRENT_CONFIG, Windows handles, Registry root keys
Summary: The unit describes the five predefined root keys of the Windows Registry (HKEY_USERS, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, and HKEY_CURRENT_CONFIG). It explains that these are handles to keys and clarifies the difference between links/merged views versus direct keys. It also provides a familiarization with basic Registry structure.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (3) There are five predefined root keys the system uses. There are five predefined root keys the system uses. HKEY_USERS HKEY_USERS HKEY_CLASSES_ROOT* HKEY_CLASSES_ROOT* HKEY_CURRENT_USER* HKEY_CURRENT_USER* HKEY_LOCAL_MACHINE HKEY_LOCAL_MACHINE HKEY_CURRENT_CONFIG* HKEY_CURRENT_CONFIG* An * denotes the key is a link or a merged view of keys. An * denotes the key is a link or a merged view of keys. 135 The Registry (3) You might have noticed that each root key starts with an H. This is because the root key names are Windows handles (H) to keys (KEY); hence the name HKEY. The key names on the 

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: Windows Registry, registry keys, thought process, summary
Summary: The unit provides an overview of the Windows Registry, covering its structure and the types of information contained within it. It serves as a summary for Module 156.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the registry and information found within it. Discussed the registry and information found within it. 156 Module Summary In this module, we discussed what the registry is, many of the keys, and some of the information that can be found within the registry. 156 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: Lab 2.1, OS Info, gathering information, eWorkbook reference
Summary: The unit describes Lab 2.1, which focuses on gathering information about the operating system and target. It directs users to an eWorkbook for specific lab details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 2.1: OS Info Gathering information about the OS and target Gathering information about the OS and target Please refer to the eWorkbook for the details of this lab. 14 Lab 2.1: OS Info Please refer to the eWorkbook for the details of the lab. 14 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: process enumeration, snapshot limitation, sentence structure
Summary: The text discusses the limitations of a specific process enumeration method, noting that it may miss newly created processes after a snapshot is taken. It highlights the importance of understanding these limitations in red teaming tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 50 What’s the Point? The point of the lab was to explore one of the more popular methods of enumerating processes. The major downside to this method is you can miss newly created processes after the snapshot has been taken. 50 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: Windows Terminal Services, enumerate processes, remote targets
Summary: The unit discusses the purpose of using Windows Terminal Services to enumerate processes on remote targets. It highlights the utility of this method for remote enumeration.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 54 What’s the Point? The point of the lab was to explore another method to enumerate processes. Using the Windows Terminal Services is nice because you have the potential to query remote targets. 54 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: undocumented API, enumerate processes, EnumProcesses(), WTSEnumerateProcessEx(), NtQuerySystemInformation()
Summary: The unit contains a review question regarding the identification of undocumented APIs for process enumeration. It lists three specific functions: EnumProcesses(), WTSEnumerateProcessEx(), and NtQuerySystemInformation().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What undocumented API can be used to enumerate processes? What undocumented API can be used to enumerate processes? A EnumProcesses() A EnumProcesses() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 61 Unit Review Questions Q: What undocumented API can be used to enumerate processes? A: EnumProcesses() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 61 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: OpenProcess(), WTSEnumerateProcessesEx(), NtQuerySystemInformation(), process PID
Summary: The unit contains review questions regarding Windows APIs for process information retrieval. It specifically lists OpenProcess(), WTSEnumerateProcessesEx(), and NtQuerySystemInformation() as potential methods.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What API could be used to obtain more information about a process given only its PID? What API could be used to obtain more information about a process given only its PID? A OpenProcess() A OpenProcess() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 63 Unit Review Questions Q: What API could be used to obtain more information about a process given only its PID? A: OpenProcess() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 63 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecex

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: OpenProcess(), WTSEnumerateProcessesEx(), NtQuerySystemInformation(), process information, PID
Summary: This unit contains a review section with questions and answers regarding Windows APIs for process information retrieval. It specifically identifies OpenProcess(), WTSEnumerateProcessesEx(), and NtQuerySystemInformation() as methods to obtain process details from a PID.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What API could be used to obtain more information about a process given only its PID? What API could be used to obtain more information about a process given only its PID? A OpenProcess() A OpenProcess() B WTSEnumerateProcessesEx() B WTSEnumerateProcessesEx() C NtQuerySystemInformation() C NtQuerySystemInformation() 64 Unit Review Questions Q: What API could be used to obtain more information about a process given only its PID? A: OpenProcess() B: WTSEnumerateProcessEx() C: NtQuerySystemInformation() 64 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: C:\Program Files, C:\Program Files (x86), 32-bit and 64-bit applications, installation paths
Summary: The unit describes standard Windows directory conventions for locating 32-bit and 64-bit applications, specifically C:\Program Files and C:\Program Files (x86). It also notes that some applications may be installed in non-standard locations like the root of the C: drive or user-specific folders.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Where to Look? Where can you find 32-bit and 64-bit applications? Where can you find 32-bit and 64-bit applications? C:\Program Files C:\Program Files It should be safe to assume that entries found in this folder are 64-bit applications C:\Program Files (x86) C:\Program Files (x86) C:\ C:\ A similar assumption can be made for entries found in this location; that they will be 32-bit applications Some apps, like Python, install at the root system drive, although not very common 67 Where to Look? One of the goals of recon is to determine what applications are installed on your target. Maybe you want to see i

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: course roadmap, OS info gathering, process enumeration, directory walking, tool development
Summary: The unit lists a course roadmap for gathering operating system information, including service packs, process enumeration, and directory walks. It also outlines the development of a custom tool for directory listing as part of a Windows implant.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 73 In this module, we will discuss a feature for enumerating directories. Many impla

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: sc.exe, sdshow, security descriptor, BITS service
Summary: The text describes how to use the sc.exe command-line utility to view a service's security descriptor using the sdshow flag. It explains that these descriptors can be interpreted using SDDL and ace_strings.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 52 Viewing Security Descriptors Viewing Security Descriptors Using the sc.exe command-line utility, we can view a service’s security descriptor. Running the program with the /? argument shows the help menu. From the help menu we can see the argument sdshow and its description: Displays a service’s security descriptor. This is what we want. From here we can choose a service, like BITS, and see what its security descriptor currently is. With the information we now know about SDDL and ace_strings, we can interpret the output without too much headache. 52 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f
