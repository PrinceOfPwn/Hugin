# Atlas Material — edr-evasion (part 6)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: evasion
Units: 29

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: antivirus detection engines, static vs dynamic analysis, YARA rules, bypass techniques (delaying, encryption), Bitdefender scanning engine
Summary: The text describes the components of antivirus (AV) detection engines, specifically focusing on static and dynamic analysis. It explains how static signatures like YARA rules are used to detect threats before execution, but can be bypassed by changing code bases. It also mentions techniques for bypassing dynamic analysis, such as delaying execution or encryption.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 66 Detection Engines There are multiple components that make up a solution. There are multiple components that make up a solution. Static Static Dynamic Dynamic Signature matching engine before runtime using rules similar to YARA Executing samples in a virtualized container to detect malicious behavior Scan Scan Some AVs offer a scanning engine with various modes like Automatic/Custom Detection Engines When it comes to protecting users and the system, it is best if the AV solution can detect the threat before it has a chance to execute, naturally. At this stage, this would fall under static analysis where

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: parent process, evasion, explorer.exe, process tree, detection avoidance
Summary: The text discusses the importance of selecting an appropriate parent process for a malicious implant to blend in with normal system behavior. It explains how certain processes, like browsers or office applications, spawning unexpected child processes (e.g., PowerShell) should trigger alerts in security software. The section introduces the concept of using Windows features to manipulate the parent process to appear as explorer.exe.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 67 Choose Your Parent Process One method that can be used as an addition to avoid detection is to choose your parent process. There are certain processes that should never spawn other processes, including PowerShell or CMD prompt; browsers, or office applications. What if you could choose your parent process? What if you could choose your parent process? Choose Your Parent Process If you were developing an AV solution, one of the checks you might implement is the relationship between processes. Watching explorer.exe spawn a number of processes of all kinds is fine but watching a browser process spawn a Po

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: custom loader, PE image mapping, memory execution, evasion techniques, non-traditional PE layout
Summary: The text defines custom loaders as tools designed to map and execute PE images in memory while incorporating evasion techniques. It explains that custom loaders can handle non-traditional PE structures to bypass scanners that rely on standard layouts. The section highlights the difference between a loader's basic function and a specific 'custom' loader built for stealth.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 5 What Is It A custom loader can be used to load PE images, among other items, and execute them. This custom loading can be done locally within the current address space of a process or remotely by crossing process boundaries. Load what you want, when you want Load what you want, when you want What Is It What exactly is a loader? What is a custom loader? Is there even a difference? Not really. One could jump in and argue that a loader simply maps a PE image into memory and executes it. A custom loader, on the other hand, was built with evasion in mind in addition to mapping and executing a PE image. Custo

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: parent process manipulation, sponsoring process, API calls, evasion
Summary: The unit describes a technique for manipulating process attributes to choose or spoof a parent process. It highlights that this method requires only two API calls and is intended to use as an evasion tactic.
Excerpt:
Visual caption: A presentation slide titled 'Choose Your Parent Process Implementation' showing a diagram and pseudo-code for manipulating process attributes. Visible text: Choose Your Parent Parent Process Implementation; Are you my parent?; Requires just two API calls; Helps avoid detection; SANS Institute 2024; SEC701 / Red Team Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: InitializeProcThreadAttributeList, UpdateProcThreadAttribute, parent process ID, buffer size, process heap, avoid detection
Summary: The unit describes the implementation of 'Choose Your Parent Process' using the InitializeProcThreadAttributeList and UpdateProcThreadAttribute APIs. It explains how to use these specific API calls to set a process attribute list before creating a new process, which helps avoid detection by preventing suspicious parent-process relationships.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 68 Choose Your Parent Process: Implementation Are you my parent? Are you my parent? Requires just two API calls Requires just two API calls //// make pointer variable PPROC_THREAD_ATTRIBUTE_LIST pAttrList; //// get the buffer size needed InitializeProcThreadAttributeList(...); //// make the real call InitializeProcThreadAttributeList(...); //// update the attribute before creation UpdateProcThreadAttribute(...); Helps avoid detection Helps avoid detection Choose Your Parent Process: Implementation As with any new method, there will be a new set of APIs and/or structures to understand. Everything that is a

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: UpdateProcThreadAttribute, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, parent PID, attribute list
Summary: The text describes the UpdateProcThreadAttribute API, specifically focusing on its use for modifying process or thread attributes. It details the parameters of the function, including the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute key.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 70 UpdateProcThreadAttribute UpdateProcThreadAttributeList UpdateProcThreadAttributeList Updates an attribute in the attribute list for the process/thread Updates an attribute in the attribute list for the process/thread BOOL UpdateProcThreadAttribute( LPPROC_THREAD_ATTRIBUTE_LIST lpAttrList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize ); Has BOOL return type Has BOOL return type UpdateProcThreadAttribute The UpdateProcThreadAttribute API is used when you want to update an attribute for a process or a thread. This would typically not be cal

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: AV/EDR bypass, detection avoidance, cloud engine submission, reverse engineering, security tool development
Summary: The text discusses the advantages and disadvantages of developing custom bypasses for AV/EDR solutions. It highlights that while bypassing allows for longer persistence, it requires significant time and research and carries risks like sample submission to cloud engines.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 71 The Pros and Cons Just like anything else, there is an upside and downside. Just like anything else, there is an upside and downside. Pros Pros Cons Cons Avoid detection and live longer Sample not submitted to cloud engine Time consuming Requires knowledge of inner workings Cons Cons Could lose sample to AV/EDR cloud engine if not properly cut off from internet The Pros and Cons Bypassing AV/EDR solutions is not an easy task. There are a few pros and cons with doing so and some of the pros might seem obvious. One obvious pro is that by finding a bypass, our presence on the target will not be detected. 

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: AV/EDR bypass, persistence, publicly available methods, SEC670
Summary: The unit contains a summary slide from a SANS course regarding techniques for bypassing AV/EDR systems. It highlights the importance of learning evasion techniques to maintain persistence on target systems.
Excerpt:
Visual caption: A summary slide from a SANS Institute course on bypassing AV/EDR systems. Visible text: Module Summary; Learned bypassing AV/EDR should be a requirement; Discussed how avoiding detection allows you to remain on target longer; Discovered several publicly available methods exist to assist with avoidance; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: AV/EDR bypass, persistence, publicly available methods
Summary: The unit provides a summary of the module's content regarding bypassing AV/EDR systems to maintain persistence on a target system. It highlights that while only a few methods are used in this course, many other publicly available techniques exist.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 72 Module Summary Learned bypassing AV/EDR should be a requirement Learned bypassing AV/EDR should be a requirement Discussed how avoiding detection allows you to remain on target longer Discussed how avoiding detection allows you to remain on target longer Discovered several publicly available methods exist to assist with avoidance Discovered several publicly available methods exist to assist with avoidance Module Summary In this module, we discussed a small number of methods that can be taken to help you bypass detection and stay on target longer. There are many more that are out there and perhaps you w

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: WSASocket, SOCKET return type, AF_INET, SOCK_STREAM, IPPROTO_TCP, WsaGetLastError
Summary: The text describes the WSASocket API used for creating and configuring sockets in Windows environments. It details specific parameters like address family, type, and protocol, while also mentioning its relationship to the standard socket() function.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 WSASocket WSASocket() WSASocket() Used to create a socket Used to create a socket SOCKET WSAAPI WSASocketA( int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags ); // sister function socket(); Has SOCKET return type Has SOCKET return type WSASocket Before we can try to callback and check in with our C2 Listening Post, we need to create a socket and set it up accordingly. The WSASocket API is what we will be using to get this done. The return type is a SOCKET, so we will be saving this in a predefined SOCKET variable type. If the API fails, it will return the value 

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Reflective DLL Injection, RDI, manual mapping, system loader
Summary: The unit describes Reflective DLL Injection (RDI) as a technique for loading DLLs into memory without being listed by the system loader. It explains how RDI allows manual mapping of a source DLL into a target's virtual address space.
Excerpt:
Visual caption: A presentation slide and accompanying text describing Reflective DLL Injection (RDI) as a stealthy technique for loading DLLs into memory without being listed by the system loader. Visible text: Let Your Reflection Show; Reflective DLL Injection (RDI); With Reflective DLL Injection, or RDI, the source DLL is manually mapped into the target's virtual address space. This means that the full path of the DLL will Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PE-sieve, defensive tools, offensive tools, detection
Summary: The text describes the purpose of a lab exercise involving defensive tools like PE-sieve to detect offensive tool effects. It highlights the understanding of how defensive measures are designed against specific red teaming techniques.
Excerpt:
What’s the Point? The point of the lab was to become familiar with defensive tools that were made to detect the effects our offensive tools. PE-sieve is one of many tools that has this kind of capability. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 30 30 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Blending In, Windows 10, SEC679
Summary: The unit describes a strategy for evading detection by blending in with legitimate system files. It features a image of a Windows file explorer window to illustrate this concept.
Excerpt:
Visual caption: A slide titled 'Blending In' showing a screenshot of a Windows file explorer window and accompanying text about the strategy of blending in with files. Visible text: Blending In; On this Windows 10; SEC679: Red Teaming Tools, Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: User32.dll, AppCert, AppInit, RunOnce
Summary: The unit contains a multiple-choice question regarding evasion techniques specifically for processes linked against User32.dll.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about evasion techniques for processes linked against User32.dll. Visible text: Unit Review Questions; What technique should be used for processes linked against User32.dll?; AppCert; AppInit; RunOnce Alt/source label:

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: hiding a service, evade detection, SANS SEC4079
Summary: The unit describes a slide from a SANS course discussing the technique of hiding a service to evade detection. It is part of a module on red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A slide from a SANS course titled 'What Else?' discussing the technique of hiding a service to evade detection. Visible text: What Else?; Hiding a service; SEC4079 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: UnhookTheHook, Bitdefender, eWorkbook
Summary: The text describes Lab 5.2, titled 'UnhookTheHook', which focuses on testing unhooking skills against specific security software like Bitdefender. It directs users to the eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 55 Lab 5.2: UnhookTheHook Test your unhooking skills against Bitdefender and others. Test your unhooking skills against Bitdefender and others. Please refer to the eWorkbook for the details of the lab. Lab 5.2: UnhookTheHook Please refer to the eWorkbook for the details of this lab. 55 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: UnhookTheHook, Bitdefender, eWorkbook
Summary: The text describes a lab exercise titled 'UnhookTheHook' focused on testing unhooking skills against specific antivirus software like Bitdefender. It directs users to the eWorkbook for further details.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 55 Lab 5.2: UnhookTheHook Test your unhooking skills against Bitdefender and others. Test your unhooking skills against Bitdefender and others. Please refer to the eWorkbook for the details of the lab. Lab 5.2: UnhookTheHook Please refer to the eWorkbook for the details of this lab. 55 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: unhooking, blind security product, review questions
Summary: The unit contains a review question regarding the effectiveness of unhooking hooks to blind security products. It provides multiple-choice options for determining if such an action removes all introspection capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 61 Unit Review Questions Does unhooking hooks truly blind a Security Product? Does unhooking hooks truly blind a Security Product? A Yes, because it will no longer have introspection into that process A Yes, because it will no longer have introspection into that process B Depends, there could be a kernel module still watching B Depends, there could be a kernel module still watching C Only if it's Defender C Only if it's Defender Unit Review Questions Q: Does unhooking hooks truly blind a Security Product? A: Yes, because it will no longer have introspection into that process B: Depends, there could be a k

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: unhooking, blind security product, 100% visibility, kernel module
Summary: The unit contains a review question regarding the effectiveness of unhooking hooks to blind security products. It provides multiple-choice options for determining if such an action removes all introspection from a process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 61 Unit Review Questions Does unhooking hooks truly blind a Security Product? Does unhooking hooks truly blind a Security Product? A Yes, because it will no longer have introspection into that process A Yes, because it will no longer have introspection into that process B Depends, there could be a kernel module still watching B Depends, there could be a kernel module still watching C Only if it's Defender C Only if it's Defender Unit Review Questions Q: Does unhooking hooks truly blind a Security Product? A: Yes, because it will no longer have introspection into that process B: Depends, there could be a k

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: unhooking hooks, blind security product, security product introspection, kernel module
Summary: The unit contains a review question regarding the effectiveness of unhooking hooks to blind security products. It provides multiple-choice options for whether this action removes introspection or if kernel modules might still monitor the process.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 62 Unit Review Answers Does unhooking hooks truly blind a Security Product? Does unhooking hooks truly blind a Security Product? A Yes, because it will no longer have introspection into that process A Yes, because it will no longer have introspection into that process B Depends, there could be a kernel module still watching B Depends, there could be a kernel module still watching C Only if it's Defender C Only if it's Defender Unit Review Answers Q: Does unhooking hooks truly blind a Security Product? A: Yes, because it will no longer have introspection into that process B: Depends, there could be a kerne

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Why Avoid Detection?, AV/EDR solutions, SEC701
Summary: The unit contains a slide discussing the importance of avoiding detection by antivirus (AV) and endpoint detection and response (EDR) systems. It highlights that these solutions can reveal an attacker's presence during red teaming operations.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Why Avoid Detection?' discussing AV/EDR solutions. Visible text: Why Avoid Detection?; AV/EDR solutions can give away your presence.; SEC701 | Red-Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: AMSI, PowerShell, patching amsi.dll, Lab 5.4
Summary: The unit describes a lab exercise focused on patching the Antimalware Scan Interface (AMSI) in PowerShell processes. It covers identifying how data is passed for analysis and exploring various methods to patch amsi.dll.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 138 Lab 5.4: AMSI No More Patch a PowerShell process with amsi.dll loaded Observe how data is being passed in for analysis Explore various methods to patch amsi.dll Lab 5.4: AMSI No More Please refer to the eWorkbook for the details of this bootcamp challenge. 138 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: PE-sieve, defensive tools, offensive tools
Summary: The text describes the purpose of a lab exercise involving defensive tools like PE-sieve to detect offensive tool effects. It highlights the importance of understanding how defenders use these tools.
Excerpt:
What’s the Point? The point of the lab was to become familiar with defensive tools that were made to detect the effects our offensive tools. PE-sieve is one of many tools that has this kind of capability. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 30 30 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: Blending In, Windows 10, SEC679, Red Teaming Tools
Summary: The unit describes a strategy for blending in with legitimate system files to avoid detection. It features a slide titled 'Blending In' and mentions the context of developing Windows implants.
Excerpt:
Visual caption: A slide titled 'Blending In' showing a screenshot of a Windows file explorer window and accompanying text about the strategy of blending in with files. Visible text: Blending In; On this Windows 10; SEC679: Red Teaming Tools, Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.8  Key cues: GflagsX, gflags.exe, Pavel Yosifovich, github.com/zodiacon
Summary: The text introduces GflagsX, a modern version of the gflags.exe utility created by Pavel Yosifovich. It highlights its improved features and updated GUI.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 84 GflagsX A modern take on the original gflags.exe utility A modern take on the original gflags.exe utility Pavel Yosifovich created a new version of gflags that offers a great new look to the tool. Check out his repo for this and other awesome tools: https://github.com/zodiacon. GflagsX Pavel Yosifovich has been recreating several tools with better features and a nicer looking GUI. Pavel has been posting them publicly on his repo https://github.com/zodiacon. If you get a chance, check them out for yourself. 84 © 2024 Jonathan Reiter © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.e

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: AMSI, patching amsi.dll, PowerShell, Lab 5.4
Summary: The unit describes Lab 5.4, which focuses on patching the amsi.dll library within a PowerShell process to bypass AMSI protections. It outlines objectives such as observing data flow and exploring various patching methods.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 138 Lab 5.4: AMSI No More Patch a PowerShell process with amsi.dll loaded Observe how data is being passed in for analysis Explore various methods to patch amsi.dll Lab 5.4: AMSI No More Please refer to the eWorkbook for the details of this bootcamp challenge. 138 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: IAT Hooking, function pointer hooking, read-only, PAGE_READWRITE, 1. Parse PE headers, 2. Locate module, 3. Offer a pointer, 4. Change page protections
Summary: The unit describes the mechanism of IAT Hooking, defining it as function pointer hooking where an array of addresses is modified. It outlines a technical process for making the read-only IAT table writeable and overwriting function pointers with new addresses.
Excerpt:
Visual caption: A presentation slide explaining the concept of IAT Hooking, including its definition and a step-by-step process. Visible text: IAT Hooking; An array of addresses; AKA: Function pointer hooking; IAT is typically read-only. Must make it writeable; 1. Parse PE headers to find import table; 2. Locate module that implements the hooked function; 3. Offer a pointer to the function in the found module; 4. Change page protections to PAGE_READWRITE save old permissions; 5. Overwrite function pointer; 6. Restore previous page protections Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: UnhookTheHook, Bitdefender, eWorkbook reference, SANS SEC679
Summary: This unit contains a slide from a SANS Institute course regarding Lab 5.2: UnhookTheHook. It instructs students to refer to the eWorkbook for specific details on testing unhooking skills against antivirus software like Bitdefender.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 5.2: UnhookTheHook' providing instructions to refer to the eWorkbook for details. Visible text: Lab 5.2: UnhookTheHook; Test your unhooking skills against Bitdefender and others.; Please refer to the eWorkbook for the details of the lab.; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.8  Key cues: Objectives, avoid detection, SEC679, Red Teaming Tools
Summary: The unit contains a slide outlining the learning objectives for a module on avoiding detection in red teaming. It lists goals related to understanding why detection is avoided and exploring methods for evasion.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Objectives' listing three main goals for the module. Visible text: Objectives; Our objectives for this module are:; Discuss reasons to avoid detection; Explore various methods to avoid detection; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:
