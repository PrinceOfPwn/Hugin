# Atlas Material — recon (part 6)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: recon
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: programmatically enumerate, directory enumeration, querying subdirectories
Summary: The unit describes a lab exercise focused on programmatically enumerating directories and subdirectories to locate specific files. It is part of the Red Teaming Tools course.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 84 What’s the Point? The point of this lab was the explore how you can programmatically enumerate a directory to find a file, and if you had time, enumerate any subdirectories. 84 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: programmatically enumerate, directory enumeration, subdirectories, SANS SEC670
Summary: The text describes a lab exercise focused on programmatically enumerating directories and subdirectories to locate specific files. It is part of the SANS SEC670 course on Red Teaming Tools.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control What’s the Point? What’s the point? 84 What’s the Point? The point of this lab was the explore how you can programmatically enumerate a directory to find a file, and if you had time, enumerate any subdirectories. 84 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumeration, CreateToolhelp, WTSEnum, User Information, Windows APIs
Summary: The unit outlines a curriculum for gathering operating system information, including service packs, process enumeration, and software lists. It also introduces the next module focusing on user information retrieval via Windows APIs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 88 This module will discuss the importance and benefits of gathering information abo

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: User Information, gathering user account information, SANS SEC627
Summary: The unit describes methods for gathering user account information from a local system as part of a SANS SEC627 course. It focuses on identifying 'who is who' on the system.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'User Information' discussing techniques for gathering user account information on a system. Visible text: User Information; Who's who on the system; SANS SEC627; gathering user account information Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: OS Information, Process Enumeration, Lab 2.1-2.5, Windows Tool Development, Persistence
Summary: The unit lists a curriculum for gathering operating system information, including service packs, process enumeration, installed software, and network details. It also outlines the following section's topics such as Windows tool development and persistence.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 115 This module will look at how to gather information about the network and the tar

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: network information, gathering, NIC configurations
Summary: The unit outlines the learning objectives for a module focused on gathering network information and NIC configurations. It specifies these goals as part of the training content.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Gather network information Gather NIC configurations 116 Objectives The objectives for this module are to determine how to gather any network information we can, as well as the target’s NIC configurations. 116 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Network Information, dual-homed systems, security course slide
Summary: The unit describes a slide from a cybersecurity course regarding identifying network connections and dual-homed systems. It references specific training modules related to red teaming tools and developing Windows implants.
Excerpt:
Visual caption: A slide from a cybersecurity course titled 'Network Information' discussing the identification of network connections and dual-homed systems. Visible text: Network Information; What network is the target connected to?; SEC603 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: 
Summary: This unit introduces Lab 1.2, which focuses on using Process Monitor (ProcMon) from the Sysinternals Suite to observe process behavior and identify program flaws during startup or OS boot.
Excerpt:
Lab 1.2: ProcMon Process Monitor is one of the tools that comes bundled with the Systinternals Suite and is great for seeing what a process is doing when it starts up. ProcMon also has the ability to monitor what is happening when the OS starts. Please refer to the eWorkbook for the details of the lab. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.2: ProcMon Observe how ProcMon can be used to spot flaws with a program. Observe how ProcMon can be used to spot flaws with a program. Please refer to the eWorkbook for the details of this lab. 31 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Module Summary, network information gathering, sourcing NIC information
Summary: The unit contains a summary slide from a SANS SEC670 course. It outlines information gathering techniques for network and NIC configurations.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Module Summary' detailing information gathering techniques for network and NIC configuration. Visible text: Module Summary; Discussed how to gather information about the network; Discussed how to gather NIC information about the target; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: GetAdapterAddresses(), GetNumberOfInterfaces(), GetIpStatistics(), network adapter IP address
Summary: The unit contains a review question regarding Windows APIs for retrieving network adapter IP addresses. It lists three specific API functions: GetAdapterAddresses(), GetNumberOfInterfaces(), and GetIpStatistics().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What API will give you an IP address for a network adapter? What API will give you an IP address for a network adapter? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 126 Unit Review Questions Q: What API will give you an IP address for a network adapter? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 126 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: GetAdapterAddresses(), GetNumberOfInterfaces(), GetIpStatistics(), Unit Review Answers
Summary: This unit contains a review section for the SEC670 course, specifically focusing on Windows API functions related to networking. It lists multiple variations of questions and answers regarding identifying network adapter IP addresses.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Answers What API will give you an IP address for a network adapter? What API will give you an IP address for a network adapter? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 127 Unit Review Answers Q: What API will give you an IP address for a network adapter? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 127 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: GetAdapterAssets(), logical interfaces, Windows API
Summary: The unit contains a review question regarding which Windows API includes logical interfaces in its results. It lists three options: GetAdapterAddresses(), GetNumberOfInterfaces(), and GetIpStatistics().
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What API includes logical interfaces in its results? What API includes logical interfaces in its results? A GetAdapterAddresses() A GetAdapterAddresses() B GetNumberOfInterfaces() B GetNumberOfInterfaces() C GetIpStatistics() C GetIpStatistics() 128 Unit Review Questions Q: What API includes logical interfaces in its results? A: GetAdapterAddresses() B: GetNumberOfInterfaces() C: GetIpStatistics() 128 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Course Roadmap, Slide outline, Section 2, Gathering Operating System Information, Process Enumeration, Registry Information
Summary: The unit contains a slide outlining the course roadmap and specific topics for Section 2, focusing on gathering operating system information. It lists sub-topics such as process enumeration and registry information.
Excerpt:
Visual caption: A slide showing the course roadmap and a detailed outline of Section 2 topics related to gathering operating system information. Visible text: Course Roadmap; Section 2; Gathering Operating System Information; Process Enumeration; Registry Information; SEC673 Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: registry information, learning objectives, SANS SEC670
Summary: The unit describes the learning objectives for a module focused on gathering registry information. It specifies that students should understand what types of data can be found within the Windows Registry.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Gather registry information 131 Objectives The objectives for this module are to understand what information can be found in the registry. 131 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: registry information, learning objectives, SANS SEC670
Summary: The unit describes the learning objectives for a module focused on gathering registry information. It specifies that students will learn what types of data can be found within the Windows Registry.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Objectives Our objectives for this module are: Gather registry information 131 Objectives The objectives for this module are to understand what information can be found in the registry. 131 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: Windows Registry, root keys, HKEY_USERS, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_CURRENT_CONFIG
Summary: The text describes the five predefined root keys of the Windows Registry (HKEY_USERS, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, and HKEY_CURRENT_CONFIG). It explains that 'H' stands for handle and 'KEY' stands for key. It also provides a brief overview of which types of information are stored in each specific root key.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (3) There are five predefined root keys the system uses. There are five predefined root keys the system uses. HKEY_USERS HKEY_USERS HKEY_CLASSES_ROOT* HKEY_CLASSES_ROOT* HKEY_CURRENT_USER* HKEY_CURRENT_USER* HKEY_LOCAL_MACHINE HKEY_LOCAL_MACHINE HKEY_CURRENT_CONFIG* HKEY_CURRENT_CONFIG* An * denotes the key is a link or a merged view of keys. An * denotes the key is a link or a merged view of keys. 135 The Registry (3) You might have noticed that each root key starts with an H. This is because the root key names are Windows handles (H) to keys (KEY); hence the name HKEY. The key names on the 

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: HKEY_CLASSES_ROOT, HKCR, HKCU\SOFTWARE\Classes, HKLM\SOFTWARE\Classes
Summary: The unit describes the technical details of the HKEY_CLASSES_ROOT (HKCR) registry key in a Windows environment. It specifically mentions paths like HKCU\SOFTWARE\Classes and HKLM\SOFTWARE\Classes.
Excerpt:
Visual caption: A slide from a SANS course explaining the technical details of the HKCR© key in the Windows Registry. Visible text: The Registry (6); Deep dive: HKEY_CLASSES_ROOT (HKCR©); HKCU\SOFTWARE\Classes; HKLM\SOFTWARE\Classes; SEC473 | Red Team Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: HKEY_CLASSES_ROOT, HKCR, file extension associations, COM class registrations, HKCU\SOFTWARE\Classes, HKLM&;SOFTWARE%Classes
Summary: The unit describes the structure and purpose of the HKEY_CLASSES_ROOT (HKCR) registry key, specifically its composition as a combination of HKCU&;SOFTWARE%Classes and HKLM&;SOFTWARE%Classes. It explains how this key is used for file extension associations and COM class registrations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control The Registry (6) Deep dive: HKEY_CLASSES_ROOT (HKCR)* Deep dive: HKEY_CLASSES_ROOT (HKCR)* HKCU\SOFTWARE\Classes HKCU\SOFTWARE\Classes This root key holds three types of information: file extension associations, COM class registrations, and virtualized registry root for the UAC. Every registered file extension will have its own key that is typically the REG_SZ value type. Sometimes they simply point to another key that holds the needed information. HKLM\SOFTWARE\Classes HKLM\SOFTWARE\Classes The combination of the above Classes keys make this root key. The combination of the above Classes keys make this r

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: HKKY_CURRENT_CONFIG, HKCC, HKEY_LOCAL_MACHINE, SEC701
Summary: The unit describes the HKCY_CURRENT_CONFIG (HKCC) registry key and its link to HKEY_LOCAL_MACHINE. It is part of a cybersecurity course on red teaming tools.
Excerpt:
Visual caption: A slide from a cybersecurity course explaining the HKKY_CURRENT_CONFIG (HKCC) registry key. Visible text: The Registry (8); Deep dive: HKKY_CURRENT_CONFIG (HKCC)*; HKEY_CURRENT_CONFIG is entirely linked to HKEY_LOCAL_MACHINE; SEC701; SANS Institute Alt/source label:

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: registry, information found within, Windows system components
Summary: The unit provides a summary of the registry, covering its structure and the types of information contained within it. It serves as an introductory overview of the registry's role in Windows systems.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Discussed the registry and information found within it. Discussed the registry and information found within it. 156 Module Summary In this module, we discussed what the registry is, many of the keys, and some of the information that can be found within the registry. 156 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: PowerShell, WMI queries, Get-WmiObject, wmi2_Process, smbclient
Summary: The unit contains a PowerShell command for querying WMI objects, specifically targeting processes named 'notepad.exe'. It also mentions that certain actions can trigger logon events via smbclient.
Excerpt:
Visual caption: A screenshot of a PowerShell terminal window showing WMI queries for testing purposes. Visible text: Testing WMI Queries; Get-WmiObject -Query "Select * from wmi2_Process where name='notepad.exe'"; Can trigger logon events using smbclient Alt/source label:

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.8  Key cues: strings command, binary file, memory2.201, SANS SEC701
Summary: The unit contains a visual caption describing a screenshot of a slide showing the output of a 'strings' command on a binary file named 'memory2.exe'.
Excerpt:
Visual caption: A screenshot of a slide from a SANS Institute course showing the output of a strings command on a binary file. Visible text: Viewing Strings; Address; Length; Type; String; SANS SEC701; memory2.exe Alt/source label:

=== UNIT 23 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Nmap, ncat, hping3, Netstat, querylsd.exe, portscan, netstat -a
Summary: The unit contains a screenshot of terminal output from Nmap and other network reconnaissance tools. It lists specific commands like ncat, hping3, and netstat to identify open ports and services.
Excerpt:
Visual caption: A screenshot of a terminal window displaying the output of an Nmap scan and other network reconnaissance tools. Visible text: Nmap; ncat; hping3; Netstat; querylsd.exe; portscan; netstat -a; 10.0.2.154; 10.0.2.154; 10.0.2.154 Alt/source label:

=== UNIT 24 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Nmap scan, Netcat listener, NMAP SCAN RESULTS
Summary: The unit contains a visual caption describing a terminal window showing Nmap scan results and a Netcat listener. It includes repeated instances of the text 'NMAP SCAN RESULTS'.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of an Nmap scan and a Netcat listener, followed by another Nmap scan result. Visible text: NMAP SCAN RESULTS; NMAP SCAN RESULTS; NMAP SCAN RESULTS Alt/source label:

=== UNIT 25 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: terminal window, tool installation, ls -la | query, Refining, Install Packages
Summary: The unit contains a screenshot of a terminal window showing commands for checking and installing tools. It includes multiple instances of the command 'ls -la | grep .*' used to list files in a directory.
Excerpt:
Visual caption: A screenshot of a terminal window showing commands for checking and installing various tools, as well as listing files in a directory. Visible text: Refining:; Install Packages:; Files:; ls -la | grep .*; ls -la | grep .*; ls -la | grep .*; ls -la | grep .*; ls -la | grep .*; ls -la | grep .*; ls -la | grep .*; ls -la | grep .* Alt/source label:

=== UNIT 26 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Nmap, Ncat, NSE, Metaploit Framework, Flipper Zero
Summary: The unit contains a description of a technical documentation page featuring command-line tools like Nmap, Ncat, and the Metasploit Framework. It also mentions hardware devices such as the Flipper Zero.
Excerpt:
Visual caption: A screenshot of a technical documentation page detailing various command-line tools and techniques for network reconnaissance and exploitation. Visible text: Nmap, Ncat, Nmap Scripting Engine (NSE), Metasploit Framework, Flipper Zero, Alt/source label:

=== UNIT 27 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: DNS records, Cloudflare proxying, third-party cloud services, SaaS offerings, Office 365, subdomains
Summary: The unit discusses how DNS records can reveal information about exposed services and the potential risks associated with different hosting environments like Cloudflare or third-party cloud providers. It highlights the importance of verifying infrastructure ownership before testing and notes that SaaS offerings like Office 365 can provide alternative paths to objectives.
Excerpt:
2. DNS Records: Domain Name System (DNS) records can provide a wealth of information regarding services that may be exposed to the Internet, but here there be dragons. NOTE: Because the lab has no outbound Internet access, you must use your own Kali VM if you want to following along with these steps. But they are optional, so feel free not to. When we browse to cvberbotic.io, we are actually being sent to Cloudflare, which proxies the traffic between us and the Webserver. The issue being that we don't know if the web server is hosted on premise of the target organisation, or in another 3rd party cloud service. This information you must confirm with the client - providers such as Amazon and A

=== UNIT 28 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Host Reconnaissance, Defense in Depth, Offense in Depth
Summary: The unit contains a visual caption describing host reconnaissance techniques. It specifically mentions the concepts of 'Defense in Depth' and 'Offense in Depth' as they relate to host-level information gathering.
Excerpt:
Visual caption: A screenshot of a slide or webpage titled 'Host Reconnaissance' discussing the concepts of Defense in Depth and Offense in Depth. Visible text: Host Reconnaissance; Defense in Depth; Offense in Depth Alt/source label:

=== UNIT 29 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: ls -la, cat /etc/passwd, home/user1, home/user2
Summary: The unit contains a screenshot of terminal output showing the execution of 'ls -la' and 'cat' commands. It displays file listings for various directories and specific content from the system configuration files.
Excerpt:
Visual caption: A screenshot of a terminal showing the output of 'ls -la' and 'cat' commands on various files and directories within a directory structure. Visible text: ls -la; cat /etc/passwd; ls -l /home/user1; ls -l /home/user2 Alt/source label:

=== UNIT 30 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: PowerShell, Get-DomainComputer, DNS Alias Name, domain enumeration
Summary: The unit contains a screenshot of a PowerShell command used to enumerate domain computer names and their corresponding DNS alias names.
Excerpt:
Visual caption: A screenshot of a PowerShell command and its output listing domain computer names. Visible text: Get-DomainComputer; beacon.o powershell Get-DomainComputer -Properties DnsAliostName | sort -Property DnsAliostName; dnsaliostname; dc-2.dev.cyberbotic.io; srv-1.dev.cyberbotic.io; srv-2.dev.cyberbotic.io; w03h 1.dev.cyberbotic.io; w03h 2.dev.cyberbotic.io Alt/source label:

=== UNIT 31 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Get-DomainGPO, PowerShell, Group Policy Objects, Policy listing
Summary: The unit contains a visual caption describing a screenshot of a command-line interface. It shows the use of the Get-DomainGPO command in PowerShell to list Group Policy Objects.
Excerpt:
Visual caption: A screenshot of a command-line interface showing the use of Get-DomainGPO command to list Group Policy Objects. Visible text: Get-DomainGPO; PowerShell; Default Domain Policy; Roaming Users; Windows Defender Alt/source label:

=== UNIT 32 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Find-DomainUserLocation, PowerShell, domain user locations, OPSEC
Summary: The unit describes a PowerShell command used to identify the location of domain users across machines. It highlights an operational security (OPSEC) concern regarding the query' noise level.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of a PowerShell command to find domain user locations. Visible text: Find-DomainUserLocation; beacone powershell Find-DomainUserLocation | select UserName, Session1ronName; OPSEC: Querying every machine in the domain is obviously very noisy. Alt/source label:

=== UNIT 33 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: ADSearch, LDAP query, terminal output, 6 results
Summary: The unit contains a screenshot of a terminal window showing the output of an ADSearch tool performing a custom LDAP query. The results show six search results for a specific domain structure.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of an ADSearch tool performing a custom LDAP query. Visible text: ADSearch; LDAP //dc=...\dc=...; TOTAL NUMBER OF SEARCH RESULTS: 6; COMPLETE & CONTINUE >> Alt/source label:

=== UNIT 34 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: notice, notice-query, ls -la, grep "$HOME"
Summary: The unit contains a screenshot of terminal documentation for 'notice' and 'notice-query' commands. It also includes an example of the listing directory contents with long format and filtering by home directory.
Excerpt:
Visual caption: A screenshot of a terminal window displaying documentation for the 'notice' and 'notice-query' commands, along with a example of a 'ls -la' command output. Visible text: Notice; Notice query; Notice-query; lsa; ls -la; ls -la | grep "$HOME"; ls -la | grep "$HOME" Alt/source label:

=== UNIT 35 ===
Source: CRTO Book.pdf
Value: 0.8  Key cues: Nmap scan, system_info, Local Address Port, Process, nmap -p 1-65535 --version
Summary: The unit contains a screenshot of an Nmap scan and manual checks for local information. It includes specific commands like 'nmap -p 1-65535 --version' and displays system info, ports, and processes.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of an Nmap scan and a subsequent manual check for local information. Visible text: Nmap scan results; system_info; Local Address Port; Process; nmap -p 1-65535 --version Alt/source label:

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: Current State of the Art Tools, Profit driven, Community driven, Huntress Labs, PE-sieve
Summary: The unit describes current state-of-the-art tools for identifying and analyzing malicious activity, comparing profit-driven versus community-driven solutions. It specifically mentions Huntress Labs and PE-sieve as examples of the other types.
Excerpt:
Visual caption: A slide titled 'Current State of the Art Tools' showing a comparison between profit-driven and community-driven tools, with specific examples like Huntress Labs and PE-sieve. Visible text: Current State of the Art Tools; Profit driven; Huntress Labs; Community driven; PE-sieve; SEC701 Alt/source label:

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: 
Summary: This unit introduces Lab 1.2, which focuses on using Process Monitor (ProcMon) from the Sysinternals suite to observe process behavior and identify program flaws during startup or OS boot.
Excerpt:
Lab 1.2: ProcMon Process Monitor is one of the tools that comes bundled with the Systinternals Suite and is great for seeing what a process is doing when it starts up. ProcMon also has the ability to monitor what is happening when the OS starts. Please refer to the eWorkbook for the details of the lab. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.2: ProcMon Observe how ProcMon can be used to spot flaws with a program. Observe how ProcMon can be used to spot flaws with a program. Please refer to the eWorkbook for the details of this lab. 31 31 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.8  Key cues: ProcMon, Lab 1.2, software flaw identification
Summary: The unit describes a laboratory exercise involving Process Monitor (ProcMon) to identify software flaws. It references an external eWorkbook for detailed instructions.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 1.2: ProcMon' describing the use of Process Monitor to identify flaws in programs. Visible text: Lab 1.2: ProcMon; Observe how ProcMon can be used to spot flaws with a program.; Please refer to the eWorkbook for the details of this lab. Alt/source label:

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: Windows Version Mapping, Internal Version Numbers, OS Querying
Summary: The unit provides a reference table mapping Windows OS versions to their internal version numbers (e.g., 6.1 for Windows 7). It explains that these internal numbers are used when querying the target system's OS information.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Versions Windows releases and their respective version numbers Windows releases and their respective version numbers Windows XP Windows Server 2003 Windows Vista / Server 2008 Windows 7 / Server 2008 R2 Windows 8 / Server 2012 Windows 8.1 / Server 2012 R2 Windows 10 / Server 2016 5.1 5.2 6.0 6.1 6.2 6.3 10 8 Windows Versions When you are querying the target to determine the specific version of the OS, you will not find something that tells you that the target is a Windows Vista system. Instead, you would be given back something like 6.1 to indicate Windows 7. The table is simply here for an easy r

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 2 - Getting to Know Your Target.pdf
Value: 0.8  Key cues: course roadmap, OS info gathering, process enumeration, Section 2 overview
Summary: The text lists a course roadmap for gathering operating system information, including service packs, process enumeration, and network details. It also outlines the modules in Section 2 of the Red Teaming Tools course.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Gathering Operating System Information Lab 2.1: OS Info Service Packs/Hotfixes/Patches Process Enumeration Lab 2.2: ProcEnum Lab 2.3 CreateToolhelp Lab 2.4 WTSEnum Installed Software Directory Walks Lab 2.5: FileFinder User Information Services and Tasks Network Information Registry Information Bootcamp S e c t i o n 2 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 115 This module will look at how to gather information about the network and the tar
