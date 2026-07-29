# Atlas Material — edr-evasion (part 4)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: evasion
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: PE-sieve, injection methods, injected PEs, hooks, dump an implant
Summary: This unit introduces Lab 1.1, which focuses on using the PE-sieve tool to detect and analyze malicious activity such as injected PEs and hooks. It describes the purpose of intelligence gathering from the tool's GitHub repository and its ability to dump implants.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Lab 1.1: PE-sieve Observe how a defensive tool can catch injection methods. Observe how a defensive tool can catch injection methods. Please refer to the eWorkbook for the details of this lab. 29 Lab 1.1: PE-sieve PE-sieve, according to hasherezade’s GitHub repo, “is a tool that helps detect malware running on the system, as well as to collect the potentially malicious material for further analysis.” The tool is designed to scan a single process, but it does a great job at detecting various items like injected PEs and hooks. It also has the ability to dump an implant should one be discovered injected into

=== UNIT 2 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: UACMe Project, FusionCheckFile, LdrResourcesSearchResource, NtCreateFile, NtCreateSection
Summary: The unit describes the UACMe project's FusionCheckFile function, which is used for parsing embedded manifests. It lists specific system calls like LdrResourcesSearchResource, NtCreateFile, and NtCreateSection.
Excerpt:
Visual caption: A slide from a presentation about the UACMe project, specifically detailing the FusionCheckFile function. Visible text: UACMe Project: FusionCheckFile; Responsible for parsing embedded manifests; LdrResourcesSearchResource; NtCreateFile; NtCreateSection; SECF07 | Red Team Toolkit: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 3 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: process injection, userland process, execution of arbitrary code, detection avoidance, evasion
Summary: The unit defines process injection as a method of forcing code from one userland process into another to execute arbitrary code. It discusses the motivations for using injection, specifically focusing on avoiding detection by executing shellcode within legitimate processes. The text distinguishes between true process injection and other pre-execution techniques like DLL hijacking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 51 Process Injection What exactly is process injection and what are some reasons for injecting into a process? Forcefully making a process execute arbitrary code Avoid detection by having a legit process execute your shellcode Process Injection Depending on what blog post you read or what YouTube video you watch, you might get a different definition of what process injection is. For this course, we define process injection as a method of forcing code from one userland process, say malware, into another userland process to execute arbitrary code. We will discuss other techniques that are not true to that d

=== UNIT 4 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: Process Injection, arbitrary code execution, security evasion
Summary: The unit describes the concept of process injection, defining it as forcing a process to execute arbitrary code. It highlights the reasons for using this technique, specifically to evade detection by running shellcode within a legitimate process.
Excerpt:
Visual caption: A presentation slide titled 'Process Injection' explaining the concept and reasons for it. Visible text: Process Injection; What exactly is process injection and what are some reasons for injecting into a process?; Forcefully making a process execute arbitrary code; Avoid detection by having a legit process execute your shellcode Alt/source label:

=== UNIT 5 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 3 - Operational Actions.pdf
Value: 0.85  Key cues: process injection, SetWindowsHookEx API, module summary
Summary: The unit provides a summary of the module covering various forms and techniques of process injection, including the use of SetWindowsHookEx API. It highlights that different methods may share similar techniques or offer additional features beyond simple injection.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 74 Module Summary Learned process injection comes in many forms; results are really the same Learned process injection comes in many forms; results are really the same Discussed how some methods have similar techniques Discussed how some methods have similar techniques Discussed how some methods serve as an injection method but also offer bonus features Discussed how some methods serve as an injection method but also offer bonus features Module Summary In this module, we covered several methods of injection and even tossed in something extra with the SetWindowsHookEx API. If you are a defender taking this

=== UNIT 6 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: fileless malware, static analysis bypass, AV/EDR limitations, memory scanning
Summary: The text discusses the advantages of fileless malware, specifically focusing on how not being present on disk avoids static analysis and detection by AV/EDR solutions. It highlights that while EDRs have improved behavior detection, it remains difficult to scan all memory regions constantly due to resource constraints.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 8 Advantages It sure is great to not be on disk. It sure is great to not be on disk. No files to be analyzed No files to be analyzed Bypass static detection Bypass static detection Since files are not dropped to disk, there is nothing for an analyst to retrieve. Files on disk are prone to static analysis before execution. By not being on disk, there is no risk of static detection. Advantages The biggest advantage for fileless malware is the fact that nothing is dropped to disk. The fact that certain programs, system files, tools, etc. cannot be blocked by IT staff without hindering support keeps enabling 

=== UNIT 7 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: fileless malware, bypass static detection, not on disk
Summary: The unit describes the advantages of fileless malware techniques, specifically focusing on how they bypass static analysis. It highlights that not being present on disk allows for easier evasion of security measures.
Excerpt:
Visual caption: A slide from a presentation about fileless malware techniques, highlighting the advantages of not being on disk. Visible text: Advantages; It sure is great to not be on disk.; No files to be analyzed; Bypass static detection; SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 8 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Sysmon, WMI attacks, Event Filter, Event Consumer, binding
Summary: The text discusses the use of Sysmon to detect WMI-based attacks, specifically focusing on how it can log events related to Event Filters, Event Consumers, and their bindings. It highlights that while logs are generated, the determination of whether an event is malicious depends on analysis.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 108 Detecting WMI Attacks Sysmon can be configured to detect WMI attacks. Sysmon can be configured to detect WMI attacks. The abuse that has been done with WMI can be detected using several tools, one of them being Sysmon. The configuration can catch the Event Filters, the Event Consumers, and our bindings of filters and consumers. Detecting WMI Attacks There are several methods and tools for detecting these style of attacks, so be careful before you implement this method. One of the more popular tools today is one put out by Microsoft called Sysmon. It has proven to be very formidable, and when configure

=== UNIT 9 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Volatility, PE-sieve, Moneta, memory forensics, injection methods, performance impact
Summary: The unit discusses memory forensics tools such as Volatility, PE-sieve, and Moneta for detecting implants in Windows systems. It highlights the limitations of security products regarding performance impacts when scanning memory regions. The text emphasizes that while being in memory is not a guarantee of evasion, detection by motivated analysts using these specific tools is likely.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 11 Memory Forensics Being in memory is not a get out of jail free card. Being in memory is not a get out of jail free card. Volatility Volatility From the Volatility Foundation, ingests memory dumps with numerous plug-ins PE-sieve PE-sieve From Hasherzade, scans a process and can dump implants detecting all kinds of injection methods Moneta Moneta From forrest-orr, user-mode Windows memory analysis tool, similar to PE- sieve Memory Forensics Almost everything you do on a Windows system can be logged by something. Even if a certain Windows tool does not catch your activity, highly motivated memory analysts

=== UNIT 10 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: System32 folder, blending in, file naming conventions, timestamps
Summary: The unit discusses techniques for blending in with existing files on a Windows system, specifically within the System32 folder. It covers selecting an appropriate location among many items and choosing a filename that matches surrounding file naming conventions and timestamps.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 16 Blending In On this Windows 10 VM, there are over 4,200 items in the System32 folder. Plenty of options to blend in with files around you. Blending In When it comes to blending in, it can be somewhat easy with the proper level of permissions. As one possible example, a prime spot could be the System32 folder where there are well over 4,200 items to surround yourself. You would not necessarily want to be the first or the last entry in the folder but pick a spot that would require the user to scroll down for quite some time. Users are notorious for scrolling right past something unless they are specifica

=== UNIT 11 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: antivirus scanning, implant detection, sideloading risk, cloud-based analysis, custom binary risks
Summary: The text discusses the risks associated with being scanned by antivirus (AV) solutions when deploying custom-made implants. It highlights considerations regarding what information might be revealed to AV vendors and potential cloud analysis implications for unknown binaries.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 17 Being Scanned If you get scanned, what will they find out? If you get scanned, what will they find out? All tool capabilities All tool capabilities Bare minimum for access Bare minimum for access Will you lose months or years of effort if your binary gets picked up by an AV solution? Or will the functionality required to maintain access across reboots be the only thing discovered? Being Scanned Another risk you must consider is should there be some AV solution installed like Defender, will that deter you from dropping to disk? If not, are you okay with it possibly being scanned? Some AV solutions requi

=== UNIT 12 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: DRM, Themida, Skrull, anti-copy, Process Ghosting
Summary: The unit discusses methods for protecting implants from analysis and detection, specifically mentioning commercial tools like Themida and the Skrull malware DRM. It highlights how these tools use techniques such as code block protection and Process Ghosting to hinder reverse engineering.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 18 Protecting Yourself What can you do to protect your implant? What can you do to protect your implant? You could get extremely creative and DRM your implant like the PoC Skrull did. According to the author, the malware launchers are anti-copy and are thus broken if, and when, they are submitted for analysis. Protecting Yourself There are several public techniques and tools that are out there today that aid your efforts to protect yourself. There are commercial tools like packers and encryptors that do a tremendous job annoying reverse engineers. One such tool is Themida, which is made by the company Ore

=== UNIT 13 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: AppCert DLLs
Summary: The unit describes how AppCert DLLs are used by Windows to monitor specific API calls like CreateProcess and WinExec. It explains that the system checks the Registry for these DLLs during process creation.
Excerpt:
Visual caption: A presentation slide about AppCert DLLs and their role in Windows security. Visible text: AppCert DLLs; Certain Create* API calls look for AppCert.; Like AppInit, Windows will investigate the Registry for DLLs that must be loaded into a process.; CreateProcess; WinExec; SEC607 / Red Teaming: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: User32.dll, AppCert, AppInit, RunOnce
Summary: The unit contains a multiple-choice question regarding evasion techniques specifically for processes linked against User32.dll.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about evasion techniques for processes linked against User32.dll. Visible text: Unit Review Questions; What technique should be used for processes linked against User32.dll?; AppCert; AppInit; RunOnce Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: IFEO GlobalFlag, silent process exit, sfflags.exe, sfflags.exe, Windows SDK
Summary: The unit describes the IFEO GlobalFlag setting in Windows and its impact on monitoring silent processes. It mentions that this flag is bundled with the Windows SDK and relates to process monitoring.
Excerpt:
Visual caption: A slide and accompanying text describe the IFEO GlobalFlag setting in Windows, explaining how it affects the process monitoring of 'silent' processes. Visible text: IFE0 GlobalFlag; A nice addition to the traditional IFEO; fflags.exe; silent process exit; Bundled with the Windows SDK; Monitor on any process; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control; IFE0 GlobalFlag. Alt/source label:

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: Gflags.exe, GUI version, Kernel, Image File, Silent Process Exit, programmatic implementation
Summary: The unit describes the GUI version of Gflags.exe, highlighting its various tabs for Kernel, Image File, and Silent Process Exit features. It encourages users to understand these tools to eventually implement similar functionalities programmatically.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 83 Running Gflags.exe Running Gflags.exe The GUI version of the gflags program looks similar to the screenshot on the slide. You can see the various tabs at the top of the window that are specific to categories like the Kernel, Image File, and Silent Process Exit. Feel free to explore the tool and the features that it provides. Once you have an understanding you can programmatically implement many of these items on your own. © 2024 Jonathan Reiter 83 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 4 - Persistence Die Another Day.pdf
Value: 0.85  Key cues: GflagsX, GUI comparison, Silent Process Exit, Image tab
Summary: The text describes the comparison between GflagsX and a legacy tool, highlighting its modernized GUI and consolidated features like Silent Process Exit options under the Image tab.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 85 Running GflagsX Running GflagsX The GUI for Pavel’s tool looks much nicer and more modern than the legacy tool. There are not as many tabs at the top of the window, but many of those features are consolidated. For example, the Silent Process Exit tab and its options are located under the Image tab for GflagsX. © 2024 Jonathan Reiter 85 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: encryption, CNG APIs, AES-CTR, AES-GCM, SSL interception, BCryptEncrypt
Summary: The unit discusses the importance of encrypting data within implant communications to bypass SSL interception by proxies like F5 BIG-IP or Blue Coat. It recommends using modern Win32 APIs (CNG) for AES-CTR or AES-GCM encryption instead of older methods like RC4.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 107 Encryption of Data CNG APIs CNG APIs Need to specify what algorithm should be used and its properties Need to specify what algorithm should be used and its properties // basics steps for CNG API usage // open the algorithm provider BCryptOpenAlgorithmProvider(, BCRYPT_AES_ALGORITHM,,) // set algorithm properties BCryptSetProperty(,, BCRYPT_CHAIN_MODE_GCM,,) // create a key BCryptGenerateSymmetricKey() // encrypt the data BCryptEncrypt(); // decrypt the data BCryptDecrypt(); Can create or import a key followed by encrypting or decrypting the data Can create or import a key followed by encrypting or dec

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: certificate pinning, Man-in-the-Middle (MITM), WinHttp, WinInet, INTERNET_OPTION_SERVER_CHAIN_CONTEXT
Summary: The text explains the concept of certificate pinning as a technique to prevent Man-in-the-Middle (MITM) attacks by validating specific thumbprints in an implant's communication. It details how to implement it using WinHttp and WinInet APIs, specifically mentioning the use of INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 109 Cert Pinning Let’s put a pin in it Let’s put a pin in it Windows, Apple, Android, and others all do certificate pinning Windows, Apple, Android, and others all do certificate pinning // ask for server’s cert chain context InternetQueryOption(INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEX T) // find first of common name, unit name, org name CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE) // get encrypted key hash for cert context CertGetCertificateContextProperty(CERT_HASH_PROP_ID) // convert hash to hex bytes std::stringstream ss; ss << std::hex; for (; i < hashLen; ) { ss << static_cast<INT>(certHash[i]);

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Avoiding Strings, Global Variables, IDAPro, Ghidra, statement of risk
Summary: The unit describes techniques for obfuscating strings and global variables within a piece of malware or tool. It highlights how these elements can be easily identified during static analysis using tools like IDAPro or Ghidra.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Avoiding Strings/Global Variables' showing code snippets and explanations for obfuscating strings. Visible text: Avoiding Strings/Global Variables; Strings can easily give you away; Avoid references to the data section; Can be found by static analysis in IDAPro or Ghidra; change this; use this; to this; avoid global vars Alt/source label:

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: strings, global variables, data section, .rdata, IDAPro, Ghidra, array of individual letters
Summary: The unit discusses techniques for evading detection by avoiding the use of plain-text strings and global variables in Windows implants. It explains how string arrays can be used to hide information from automated tools like Sysinternals Strings or IDAPro's Strings view. The text also notes that while array methods may still be found via manual analysis, they are more effective than direct declarations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 124 Avoiding Strings/Global Variables Strings can easily give you away. Strings can easily give you away. Avoid references to the data section. Avoid references to the data section. // change this char charName[] = “GetProcAddress”; // or this char* charName = “GetProcAddress” // to this char charName[] = {‘G’,‘e’,‘t’,‘P’,...,0}; // avoid global vars int g_c2port = 4444; char* g_charName = “LoadLibraryA”; Can still be found via static analysis in IDAPro or Ghidra Can still be found via static analysis in IDAPro or Ghidra Avoiding Strings/Global Variables Strings can be a dead giveaway as to what your impl

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: AES encryption, CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptDecrypt, PROV_RSA_AES, shellcode evasion
Summary: The unit describes the use of AES encryption and decryption using Windows CryptoAPIs to protect shellcode from detection by AV/EDR systems. It outlines a sequence of API calls (CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptDecrypt) and emphasizes transitioning to Crypto Next Gen APIs.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 127 Encrypting/Decrypting Your Shellcode: AES (1) AES Encryption AES Encryption These versions are deprecated. These versions are deprecated. // make an AES decrypting function void AESDecrypt( args go here ) { CryptAcquireContextA(); CryptCreateHash(); CryptHashData(); CryptDeriveKey(); CryptDecrypt(); CryptReleaseContex(); CryptDestroyHash(); CryptDestroyKey(); } Use the Crypto Next Gen APIs instead. Use the Crypto Next Gen APIs instead. Encrypting/Decrypting Your Shellcode: AES (1) Having raw shellcode in your binary can instantly be flagged by various AV/EDR solutions. We can easily use AES encryption

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: XOR operation, shellcode encryption/decryption, encoding vs encryption, null byte removal
Summary: The unit discusses the use of XOR operations for encrypting and decrypting shellcode. It distinguishes between encoding (like Base64) and encryption (which requires a key), noting that XOR is technically a form of encryption because it uses a key.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 129 Encrypting/Decrypting Your Shellcode: XOR Using XOR Using XOR XORing data with a key XORing data with a key // make an XOR decrypting function 1 void XorIt( args go here ) 2 { 3 DWORD i = 0; 4 for (; i < sizeof(scode); i++) 5 { 6 scode[i] = (BYTE)scode[i] ^ key; 7 } 8 } Same routine for encrypt and decrypt Same routine for encrypt and decrypt Encrypting/Decrypting Your Shellcode: XOR There has been some discussion as to whether or not XORing data is encoding it or encrypting it. If you read about encryption, you would see there is a key that is involved, then you might say that XORing data is indeed e

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: XOR operation, shellcode encryption, shellcode decryption, SANS SEC701
Summary: The unit describes the use of XOR operations as a method for encrypting and decrypting shellcode. It highlights that the same routine is used for both encryption and XORing data with a key.
Excerpt:
Visual caption: A presentation slide explaining the use of XOR operations for encrypting and decrypting shellcode. Visible text: Encrypting/Decrypting Your Shellcode: XOR; Using XOR; XORing data with a key; Same routine for encrypt and decrypt; void XOR(array of shellcode); SANS SEC701 Alt/source label:

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Base64 encoding, certutil.exe, CryptStringToBinaryA, CryptBinaryToStringA, shellcode transformation
Summary: The unit describes methods for encoding and decoding shellcode using Base64, specifically highlighting the use of certutil.exe, custom Python scripts, and Windows APIs like CryptStringToBinaryA and CryptBinaryToStringA.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 130 Encoding/Decoding Your Shellcode: Base64 // can use certutil certutil.exe ‐encode scode.bin scode.b64 // place resulting bytes in variable char scode[] = “ASfdbgfndGBAthyh==”; // decode shellcode CryptStringToBinaryA(...); // encode raw shellcode CryptBinaryToStringA(...); Encoding/Decoding Your Shellcode: Base64 For transforming, or encoding your shellcode, there are several tools that can assist you with this. Online tools are available if you want to give up your shellcode to them, but why take that chance in the first place? We want to use something that is either native to the OS or something tha

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Base64, certutil.exe -encode, CryptStringToBinary, CryptBinaryToStringTo
Summary: The unit describes techniques for encoding and decoding shellcode using various methods including Base64, certutil.exe, and specific cryptographic functions.
Excerpt:
Visual caption: A screenshot of a technical document or slide describing how to encode and decode shellcode using Base64. Visible text: Encoding/Decoding Your Shellcode: Base64; certutil.exe -encode; CryptStringToBinary; CryptBinaryToStringTo; SANS Institute 2024 Alt/source label:

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: AMSI, amsi.dll, patching, PowerShell script, SANS SEC670
Summary: The unit describes a lab exercise focused on patching the amsi.dll library to bypass AMSI protections in PowerShell scripts. It outlines objectives such as observing data flow for analysis and exploring various methods for patching.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Lab 5.4: AMSI No More' outlining the objectives for patching amsi.dll. Visible text: Lab 5.4: AMSI No More; Patch a PowerShell script with amsi.dll loaded; Observe how data is being passed in for analysis; Explore various methods to patch amsi.dll; SEC670 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: reflective loading, memory-only execution, custom loader, PE image, security of modularity
Summary: The text discusses the advantages of using custom loaders for memory-based execution, specifically reflective loading to avoid disk artifacts. It describes scenarios where a custom loader allows an implant to pull down and execute PE images or DLLs over a socket without dropping them to disk.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 13 When To Make A Custom Loader There is a time and a place for everything including when to use your own loader. Perhaps one of the best times is when you do not want to have anything on disk. Reflective loading is commonly used to describe this method of manually loading something in memory. Sometimes, all the time, or never Sometimes, all the time, or never When To Make A Custom Loader Having a custom loader is a great feature to have in your arsenal. Adding it as a feature to your custom shell would be amazing because it would allow you to pull down PE image over a socket and execute them without the 

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: syscalls, unhooking, hooked functions, AV products
Summary: The unit outlines learning objectives for a module on syscalls, unhooking hooks, identifying hooked functions, and re-hooking them. It explains the potential reasons why hooking occurs, such as security software or other malicious actors.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 27 Objectives Our objectives for this module are: Learn about syscalls Discuss why we would need to unhook hooks Learn how to find hooked functions Learn how to re-hook hooked functions The objectives for this module are to learn about syscalls, discuss why we would even need to unhook functions. The presence of a hooked function could indicate that another malicious actor is on the box with us or that some AV product has been installed and implemented its own hooks for functions that it thinks it needs to “watch.” The latter option is most likely going to be the situation you might come across during you

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: syscalls, unhooking hooks, finding hooked functions, re-hooking
Summary: The unit describes learning objectives for a module focused on system calls and unhooking hooks. It covers identifying and re-hooking functions to evade detection.
Excerpt:
Visual caption: A slide outlining the learning objectives for a module on system calls and unhooking hooks. Visible text: Objectives; Learn about syscalls; Discuss why we would need to unhook hooks; Learn how to find hooked functions; Learn how to re-hook hooked functions; SEC701 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: syscall, user mode to kernel mode, sytem call, NtOpenProcess, NtCreateThread
Summary: The unit describes the concept of system calls (syscalls) as mechanisms for transitioning between user and kernel modes. It lists specific Windows syscall examples such as NtOpenProcess and NtCreateThread.
Excerpt:
Visual caption: A presentation slide explaining the concept of a system call (syscall) and listing examples of common Windows syscalls. Visible text: What Is A Syscall; Syscall me maybe; Syscall is short for system call. A syscall is a mechanism used to transition code from user mode to kernel mode and back to user mode again. Each syscall has a; NtOpenProcess; NtCreateProcess; NtCreateToken; NtAccessCheck; NtCreateThread; NtLoadDriver Alt/source label:

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Windows syscall table, hardcoded syscall numbers, portability of implants, Linux vs Windows syscall differences
Summary: The unit discusses the variability of Windows syscall numbers across different OS versions and the risks associated with hardcoding these values in shellcode. It highlights a difference between Linux (where interrupt 0x80 is relatively stable) and Windows, where syscall numbers change frequently.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 29 What’s Your Number Syscall my number Syscall my number What’s Your Number? Many attempts have been done to document each one and arguably one of the more popular documents is the syscall table by Mateusz Jurcsyk (j00ru). The screenshot on the slide is from j00ru’s HTML version of the syscall table. The table shows syscalls from Windows XP SP1 to Windows 10 and Windows 11. The online tool offers a feature to highlight a certain number of a syscall, like syscall 0x00 for example. Depending on the version of Windows you have, syscall 0x00 will either be NtAccessCheck on Windows 10 through Windows 11 or Nt

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: NtAllocateVirtualMemory, kernelbase.dll, ntdll.dll, win32u.dll, syscall number, user mode to kernel mode transition
Summary: The text describes the transition from user mode to kernel mode via system calls, specifically focusing on how functions like VirtualAlloc are forwarded through libraries like kernelbase.dll and ntdll.dll. It explains the role of win32u.dll for GUI threads and the preparation of syscall numbers in registers before entering the kernel.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 30 Hello Operator? Syscall NtAllocateVirtualMemory please Syscall NtAllocateVirtualMemory please User mode User mode Kernel mode Kernel mode main:VirtualAlloc kernelbase:VirtualAlloc ntdll!NtAllocateVirtualMemory Func Addr Nt Index fffff80… 0 fffff80… 1 fffff80… … fffff80… 17 fffff80… 18 Hello Operator? Without diving deep into the weeds with the full transition into the kernel, how does a user mode process get the help of the kernel and its syscalls? When a user mode application needs to create an objects, like a process object, or when it needs to allocate pages of memory, it will eventually need the he

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: native vs GUI system calls, Notepad++.exe, NTDLL.DLL, WIN32.DLL, NtOpenProcess, NtUserOpenClipboard
Summary: The unit describes the technical differences between native system calls and GUI-based system calls in Windows. It uses Notepad++ as a example to illustrate how certain functions are called through NTDLL.DLL or WIN32.DLL.
Excerpt:
Visual caption: A slide from a technical presentation explaining the difference between native and GUI-based system calls in Windows, using Notepad++ as an example. Visible text: GUI or Console Thread?; Notepad++.exe; NTDLL.DLL (Native); NtOpenProcess; NtCreateProcess; WIN32.DLL (GUI); NtUserOpenClipboard; NtUserCloseClipboard; KERNEL (and EXECUTIVE); WIN32.SYS; SEC67 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: NtUserOpenClipboard, win32k.sys, native syscalls vs GUI syscalls, kernel table indexing
Summary: The text discusses the differences between native syscalls and GUI-based syscalls (like those in win32k.sys) when executing system calls from user mode to kernel mode. It explains how different kernel components manage their own tables for these operations, which may be targeted by EDR monitoring.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 31 GUI or Console Thread? NTDLL.DLL (Native) NTDLL.DLL (Native) WIN32U.DLL (GUI) WIN32U.DLL (GUI) NtOpenProcess NtCreateProcess NtUserOpenClipboard NtUserCloseClipboard Notepad++.exe KERNEL ( and EXECUTIVE) KERNEL ( and EXECUTIVE) WIN32K.SYS WIN32K.SYS User mode Kernel mode GUI or Console Thread? It matters. All threads are not equal and when they invoke a syscall, where they end up and how they get there differs. They all will wind up in the kernel, but their journey to get there is a bit different. Let us look at a user mode process like notepad++.exe. As you are typing your awesome stuff into the windo

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: syscall stub, assembly instructions, RCX to R10, EAX syscall number, KUSER_SHARED_DATA, kernel mode transition
Summary: The unit describes the structure and assembly instructions of a syscall stub in Windows. It explains how syscalls differ from standard functions by being much smaller and lacking typical prologues and epilogues. The text breaks down specific assembly instructions for moving registers, checking shared data, and transitioning to kernel mode.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 32 How Is A Syscall Structured? NTDLL.DLL (Native) NTDLL.DLL (Native) WIN32U.DLL (GUI) WIN32U.DLL (GUI) NtOpenProcess NtUserOpenClipboard Notepad++.exe 4c8bd1 mov r10, rcx b8c3100000 mov eax, <some number here> f604250803fe7f01 test byte ptr [7FFE0308h], 1 7503 jne <module_name>!<Some Nt function>+0x15 0f05 syscall c3 ret cd2e int 2Eh c3 ret How Is A Syscall Structured? Believe it or not, syscalls have a signature just like regular functions. The major differences with syscalls though is they do not set up the same things a called function does. For instance, a typical function will enter its prolog, crea

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: hooked syscalls, Notepad++.exe, NtOpenProcess, NtUserOpenClipboard
Summary: The unit describes a screenshot of a tool demonstrating hooked syscalls for the Notepad++ process. It identifies specific DLLs (NT_SYSCALL.DLL and WIN2I.DLL) and system calls like NtOpenProcess and NtUserOpenClipboard.
Excerpt:
Visual caption: A screenshot of a software tool showing hooked syscalls for the Notepad++ process, including native and GUI versions. Visible text: Hooked Syscalls; Notepad++.exe; NT_SYSCALL.DLL (Native); WIN2I.DLL (GUI); NtOpenProcess; NtUserOpenClipboard; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: user-mode hooks, ntdll.dll, win32u.dll, security product inspection, hook restoration, security software behavior
Summary: The text discusses the concept of user-mode hooks implemented by security products to monitor and inspect function arguments for malicious behavior. It highlights that while individual APIs are benign, combinations can be suspicious, leading security software to hook functions in modules like ntdll.dll or win32u.dll. The section also mentions the challenge for implant developers who must deal with these hooks by implementing restoration operations.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 33 Hooked Syscalls NTDLL.DLL (Native) NTDLL.DLL (Native) WIN32U.DLL (GUI) WIN32U.DLL (GUI) NtOpenProcess NtUserOpenClipboard Notepad++.exe e93b3c1600 jmp 00007ffe`063f0cc0 cc int 3 cc int 3 cc int 3 Hooked Syscalls Security products will often implement any number of user mode hooks. In fact, there have been a few people that take the time to document all the hooked functions and in what modules they are hooked; ntdll, kernelbase, win32u, etc. One of those efforts is hosted by VX-Underground on their GitHub repo. The whitepaper is called AntiVirus artifacts with first, second, and third editions. The best

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: Direct Syscalls, NtAllocateVirtualMemory, ntdll.dll, EDR bypass, syscall number recovery, call stack spoofing
Summary: The unit discusses the concept of 'Direct Syscalls' as a technique to bypass EDR user-mode hooks by invoking syscalls directly from an implant rather than through ntdll.dll. It explains that while this avoids user-mode hooks, it can still be detected by kernel-mode components checking call stacks. The text also mentions the existence of methods for recovering syscall numbers and techniques for spoofing or cloning call stacks.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 34 Direct Syscalls Normal stub for syscall in ntdll NtAllocateVirtualMemory mov r10, rcx mov eax, 0x18 test byte ptr [7FFE0308h], 1 jne ntdll!NtAllocateVirtualMemory+0x15 syscall ret int 0x2e ret main:VirtualAlloc kernelbase:VirtualAlloc ntdll!NtAllocateVirtualMemory syscall kernel user Direct Syscalls Hello operator, I would like to make a direct call to NtAllocateVirtualMemory. Direct syscalls are as much interesting as they are old, but they are still being used to bypass some EDRs that are not up to speed with everything. This technique has been around for at least 10 years or so, but here is the gist

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 5 - Enhancing Your Implant Shellcode Evasion and C2.pdf
Value: 0.85  Key cues: indirect syscalls, ntdll.dll, NtAllocateVirtualMemory, shellcode evasion
Summary: The unit describes the concept of indirect syscalls as a technique to evade security products by jumping to known locations in ntdll.dll. It specifically mentions NtAllocateVirtualMemory and shellcode blobs.
Excerpt:
Visual caption: A slide explaining the concept of indirect syscalls for evading security products by jumping to a known location in ntdll.dll. Visible text: Indirect Syscalls; NtAllocateVirtualMemory; Shellcode blob; ntdll.dll; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:
