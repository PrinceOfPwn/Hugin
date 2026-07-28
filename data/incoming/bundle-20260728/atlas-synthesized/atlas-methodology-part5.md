# Atlas Material — methodology (part 5)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: methodology
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows data types, course roadmap, DLLs, SAL annotations, Windows API
Summary: The unit introduces Windows data types and their definitions to the student. It also lists a course roadmap including topics like DLLs, SAL annotations, and various Windows APIs.
Excerpt:
In this module, we will introduce you to the Windows data types. Most of them will probably seem strange at first, but once we look at how they are defined any confusion should be gone. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • 

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Course Roadmap, Slide title, SANS SEC670, Windows Tool Development, Shellcode
Summary: The unit contains a slide titled 'Course Roadmap' outlining the modules for SANS SEC670. It lists various topics including tool development, operational actions, persistence, and shellcode.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a SANS SEC670 course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Section 1; Course Overview; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SA1. Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Windows data types, Course Roadmap, SANS SEC670, Developing Offensive Tools
Summary: The unit introduces Windows data types and their definitions to the student. It lists a course roadmap including topics like PE-sieve, ProcMon, DLL development, SAL annotations, and various Windows APIs.
Excerpt:
In this module, we will introduce you to the Windows data types. Most of them will probably seem strange at first, but once we look at how they are defined any confusion should be gone. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • 

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WinNt.h, typedef PVOID HANDLE, HKEY, HINSTANCE, HMODULE
Summary: The unit describes the definition of handle data types in the WinNt.h header file, specifically noting that HANDLE is a PVOID (void*). It explains that while some types like HINSTANCE and HMODULE are interchangeable but should be used correctly for clarity. The text also lists several specific typedefs including LPHANDLE, HRSRC, HKEY, and HMODULE.
Excerpt:
Handle Data Types Defined The Winnt header file is filled with definitions, the ones listed on the slide are just a small subset of them. If you take a look at the first typedef, you can see that a HANDLE is really just a PVOID, which is simply a void*. The remaining typedefs are using the HANDLE definition as the base. Typically, whenever you see a handle type being used, you could assume that it’s simply a void*, or PVOID. Although it is not recommended, something like this could be done and might not cause any issues: PVOID hKey = (HKEY)HKEY_LOCAL_MACHINE; The very last typedef is an interesting one. Even though it was mentioned on the previous slide, it is worth mentioning again due to i

=== UNIT 5 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Red Teaming, TTPs, real-world threat
Summary: The unit provides an introduction to red teaming and defines it as the process of emulating real-world threats using TTPs.
Excerpt:
Visual caption: A page from a course introduction about red teaming in cybersecurity. Visible text: Course Introduction; What is Red Teaming?; Red Teaming is the process of using tactics, then techniques, and procedures (TTPs) to emulate a real-world threat Alt/source label:

=== UNIT 6 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: OPSEC, Phases of an engagement, Planning, Doing, Reporting
Summary: The unit describes basic operational security (OPSEC) concepts and the three primary phases of a cyber engagement: Planning, Doing, and Reporting.
Excerpt:
Visual caption: A page of text describing the concepts of OPSEC and phases of an engagement in a cybersecurity training course. Visible text: 2. What is OPSEC?; 3. Phases of an engagement:; Planning, Doing, Reporting Alt/source label:

=== UNIT 7 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Red Teaming, TTPs, real-world threat emulation
Summary: The unit describes the definition and purpose of Red Teaming in cybersecurity. It defines Red Teaming as the process of emulating real-world threats through specific tactics, techniques, and procedures.
Excerpt:
Visual caption: A page from a course document describing the definition and purpose of Red Teaming in cybersecurity. Visible text: Course Introduction; What is Red Teaming?; Red Teaming is the process of using tactics, techniques, and procedures (TTPs) to emulate a real-world threat Alt/source label:

=== UNIT 8 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Red Team definition, TTPs, pen test vs red team, adversarial perspective
Summary: The unit introduces the concept of Red Teaming and provides a formal definition involving the use of TTPs to emulate real-world threats. It distinguishes between Red Teaming and penetration testing by highlighting differences in objectives, scope, and focus on detection/response.
Excerpt:
I. Course Introduction: 1. What is Red Teaming? "Red Teaming" is a term that's used a lot within the cyber security space. Its meaning and purpose has been malformed over time, or at least is not standardised due to several factors, including misuse of the name within vendor marketing; and a misunderstanding of compliance requirements. I shall attempt to provide an accurate definition here that will set the scene for the course content - we need to understand what red teams are, what they do and why they do it (and perhaps just as importantly, what they're not for). A good dictionary definition is provided by Joe Vest and James Tubberville: Red Teaming is the process of using tactics, techni

=== UNIT 9 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: Kerberos, TGT, AS-REQ, AS-REP, TGS-REQ, TGS-REP
Summary: The unit describes a flow diagram of the Kerberos authentication process involving three main entities: Client, KDC, and Service. It details six steps including AS-REQ, AS-REP, TGS-REQ, TGS-REP, and final service access.
Excerpt:
Visual caption: A flow diagram illustrating the Kerberos authentication process involving a Client, KDC, and Service. Visible text: Kerberos; Client; KDC; Service; 1. Client requests TGT (AS-REQ); 2. KDC returns TGT (AS-REP); 3. Client requests TGS for <service> (TGS-REQ); 4. KDC returns TGS (TGS-REP); 5. Client presents TGS to <service>; 6. <service> grants access Alt/source label:

=== UNIT 10 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: TTPs, holistic security posture, least privilege, OPSEC definition, bidirectional OPSEC, engagement phases
Summary: This unit discusses red team methodologies, focusing on emulating threat actor TTPs, holistic security posture assessment, and the importance of stealth and least privilege. It also defines Operations Security (OPSEC) as the ease of observation by defenders and highlights its bidirectional nature. Finally, it introduces the three main phases of an engagement: Planning, Doing, and Reporting.
Excerpt:
team will study and re-use (where appropriate) the TTPs of the threat they're emulating. This allows the organisation to build detections and processes designed to combat the very threat(s) they expect to face. Red teams will also look holistically at the overall security posture of an organisation and not be laser-focused to one specific area - this of course includes people and processes as well as technology. Finally, red teams put a heavy emphasis on stealth and the "principal of least privilege". To challenge the detection and response capabilities, they need to reach the objective without getting caught - part of this is not going after high-privileged accounts (such as Domain Admin) u

=== UNIT 11 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: OPSEC, Phases of an engagement, Planning, Doing, Reporting
Summary: The unit describes basic operational security (OPSEC) concepts and the three primary phases of a cyber engagement: Planning, Doing, and Reporting.
Excerpt:
Visual caption: A page of text describing the concepts of OPSEC and phases of an engagement in a cybersecurity training course. Visible text: 2. What is OPSEC?; 3. Phases of an engagement:; Planning, Doing, Reporting Alt/source label:

=== UNIT 12 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: methodology, scope, term of engagement, threat model
Summary: The unit describes the methodology, scope, and threat model for a red team engagement. It lists specific sections regarding planning and team engagement, scope, and threat modeling.
Excerpt:
Visual caption: A page of text describing the methodology and scope of a red team engagement. Visible text: 3. Planning and team engagement:; 4. Scope.; 5. Threat Model: Alt/source label:

=== UNIT 13 ===
Source: CRTO Book.pdf
Value: 0.85  Key cues: threat profile, MITRE ATT&CK, breach model, assume breach, offshore/onshore notifications
Summary: The text describes the process of creating threat profiles based on intent, motivations, and TTPs using sources like MITRE ATT&CK. It also outlines breach models (initial access methods) and the strategic considerations regarding notification levels for security teams during an engagement.
Excerpt:
threats, which is not always realistic. As part of this planning, be prepared to temper or help align their expectations. Once a threat has been identified, the red team must build a corresponding threat profile. This profile defines how the team will emulate this threat by identifying its intent, motivations, capabilities, habits, TTPs and so on. If it's a known threat, much of this information can be found from various threat intel sources. If it's a generic threat, the red team may construct a profile that reflects the typical capabilities of that type of threat. The MITRE ATT&CK is a great source of tactics and techniques. 6. Breach Model: The breach model outlines the means by which the

=== UNIT 14 ===
Source: MalDevAcademy - Offensive Phishing Operations Extra - shared by Tamarisk OffsecExam.html
Value: 0.85  Key cues: Ansible, architecture diagram, control node, managed nodes
Summary: The unit contains a diagram illustrating the architecture of an Ansible configuration management system, including control and managed nodes.
Excerpt:
Visual caption: A diagram illustrating the architecture of an Ansible configuration management system with a control node and managed nodes. Visible text: Control node; Ansible + Inventory; Managed nodes; Managed node 1; Managed node 2; Managed node 3 Alt/source label:

=== UNIT 15 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows data types, interchangeable types (HINSTANCE, HMODULE), code readability, development best practices
Summary: This module summarizes the importance of using standard Windows data types for clarity and consistency in development. It highlights that many Windows data types are interchangeable, such as HINSTANCE and HMODULE, and emphasizes learning their definitions to improve code readability.
Excerpt:
Module Summary In this module, we discussed many of the data types you will come across during your Windows development and during the rest of this course. We saw how many of those data types mean the same thing and thus, are interchangeable. We also saw how using types can make code look cleaner and more readable. I strongly recommend to use the Windows data types in your tools. The more you practice coding various capabilities, the more familiar and comfortable you will become with the Windows data types. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Learned you must become familiar with the Windows data types Learned you must become

=== UNIT 16 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows data types, HINSTANCE, HMODULE, SEC701
Summary: The unit provides a summary of Windows data types and their usage in red teaming. It highlights the importance of understanding these types to avoid technical issues and notes that some types are interchangeable.
Excerpt:
Visual caption: A summary slide from a SANS course on Windows data types and their usage in red teaming. Visible text: Module Summary; Learned you must become familiar with the Windows data types; Discussed how Windows data types could prevent future headaches; Learned some data types just stem from others: HINSTANCE and HMODULE; Discussed how seeing the definitions can help understand something better; Learned some data types are interchangeable: HINSTANCE and HMODULE; SEC701: Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 17 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Red Team, Military, Nation State, operational goals, purple teaming, tool development
Summary: The text discusses the different operational goals and authorities of various actors (Red Team, Military, Nation State) when developing tools for cyber operations. It highlights how tool development objectives vary based on the role's specific mandates, such as testing detections or performing destructive actions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Operational Actions Red Team: Persist, exfil data, pivot Military: Destroy, disrupt, deny, degrade, deceive Nation State: Espionage, disinformation, ransomware, etc. 9 Operational Actions After you have gotten to know your target a bit more, your objectives can be very different depending on the work role you are currently filling. If you are developing tools for a red team, you are probably not creating and releasing ransomware seeking out a payday. Instead, you might be working with the blue team to create a custom tool that is designed to test specific detections, which leads into purple teaming. If yo

=== UNIT 18 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Operational Actions, Red Team objectives, Military actions, Nation State tactics
Summary: The unit describes the differences in operational objectives between Red Team, Military, and Nation-State actors. It lists specific goals such as persistence, data exfiltration, and espionage for various entities.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Operational Actions' showing different objectives for Red Team, Military, and Nation State actors. Visible text: Operational Actions; Red Team: Persist, exfil data, pivot; Military: Destroy, disrupt, deny, degrade, deceive; Nation State: Espionage, disinformation, ransomware, etc.; SECF07 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: course roadmap, security training content, SANS SEC670, Windows Tool Development
Summary: This unit contains a course roadmap and overview of the SANS SEC670 Red Teaming Tools course. It lists various modules including Windows DLLs, Data Types, SAL Annotations, and Windows API usage for developing offensive tools.
Excerpt:
In this module, we will introduce some essential subject matter, concepts, and introductory topics required to perform advanced penetration testing and to proceed through this course. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Pe

=== UNIT 20 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Red Team as customer, requirement gathering, formal system, development shop
Summary: This unit discusses the organizational structure and workflow for developing custom tools to support a Red Team's requirements. It emphasizes the importance of formal requirement gathering from the Red Team as the primary customer, using systems like Jira or Word documents to track requests.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Requirements The Red Team is your customer The Red Team is your customer 14 Most mature organizations with a dedicated developer shop directly support the company’s internal Red Team. The Red Team will be a client of yours and should be producing a list of requirements that are needed for their engagements. Your objective will be to satisfy those requirements and release a tool to them. Requirements When it comes to determining how to make a capability that does X, Y, and Z things, you need to think of the end user of your tool and how they might want it deployed in an engagement. When the roles are split

=== UNIT 21 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Object Manager, kernel vs executive vs user objects, CreateFile/CreateThread API calls, system resource representation
Summary: The text describes the Windows object manager and how system resources like files, images, threads, and registry keys are represented as data structures. It explains the difference between kernel objects, executive objects, and user objects while detailing the role of the system's common interface for managing these resources.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (1) System resources represented as data structures in system address space System resources represented as data structures in system address space Files, images, threads, registry keys, and processes are several object types. Files, images, threads, registry keys, and processes are several object types. The Windows kernel does the hard work creating an object often at the request of a user application. There are over 4,000 object types that the Windows executive implements, some of which are not accessible via Windows APIs. 165 Windows Objects (1) Objects in Windows are simply the system’

=== UNIT 22 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Group Exercise, Red team lead, requirements analysis, timeline for release
Summary: The unit describes a group exercise scenario where students are tasked with analyzing requirements from a Red Team lead. They must identify technically impossible tasks, clarify ambiguous requirements, and establish a release timeline.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Group Exercise' outlining requirements for a new capability. Visible text: Group Exercise; Scenario: You have just received requirements from the Red Team lead; Go over the requirements; Determine which ones are not technically possible; Determine which ones need more of an explanation; Give a timeline for release; SECF23 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 23 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: requirement analysis, 32-bit/64-bit binaries, DLL payloads, 400kb limit, code injection, persistence, privilege escalation, user-mode hooks bypass
Summary: This unit presents a group exercise involving the analysis of requirements for a new red team capability. It lists specific technical requirements such as multi-architecture support, size constraints, and various features like code injection, persistence, and privilege escalation.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Group Exercise Scenario: You have just received requirements from the Red Team lead Scenario: You have just received requirements from the Red Team lead 15 Go over the requirements Determine which ones are not technically possible Determine which ones need more of an explanation Discuss a timeline for release Group Exercise Let us pause for a moment and go over a scenario where you are the team lead for the development shop. The Red Team lead has just created a ticket that has a fairly large number of requirements in it for a new capability for an upcoming engagement they have. The Red Team will be facing

=== UNIT 24 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Objects, object header, object body, Object Manager, ObTypeIndexTable, handle count
Summary: The text describes the structure and management of Windows objects, specifically focusing on object headers and bodies. It explains how the Object Manager handles creation, validation, rights, and handle counts for these objects. The content covers technical details regarding the ObTypeIndexTable and the mechanism for tracking open handles.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (4) Every object has the same structure Every object has the same structure object header object header This means that there can be one portion of the system that manages all objects. The appropriately named object manager has the role of maintaining all objects. object body object body - type - name - directory - security descriptor - handle count and list - optional subheaders - unique to the object type 168 Windows Objects (4) The object manager can perform several tasks, such as following: - Create objects and validate that a process has the rights to use that object. - Create the obj

=== UNIT 25 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Objects, object manager, query/set security, CloseHandle, file object, process object
Summary: The text describes the Windows object model, specifically how objects have generic services (like CloseHandle) and specific services (like create, open, query). It explains that while object headers are standardized to allow for common operations, different types of object bodies contain unique functionality. The section highlights the differences between creating file objects versus process objects.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (5) Objects have services that can operate on them. Objects have services that can operate on them. Close, duplicate, query/set security, wait for single object, duplicate, etc. Close, duplicate, query/set security, wait for single object, duplicate, etc. The Windows subsystems makes these services available to Windows applications. All objects, regardless of type, support several generic services. In addition, each object will have its own services like create, open, and query. 169 Windows Objects (5) With the standardization of object headers and sub headers, the object manager can provi

=== UNIT 26 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Objects, access control list (ACL), security descriptors, object manager, Process Explorer, GENERIC_READ, GENERIC_WRITE
Summary: The text describes the security mechanisms of Windows objects, specifically how they are protected by access control lists (ACLs) and security descriptors. It explains that the object manager acts as a gatekeeper for user-mode exposed objects while internal kernel objects may not require the same protections. The section also mentions using Process Explorer to view and inspect handles to these objects.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Objects (6) Objects can leverage the security of Windows. Objects can leverage the security of Windows. “You shall not pass!” “You shall not pass!” Objects that are exposed to user mode must be protected. Objects will have their own access control list (ACL) that dictates what actions can be performed on the object from a querying process. Securable objects have security descriptors, and the system acts as the gatekeeper to the objects. 170 Windows Objects (6) Objects must be secured or protected from malicious abuse or unauthorized access. Whenever an object is exposed directly to the user, it mu

=== UNIT 27 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Handles, multiple of 4, handle value of 0, 32-bit / 64-bit
Summary: This unit describes the fundamental mechanics of Windows Handles, explaining how they serve as identifiers for interacting with system objects like processes, registry keys, and threads. It details technical specifications such as handle values being multiples of 4, never being zero, and varying by architecture (32-bit/64-bit).
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Windows Handles (1) Handles act as the mechanism to interact with objects. Handles act as the mechanism to interact with objects. Always a multiple of 4 Always a multiple of 4 Named objects that are created will have handles to them. The handle is what the application needs in order to interact directly with the object. Never handle value of 0 Never handle value of 0 First valid handle is always 4 First valid handle is always 4 32-bit / 64-bit handle values 32-bit / 64-bit handle values 171 Windows Handles (1) Handles are the mechanism in place that allow a user mode application to interact with an object

=== UNIT 28 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Course Roadmap, s1-developing offensive tools, Windows DLLs, Shellcode, Evasion
Summary: The unit contains a slide outlining the course roadmap for a Windows Tool Development training program. It lists various modules including development environment setup, Windows DLLs, and advanced techniques like shellcode and evasion.
Excerpt:
Visual caption: A slide titled 'Course Roadmap' outlining the modules for a Windows Tool Development course. Visible text: Course Roadmap; Windows Tool Development; Getting Your Target; Operational Actions; Persistence: Die Another Day; Enhancing Your Implant: Shellcode, Evasion, and C2; Capture the Flag Challenge; Section 1; Developing Offensive Tools; Setting Up Your Development Environment; Windows DLLs; Windows Data Types; Call Me Maybe; SAL Annotations; Windows API; Bootcamp Alt/source label:

=== UNIT 29 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: SANS SEC670, Course Roadmap, Windows Tool Development, Windows DLLs, Windows API
Summary: The text provides a course roadmap and overview for the SANS SEC670 Red Teaming Tools course. It lists specific modules including Windows DLLs, Data Types, SAL Annotations, and Windows API calls.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 17 In this module, we will discuss what it means to develop offensive tools

=== UNIT 30 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: SANS SECF06, Offensive mindset, Development of Windows Implants, Shellcode, Command and Control
Summary: The unit contains a slide from a SANS Institute course introducing the offensive mindset for red teaming. It lists core topics including developing Windows implants, shellcode, and command and control systems.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Developing Offensive Tools' featuring an introductory text about the offensive mindset. Visible text: Developing Offensive Tools; Offensive mindset; Offensive, you are; SECF06; Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 31 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Windows Tool Development, Shellcode, Evasion, C2, Lab 1.7 - 1.10
Summary: The text lists a series of labs and sections related to Windows tool development, including topics like shellcode, evasion, and C2. It also mentions a bootcamp portion of the class with lecture-free time for practice.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Lab 1.7: Can'tHandleIt Lab 1.7: Can'tHandleIt Lab 1.8: RegWalker Lab 1.9: It's Me, WinDbg Lab 1.10: ShadowCraft S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 198 The bootcamp portion of the class is really extended class hours but without the lecture. This will give you lecture-free time for you to go back and practice labs again or take on a few of the challenges listed on the next slide. 198 © SANS Institute 2024 f80c9b76f5e518e0

=== UNIT 32 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: offensive tooling, red team ops, audit requirements, national security
Summary: The unit discusses the necessity of offensive tools in red teaming and cybersecurity operations. It highlights reasons such as fulfilling audit requirements, national security needs, and practicing against realistic threats to improve defensive capabilities.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Purpose Do we even need to have offensive tools in our arsenal? Why can’t we just have defensive tools everywhere? Defensive tools can’t always catch everything Can always count on a nation-state to be there Allows companies to strengthen their defenses Keeps giving you a paycheck 19 Purpose Offensive tooling is necessary for several reasons, the first one is that you probably would not have a job without it. Several organizations might even require external assessments to be conducted every so often. Financial institutions have audit requirements that must take place at certain intervals, and an external

=== UNIT 33 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Metasploit, Cobalt Strike, Empire, Mimikatz, PsExec, Eternal*, SEC701
Summary: The unit describes current state-of-the-art frameworks and tools used in red teaming. It lists specific tools such as Metasploit, Cobalt Strike, Empire, Mimikatz, and PsExec.
Excerpt:
Visual caption: A slide titled 'Current State of the Art Frameworks and Tools' listing several cybersecurity tools like Metasploit, Cobalt Strike, Empire, Mimikatz, and PsExec. Visible text: Current State of the Art Frameworks and Tools; Metasploit Framework; Cobalt Strike; Empire; Mimikatz; PsExec; Eternal*; SEC701 / Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 34 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Future, code repositories, API usage, SANS SEC679
Summary: The unit contains a presentation slide discussing future trends in tool development, specifically regarding time constraints, code repository policies, and API usage. It highlights the limitations of tools based on creative API utilization.
Excerpt:
Visual caption: A presentation slide titled 'Future' discussing the implications of time, code repositories, and API usage on tool development. Visible text: Future; How will time change how we develop tools?; Will code repos eventually ban the storage of such tools?; New tools are limited by your creative use of the APIs.; SANS SEC679 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 35 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: Module Summary, offensive security tools, SANS SEC670, Red Teaming Tools
Summary: The unit contains a summary slide from a SANS Institute course on red teaming tools. It lists learning objectives such as understanding offensive security tool needs, current state-of-the-art frameworks, and knowledge sharing.
Excerpt:
Visual caption: A slide from a SANS Institute course titled 'Module Summary' listing key learning objectives. Visible text: Module Summary; Discussed the need for offensive security tools; Discussed the current state of the art frameworks and offensive tools; Learn to share your knowledge; be a mentor; SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 36 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: SANS SEC670, Course Roadmap, curriculum outline, Windows Tool Development
Summary: The text provides a course roadmap and overview of the SANS SEC670 Red Teaming Tools course. It lists specific modules including Windows DLLs, Windows Data Types, SAL Annotations, and various labs involving PE-sieve and ProcMon.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Course Roadmap Course Overview Developing Offensive Tools Developing Defensive Tools Lab 1.1: PE-sieve, Lab 1.2: ProcMon Setting Up Your Development Environment Windows DLLs Lab 1.3: HelloDLL Windows Data Types Call Me Maybe Lab 1.4: Call Me Maybe SAL Annotations Lab 1.5: Safer with SAL Windows API Lab 1.6: CreateFile Bootcamp S e c t i o n 1 • Windows Tool Development • Getting to Know Your Target • Operational Actions • Persistence: Die Another Day • Enhancing Your Implant: Shellcode, Evasion, and C2 • Capture the Flag Challenge 24 In this module, we will discuss the development of defensive tools, thei

=== UNIT 37 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: defensive development, cat and mouse game, purposes of defensive tools, secure programming
Summary: The text discusses the necessity and role of vision for defensive tools in the cybersecurity landscape, highlighting the 'cat and mouse' game between offensive and defensive technologies. It also emphasizes the importance of aware programming as a technique to make exploitation harder for attackers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Purpose + Defensive development || Defensive tools Defensive mindset Defensive, you are Defensive tools are mainly designed to catch the usage of offensive tools. This creates the “cat and mouse” game that keeps everyone gainfully employed. 25 Purpose Just like offensive tools, there is a necessity for defensive tools. Many companies profit from selling their defensive tools and there is nothing wrong with that. There have been many defensive tools that have been open sourced and pushed to GitHub for all the world to see. Some are truly open source while others are simply freeware, and there is nothing wr

=== UNIT 38 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: SEC670, Windows Tool1, Red Teaming Tools, title slide
Summary: The unit contains a title slide for the SANS SEC670 course on Windows Tool Development. It lists key topics including developing Windows implants, shellcode, and command and control systems.
Excerpt:
Visual caption: A title slide for a SANS Institute course on Windows Tool Development. Visible text: SEC670.1; SANS; Windows Tool Development; Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 39 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: What's the Point?, SEC679, Red Teaming Tools, Development of Windows Implants, Shellcode, Command and Control
Summary: The unit contains a presentation slide titled 'What's the Point?' which introduces the core concepts of red teaming tools, specifically focusing on development for Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A presentation slide titled 'What's the Point?' with a central question box. Visible text: What's the Point?; SEC679 | Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 40 ===
Source: SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows - Book 1 - Windows Tool Development.pdf
Value: 0.85  Key cues: PE-sieve, defensive tool development, AI/ML integration, Rust programming
Summary: The unit summarizes the module's content regarding the necessity of developing defensive security tools and mentions specific technologies like PE-sieve. It also highlights trends in AI/ML integration, the popularity of Rust for development, and the importance of community contribution.
Excerpt:
Module Summary In this module, we discussed several reasons why it is necessary to develop defensive security tools. We also discussed a few tools like PE-sieve, the current state of the art tools, and the future of more advanced tools with better AI/ML integration. SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Module Summary Learned AI/ML is getting better Learned Rust is becoming more popular Discussed how defensive tools are getting more advanced Discussed how you should contribute however you can 33 33 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam
