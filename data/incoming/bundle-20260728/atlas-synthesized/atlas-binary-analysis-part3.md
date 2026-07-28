# Atlas Material — binary-analysis (part 3)

Source: SANS SEC670 / MalDev Academy / CRTO
Topic category: binary_exploit
Units: 40

Each unit below is a summarized page or section from premium offensive security
training material. Identify which HUGIN techniques (T-NNN) each piece of
knowledge relates to, and synthesize concept nodes, edges, and detection insights.

---
=== UNIT 1 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FindNextFileA, Windows programming, BOOL return type
Summary: The unit describes the FindNextFileA API function in Windows programming. It explains that the function is used to continue a search and returns a BOOL type.
Excerpt:
Visual caption: A slide explaining the FindNextFileA API function used in Windows programming. Visible text: FindNextFileA API; FindNextFileA(); Used to continue a search; Has BOOL return type; SEC607 | Red-Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 2 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FindNextFileA, directory walk, WIN32_FIND_DATAA, BOOL return type, GetLastError
Summary: The text describes the FindNextFileA API, which is used in conjunction with FindFirstFileA to iterate through files in a directory. It explains the function's parameters (handle and structure pointer), its return type of BOOL, and how it is typically used within a loop for directory walking.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control FindNextFile API FindNextFileA() FindNextFileA() Used to continue a search Used to continue a search BOOL FindNextFileA( _In_ HANDLE hFindFile, _In_ LPWIN32_FIND_DATAA pFindFileData ); // example do { // do stuff with the info } while ( FindNextFileA(hSearch, FindData) != 0 ); Has BOOL return type Has BOOL return type 80 FindNextFile API The next API we need to use to implement our directory walk is the FindNextFile API, which is really a macro that expands to FindNextFileA for ANSI, or FindNextFileW for Unicode. For this example, we will be using the ANSI version of the macro. The FindNextFileA function 

=== UNIT 3 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FindClose API, file search handle, query of BOOL return type, GetLastError
Summary: The unit describes the FindClose API, which is used to close file search handles after a directory walk or file search operation. It details the function's signature, return type (BOOL), and error handling via GetLastError.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control FindClose API FindClose() FindClose() Used to close a file search handle Used to close a file search handle BOOL FindClose( _Inout_ HANDLE hFindFile ); // example FindClose( hsearch ); Has BOOL return type Has BOOL return type 81 FindClose API After you are done searching for files or performing your directory walk, the file search handle should be closed out. The FindClose API can do this for us, and it is a very simple API to understand and implement in code. FindClose only takes one argument and that is a valid file search handle. The return type is BOOL so you could check to see if the function was su

=== UNIT 4 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: FindClose API, s701, Windows programming, implants
Summary: The unit describes the FindClose API function in Windows programming. It details the technical specifications of the function, including its return type and parameters.
Excerpt:
Visual caption: A slide from a SANS Institute course explaining the FindClose API function in Windows programming. Visible text: FindClose API; FindClose(); Used to close a file search handle; Has BOOL return type; BOOL FindClose(INOUT_HANDLE hFindFile); SEC701 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 5 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: WIN32_FIND_DATA, user-mode structure, file attributes
Summary: The unit contains a review question regarding the specific user-mode structure that holds file attributes in Windows. It lists multiple options for structures like WIN32_FIND_DATA, KUSER_SHARED_DATA, and FILE_OBJECT.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Unit Review Questions What user-mode structure holds the attributes of a file? What user-mode structure holds the attributes of a file? A WIN32_FIND_DATA A WIN32_FIND_DATA B KUSER_SHARED_DATA B KUSER_SHARED_DATA C FILE_OBJECT C FILE_OBJECT 86 Unit Review Questions Q: What user-mode structure holds the attributes of a file? A: WIN32_FIND_DATA B: KUSER_SHARED_DATA C: FILE_OBJECT 86 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 6 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetUserProfileDirectoryA, user profile path, buffer size calculation, OpenProcessToken, LPSTR
Summary: The text describes the GetUserProfileDirectoryA API, which is used to retrieve the root directory of a user's profile. It details the function signature, its parameters (hToken, lpProfileDir, and lpcchSize), and explains how to use it with a buffer size check.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control GetUserProfileDirectory API GetUserProfileDirectoryA() GetUserProfileDirectoryA() Used to obtain the root directory of the user’s profile Used to obtain the root directory of the user’s profile USERENVAPI BOOL GetUserProfileDirectoryA( _In_ HANDLE hToken, _Out_opt_ LPSTR lpProfileDir, _In_opt_ LPDWORD lpcchSize ); Has BOOL return type Has BOOL return type 92 GetUserProfileDirectory API The GetUserProfileDirectory API is useful when you would like to know the path of the root folder for the username that was passed into the function. The GetUserProfileDirectory API is another macro, so we should know what 

=== UNIT 7 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NetUserEnum, API signature, parameter list
Summary: The unit describes the NetUserEnum API function signature and its associated parameters such as servername, level, and filter. It is presented in a format suitable for identifying specific Windows API calls.
Excerpt:
Visual caption: A slide presenting the NetUserEnum API function signature and its parameters. Visible text: NetUserEnum API; NetUserEnum(); NET_API_STATUS; NET_API_FUNCTION; servername; level; filter; lpbyte_buffer; entriesread; totalentries; resume_handle Alt/source label:

=== UNIT 8 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: LPDWORD, resume_handle, user account querying
Summary: The text describes the parameters for a function used to query user accounts, specifically entriesread, entries_total, and resume_handle.
Excerpt:
entriesread, of type LPDWORD, is a pointer to the variable that will hold the number of entries the function queried. totalentries, of type LPDWORD, is a pointer to the variable that will hold the number of entries that could have been queried from a position called the resume position. resume_handle, of type PDWORD, is a pointer to a variable that is used as the resume handle. The resume handle can be used to continue searching user accounts and if this is what you want to do, then zero (0) should always be used for the first call. If you do not care about this, then passing NULL here is just fine. 94 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 9 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: SERVICE_WIN32_OWN_PROCESS, Windows service flags, Unit Review
Summary: The unit contains a multiple-choice question and answer regarding Windows service flags, specifically the SERVICE_WIN32_OWN_PROCESS flag. It explains whether the service shares an address space with other processes.
Excerpt:
Visual caption: A slide from a SANS Institute course showing the correct answer to a multiple-choice question about Windows service flags. Visible text: Unit Review Answers; What does SERVICE_WIN32_OWN_PROCESS indicate?; The service shares its address space with other processes; The service does not share its address space with other processes; The service will be hidden from view Alt/source label:

=== UNIT 10 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: COM library, CoInitialize, CoCreateInstance, review questions
Summary: The unit contains a multiple-choice review question regarding the COM library's initialization methods. It specifically mentions functions like CoCreateInstance, CoInitialize, and CoMemFree.
Excerpt:
Visual caption: A slide from a SANS Institute course showing a multiple-choice question about COM library initialization. Visible text: Unit Review Questions; How do you get the COM library ready for use in your process?; CoCreateInstance; CoInitialize; CoMemFree Alt/source label:

=== UNIT 11 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetAdapterAddresses, ULONG return type, SANS Institute
Summary: The unit describes the GetAdapterAddresses API function in Windows programming, specifically noting its purpose of retrieving adapter-related addresses. It mentions the function's return type and identifies it as part of a SANS Institute presentation.
Excerpt:
Visual caption: A slide from a technical presentation explaining the GetAdapterAddresses API function in Windows programming. Visible text: GetAdapterAddresses API; GetAdapterAddresses(); Grabs the addresses tied to the other adapters; Has ULONG return type; SANS Institute Alt/source label:

=== UNIT 12 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ERROR_SUCCESS, error codes, buffer size, memory allocation
Summary: The text describes the error codes returned by a specific function when it fails to execute successfully. It lists five distinct error codes: ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, and ERROR_NO_DATA.
Excerpt:
Upon success, the function will return ERROR_SUCCESS. Should the function ever fail it will return one of the following error codes: - ERROR_ADDRESS_NOT_ASSOCIATED: An address has yet to be associated with the device. - ERROR_BUFFER_OVERFLOW: The buffer size indicated is not large enough to hold the requested information. - ERROR_INVALID_PARAMETER: SizePointer is NULL, Family was not a valid family option. - ERROR_NOT_ENOUGH_MEMORY: Literally not enough memory to complete the function. - ERROR_NO_DATA: No addresses found. 123 © SANS Institute 2024 f80c9b76f5e518e0ab6ab5c122e7bb7a https://linktr.ee/offsecexam

=== UNIT 13 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: GetNumberOfInterfaces, DWORD return type, network interfaces
Summary: The unit describes the GetNumberOfInterfaces API used to enumerate network interfaces. It specifies that the function returns a DWORD value representing the count of available interfaces.
Excerpt:
Visual caption: A slide from a SANS Institute course explaining the GetNumberOfInterfaces API. Visible text: GetNumberOfInterfaces API; Grabs the number of interfaces; Has DWORD return type; SEC701 Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 14 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegOpenKeyExW, HKEY, registry key handle, out-parameter
Summary: The unit provides a code example for the RegOpenKeyExW function in C++. It explains how to obtain a handle to a registry key and describes the purpose of the out-parameter for the handle variable.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegOpenKeyEx INT main(VOID) { HKEY hHKCU = HKEY(); RegOpenKeyExW(HKEY_CURRENT_USER, L”Console”, NULL, KEY_READ, &hHKCU); } 145 Example: RegOpenKeyEx The example here initializes a variable of type HKEY that will be used to store the handle that the function gives upon success. Just like the function declares, the last parameter must be the address of the variable. Afterall, it is an _Out_ parameter so the user is responsible for making that available for the function to use. The function doesn’t “return” a handle because this function returns an LSTATUS value that could be used to determine why i

=== UNIT 15 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegOpenKeyExW, HKEY, LSTATUS, registry key access
Summary: The unit provides a code example for the RegOpenKeyExW function in C to open a registry key. It explains how the handle is returned via an _Out_ parameter and why LSTATUS values are used instead of direct handles.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegOpenKeyEx INT main(VOID) { HKEY hHKCU = HKEY(); RegOpenKeyExW(HKEY_CURRENT_USER, L”Console”, NULL, KEY_READ, &hHKCU); } 145 Example: RegOpenKeyEx The example here initializes a variable of type HKEY that will be used to store the handle that the function gives upon success. Just like the function declares, the last parameter must be the address of the variable. Afterall, it is an _Out_ parameter so the user is responsible for making that available for the function to use. The function doesn’t “return” a handle because this function returns an LSTATUS value that could be used to determine why i

=== UNIT 16 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegQueryValueExW, Registry Keys and Values, LSTATUS, SEC-07
Summary: The unit describes the technical details of the RegQueryValueExW function in Windows programming. It specifically covers its return type (LSTATUS) and its purpose for reading registry key values.
Excerpt:
Visual caption: A slide from a technical training course about the RegQueryValueExW function in Windows programming. Visible text: Registry Keys and Values (2); RegQueryValueEx; Return value is LSTATUS; Used to read the type and data of a Registry key value; SEC-07 / Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 17 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegQueryValueExW, LSTATUS, Winreg.h, Registry Keys and Values, FormatMessage
Summary: The unit describes the RegQueryValueExW function in the Windows API, detailing its parameters and return types. It explains how to interpret error codes using FormatMessage and provides specific details for each parameter like hKey, lpValueName, and lpData.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Registry Keys and Values (2) RegQueryValueEx RegQueryValueEx Return value is LSTATUS Return value is LSTATUS //declared in Winreg.h LSTATUS RegQueryValueExW( _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName, _Reserved_ LPDWORD lpReserved, _Out_opt_ LPDWORD lpType, _Out_ LPBYTE lpData, _Inout_opt_ LPDWORD lpcbData ); Used to read the type and data of a Registry key value Used to read the type and data of a Registry key value 146 Registry Keys and Values (2) Again, we have an LSTATUS return type, so the error code can be looked up using FormatMessage function passing in the FORMAT_MESSAGE_FROM_SYSTEM flag for a

=== UNIT 18 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegEnumKeyValues, Windows API, RegEnumKeyValue, SEC701
Summary: The unit describes the technical details of the `RegEnumKeyValues` function within the Windows API. It specifically covers its return type and purpose for enumerating a key's value.
Excerpt:
Visual caption: A slide titled 'Walking the Registry' explains the technical details of the `RegEnumKeyValues` function in Windows API. Visible text: Walking the Registry (2); RegEnumKeyValue; Return value is a LONG; Used to enumerate a key's value; SEC701 - Red Team Tools: Developing Windows, PowerShell, Shellcode, Command and Control Alt/source label:

=== UNIT 19 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegEnumValue, registry key retrieval, looping mechanism, lpValueName, ERROR_NO_MORE_ITEM
Summary: The text describes the implementation of the RegEnumValue function in a loop to retrieve registry keys. It details specific parameter handling for buffer sizes, null termination, and iteration logic using the ERROR_NO_MORE_ITEMS code.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegEnumValue 150 Example: RegEnumValue The example here shows the function being used in a loop with the index variable being used as the loop iterator value, or counter. The key handle is passed followed by the dwIndex value, which is an index of the value that is to be retrieved. It is a good idea to have this value be NULL on the first iteration. Incrementing the value is fine for subsequent calls. The name of the key will be stored in the keyName buffer for the lpValueName parameter. The lpcchValueName parameter, upon return, will hold the character count stored in the buffer. Note, the count

=== UNIT 20 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegQueryForKey, LSTATUS return value, registry key information, microsoft error codes
Summary: The unit describes the `RegQueryForKey` function used to query and gather detailed information about registry keys in a Windows environment. It references specific documentation for system error codes.
Excerpt:
Visual caption: A slide from a security course titled 'Walking the Registry' explaining the `RegQueryForKey` function and its parameters. Visible text: Walking the Registry (3); RegQueryForKey; Return value is LSTATUS; Used to gather detailed information about keys.; SEC701 / Red Teaming Operating System...; https://dice.microsoft.com/en-us/windows/10/ms2032/system-error-codes Alt/source label:

=== UNIT 21 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegQueryInfoKey, LSTATUS, lpcSubKeys, lpcValues, WinError.h
Summary: The unit describes the RegQueryInfoKey API for retrieving detailed information about registry keys, including subkeys and values. It explains how to parse its numerous parameters, specifically focusing on LPDWORD types and optional fields like lpcSubKeys and lpcValues. The text also notes that it returns a system error codes from WinError.h.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Walking the Registry (3) RegQueryInfoKey RegQueryInfoKey Return value is LSTATUS Return value is LSTATUS //declared in Winreg.h LSTATUS RegQueryInfoKeyW( _In_ HKEY hKey, _Out_writes_to_opt_(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass, _Inout_opt_ LPDWORD lpcchClass, _Reserved_ LPDWORD lpReserved, _Out_opt_ LPDWORD lpcSubKeys, _Out_opt_ LPDWORD lpcbMaxSubKeyLen, _Out_opt_ LPDWORD lpcbMaxClassLen, _Out_opt_ LPDWORD lpcValues, _Out_opt_ LPDWORD lpcbMaxValueNameLen, _Out_opt_ LPDWORD lpcbMaxValueLen, _Out_opt_ LPDWORD lpcbSecurityDescriptor, _Out_opt_ PFILETIME lpftLastWriteTime ); Used to gather detailed inf

=== UNIT 22 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: RegQueryInfoKey, registry key info, parameter mapping, C code example
Summary: The unit describes the implementation details of the RegQueryInfoKey function for retrieving registry information. It outlines specific parameters required to populate variables such as subkey counts, maximum name lengths, and security descriptors.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Example: RegQueryInfoKey 152 Example: RegQueryInfoKey The example here shows how RegQueryInfoKey could be called. A standard handle to a key is given followed by three NULL values: lpClass, lpcClass, and lpReserved. Next, the address of the cSubKeys variable is passed so the function can write the number of subkeys contained by that key. Next, the address of the cbMaxSubKey variable is passed so the function can write the size of the key with the longest name, minus the NULL terminating character of course. Next, the address of the cbMaxClass variable is passed to receive the size of the longest string fo

=== UNIT 23 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE Format, sarchitecture agnostic, Executable images, Object files (COFF), SEC601, SEC670
Summary: The unit describes the Portable Executable (PE) format as an architecture-agnostic format for executable images and object files. It mentions specific course codes like SEC601 and SEC670.
Excerpt:
Visual caption: A slide from a training course about the Portable Executable (PE) format, detailing its complexity and types. Visible text: PE Format; Portable executable: the format is architecture agnostic; Executable images (PE); Object files (COFF); SEC601 | Red Teaming Tools: Developing Windows Implants, Shellcodes, Command and Control Alt/source label:

=== UNIT 24 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Basic Terminology, Reserved, RVA, Section, VA, SEC20
Summary: The unit provides a definition of basic terminology used in reverse engineering, specifically focusing on terms like Reserved, RVA, Section, and VA. These terms are essential for understanding the development of Windows implants.
Excerpt:
Visual caption: A slide titled 'Basic Terminology' defining terms like Reserved, RVA, Section, and VA for use in reverse engineering. Visible text: Basic Terminology; Reserved; RVA; Section; VA; SEC20 / Red Teaming Tools, Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 25 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Reserved, RVA, Section, VA, Portable Executable, image base address
Summary: This unit defines basic terminology related to the Portable Executable (PE) format, including Reserved fields, Relative Virtual Address (RVA), Sections, and Virtual Address (VA). It explains the differences between RVA and VA and describes how sections are structured within a PE file.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 7 Basic Terminology Some basic terminology that will show itself repeatedly Some basic terminology that will show itself repeatedly Reserved Reserved Any fields that are marked “reserved” must be 0 RVA RVA Section Section Relative virtual address: the address of an item subtracted from the image base address A small unit, or chunk, of code/data within the image. There can be several sections. VA VA Virtual address: address of an item within the virtual address space but not subtracted from image base Basic Terminology Whether you are browsing MSDN pages or blog posts related to the PE format, there are se

=== UNIT 26 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: PE file structure, MS-DOS 2.0 EXE header, OEM identifier, Section headers
Summary: The unit describes a diagram illustrating the structure of a Portable Executable (PE) file format. It identifies key components such as the MS-DOS 2.2 EXE header, OEM identifier, and various sections like section headers and image pages.
Excerpt:
Visual caption: A slide titled 'Bird's Eye View' displays a diagram of the structure of a PE file format. Visible text: Bird's Eye View; MS-DOS 2.0 EXE header; unused; OEM identifier: offset to PE header; MS-DOS 2.0 Sub; unused; PE header; Section headers; Image pages Alt/source label:

=== UNIT 27 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: MZ header, PE header, MS-DOS 2.0 EXE header, Section headers, Image pages
Summary: The text provides a high-level overview of the Portable Executable (PE) file format structure, specifically highlighting the MZ header and the path to the PE header. It describes the components like DOS stubs and section headers as part. of a larger diagram.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 8 Bird’s Eye View MS-DOS 2.0 EXE header unused OEM identifier: offset to PE header MS-DOS 2.0 Stub unused PE header Section headers Image pages Bird’s Eye View If you were to look at the PE format from a bird’s eye view, this is what it might look like. This is straight from the MSDN page for the PE format but represented in a graphic to make it more digestible. The first item is the infamous EXE header that is marked with “MZ”, which are the initials for the person who was a primary developer for MS-DOS, Mark Zbikowski. The more important item in that header is how to get to the PE header. The other majo

=== UNIT 28 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: MS-DOS 2.0 EXE Header, IMAGE_DOS_HEADER, SEC_F
Summary: The unit contains a visual caption describing an image of the MS-DOS 2.0 EXE header structure, including specific technical terms like IMAGE_DOS_HEADER and SEC_F.
Excerpt:
Visual caption: A slide from a presentation or tutorial about the MS-DOS 2.0 EXE header structure, showing code and descriptive text. Visible text: MS-DOS 2.0 EXE Header; IMAGE_DOS_HEADER; SEC_F; IMAGE_DOS_HEADER; IMAGE_DOS_HEADER Alt/source label:

=== UNIT 29 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_NT_HEADERS, PE signature, FileHeader, OptionalHeader, 32-bit/64-bit compatibility
Summary: The unit describes the IMAGE_NT_HEADERS structure used in Windows PE files, covering both 32-bit and 64-bit versions. It details specific fields such as Signature, FileHeader (including SizeOfOptionalHeader and NumberOfSections), and OptionalHeader.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 11 NT Headers typedef struct _IMAGE_NT_HEADERS { DWORD Signature; // 0x00 "PE”\0\0 IMAGE_FILE_HEADER FileHeader; // 0x04 IMAGE_OPTIONAL_HEADER32 OptionalHeader; // 0x18 } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32; typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64; #ifdef _WIN64 typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS; typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS; #else typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS; typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS; #endif NT Headers The next 

=== UNIT 30 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NT Headers, IMAGE_NT_HEADERS, IMAGE_OPTIONS_HEADER, SECTION.h
Summary: The unit describes the structure of PE file headers in Windows, specifically focusing on 'NT Headers' and 'IMAGE_NT_HEADERS'.
Excerpt:
Visual caption: A presentation slide titled 'NT Headers' explaining the structure of PE file headers in Windows. Visible text: NT Headers; IMAGE_NT_HEADERS; IMAGE_OPTIONAL_HEADER; SECTION.h; SEC027 | Red Team Tools...; © 2024 Jonathan Reiler Alt/source label:

=== UNIT 31 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_NT_HEADERS, 32-bit/64-bit compatibility, FileHeader, OptionalHeader, DataDirectory
Summary: The unit describes the IMAGE_NT_HEADERS structure for both 32-bit and 64-bit Windows applications, including its components like FileHeader and OptionalHeader. It highlights specific fields such as Signature, SizeOfOptionalHeader, and NumberOfSections within these structures.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 11 NT Headers typedef struct _IMAGE_NT_HEADERS { DWORD Signature; // 0x00 "PE”\0\0 IMAGE_FILE_HEADER FileHeader; // 0x04 IMAGE_OPTIONAL_HEADER32 OptionalHeader; // 0x18 } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32; typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64; #ifdef _WIN64 typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS; typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS; #else typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS; typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS; #endif NT Headers The next 

=== UNIT 32 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NT Headers, kernelbase.dll, IMAGE_DOS_HEADER, e_lfanew, image_nt_headers, Signature, PE signature
Summary: The text describes the structure of NT Headers within a Windows PE file, specifically focusing on the IMAGE_DOS_HEADER and its relationship to the IMAGE_NT_HEADERS struct. It details the requirements for the Signature field (PE) and explains how RVA values are used to locate headers.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 12 NT Headers: kernelbase.dll NT Headers: kernelbase.dll For this side-by-side screenshot, the purple is coming from the IMAGE_DOS_HEADER->e_lfanew. That value there is used as an RVA that is then added to the base address of kernelbase.dll to give us the location of the first field in the IMAGE_NT_HEADERS struct, the Signature. The ASCII on the right hand side of the screenshot shows the signature being PE. Also, take note the size of the Signature is not two (2) bytes like it is for the IMAGE_DOS_HEADER->e_magic. This one is a DWORD, or 4 (4) bytes, so the next two (2) NULL bytes are part of it. Do not 

=== UNIT 33 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: ELF file headers, kernel_module.dll, NT Headers, analysis
Summary: The unit contains a visual caption describing a terminal window showing the disassembly and analysis of ELF file headers for kernel_module.dll. It specifically highlights various header components like NT Headers, IMAGE_DOS_HEADER, and ENTRY_POINT.
Excerpt:
Visual caption: A screenshot of a terminal window showing the disassembly and analysis of ELF file headers, specifically focusing on 'NT Headers' for kernel_module.dll. Visible text: NT Headers: kernel_module.dll; IMAGE_DOS_HEADER; IMAGE_FILE_HEADER; IMAGE_FILE_HEADER_EXTRA; IMAGE_PE_HEADER; IMAGE_PE_HEADER_EXTRA; IMAGE_ENTRY_POINT; FileHeader; SEC_070 | Red Teaming Tools...; https://linktr.ee/offsecexam Alt/source label:

=== UNIT 34 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: NT Headers, kernelbase.dll, IMAGE_DOS_HEADER, e_lfanew, IMAGE_NT_HEADERS, Signature, PE
Summary: The text describes the structure of NT Headers within a Windows PE file, specifically focusing on the IMAGE_DOS_HEADER and its relationship to the IMAGE_NT_HEADERS struct. It details the purpose of the functions of fields like e_lfanew, e_magic, and Signature.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 12 NT Headers: kernelbase.dll NT Headers: kernelbase.dll For this side-by-side screenshot, the purple is coming from the IMAGE_DOS_HEADER->e_lfanew. That value there is used as an RVA that is then added to the base address of kernelbase.dll to give us the location of the first field in the IMAGE_NT_HEADERS struct, the Signature. The ASCII on the right hand side of the screenshot shows the signature being PE. Also, take note the size of the Signature is not two (2) bytes like it is for the IMAGE_DOS_HEADER->e_magic. This one is a DWORD, or 4 (4) bytes, so the next two (2) NULL bytes are part of it. Do not 

=== UNIT 35 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: File Header, IMAGE_FILE_HEADER, SEC70, Windows Implants
Summary: The unit describes a slide from a technical training course regarding the executable file header structure. It references the SEC70 curriculum on developing Windows implants, shellcode, and command and control.
Excerpt:
Visual caption: A slide from a technical training course about the structure of an executable file header. Visible text: File Header; typedef struct _IMAGE_FILE_HEADER; SEC70 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:

=== UNIT 36 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: Optional Header, IMAGE_OPTIONAL_HEADER64, C-style struct, PE files
Summary: The unit describes the structure of the Optional Header in PE files, specifically focusing on64-bit architectures. It includes C-style struct definitions for IMAGE_OPTIONAL_HEADER64 and fields like IMAGE_DATA_DIRECTORY.
Excerpt:
Visual caption: A screenshot of a technical document describing the Optional Header structure in PE files, including C-style struct definitions and explanatory text. Visible text: Optional Header; IMAGE_OPTIONAL_HEADER64; IMAGE_DATA_DIRECTORY; SEC02: Red Team_1.0 - Reading Windows Implants, Shellcode, Command and Control; page 15 Alt/source label:

=== UNIT 37 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: IMAGE_OPTIONAL_HEADER64, Magic field, PE32+, DllCharacteristics, DataDirectory, Import/Export entries
Summary: The text describes the structure and purpose of the IMAGE_OPTIONAL_HEADER64 for 64-bit Windows executables (PE32+). It details specific fields such as Magic, size fields, entry point, ImageBase, DllCharacteristics, and the DataDirectory.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 15 Optional Header typedef struct _IMAGE_OPTIONAL_HEADER64 { WORD Magic; // 0x20b BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode; SizeOfInitializedData; SizeOfUninitializedData; DWORD AddressOfEntryPoint; ULONGLONG ImageBase; WORD DllCharacteristics; ULONGLONG SizeOfStackReserve; SizeOfStackCommit; IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64; typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY; Optional Header First off, there are several fi

=== UNIT 38 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: kernelbase.dll, Optional Header, magic field, section alignment, file alignment, PE32+, memory mapping
Summary: The text discusses the structure and parsing of the Optional Header in a Windows PE file, specifically focusing on example data from kernelbase.dll. It details the significance of thes magic field values (0x10B or 0x20B) and how section/file alignment fields dictate memory mapping and permissions.
Excerpt:
SEC670 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control 16 Optional Header: kernelbase.dll Optional Header: kernelbase.dll This is the optional header from kernelbase.dll. The optional header is not as easy to parse because not all fields are the same size. As mentioned on the previous slide, there are a few places you can check to make sure you might be in the right place. The magic field can hold several values, but typically it will either be 0x10B or 0x20B for 32-bit (PE32) or 64-bit (PE32+), respectively. It would be very uncommon these days to see a different magic value for Windows binaries, but it could happen. The section and file alignment fields are

=== UNIT 39 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: kernelbase.dll, data directory, IMAGE_DIRECTORY_IMPORT, memory reading
Summary: The unit contains a technical slide describing the memory structure of kernelbase.dll, specifically focusing on its data directory and import tables.
Excerpt:
Visual caption: A slide from a technical presentation about the data directory of kernelbase.dll, showing a table and code snippet. Visible text: Optional Header: kernelbase.dll - data directory; DataDirectory; VirtualAddress; Size; IMAGE_DIRECTORY_IMPORT; IMAGE_DIRECTORY_ENTRY_IMPORT; SEC20 - Tool Reading Memory...; Optional Header: kernelbase.dll - data directory Alt/source label:

=== UNIT 40 ===
Source: All-books-in-one SANS SEC670 Red Teaming Tools - Developing Custom Tools for Windows.pdf
Value: 0.85  Key cues: kernelbase.dll, export list, terminal output
Summary: The unit contains a visual caption describing a screenshot of the terminal output for the `exports: kernelbase.dll` command. It lists various entries and their corresponding data types.
Excerpt:
Visual caption: A screenshot of a terminal window showing the output of the `exports: kernelbase.dll` command, listing various entries and their corresponding data types. Visible text: Exports: kernelbase.dll; kernelbase.dll; IMAGE_DATA_DIRECTORY; SEC20 | Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control Alt/source label:
