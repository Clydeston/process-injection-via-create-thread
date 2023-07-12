#pragma once
#include <Windows.h>
#include <subauth.h>

#define InitializeObjectAttributes(p,n,a,r,s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = (r); \
(p)->Attributes = (a); \
(p)->ObjectName = (n); \
(p)->SecurityDescriptor = (s); \
(p)->SecurityQualityOfService = NULL; \
}

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;


/* FUNCTION DEFINITIONS */
typedef NTSTATUS(NTAPI* pointer_to_allocate_virtual_mem)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* pointer_to_openprocess_func)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* pointer_to_nt_wpm)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, ULONG ReturnLength);
typedef NTSTATUS(NTAPI* pointer_to_nt_create_thread)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);