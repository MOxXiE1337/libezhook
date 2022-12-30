#pragma once
#include <Windows.h>

typedef struct _ezhook
{
	void* target;
	void* detour;
	void* ret_addr;
	void* trampline;
	unsigned char original_bytes[5];
	unsigned char new_bytes[5];
	void* ebx;
	void* esi;
	void* edi;
	struct _ezhook* prev;
	struct _ezhook* next;
} ezhook;

typedef struct _ezhook_entry
{
	void* target; // key
	ezhook* hooks;
	struct _ezhook_entry* next;
} ezhook_entry;

// hook a function, return its trampline
__declspec(dllexport) void* __stdcall hook(void* target, void* detour);

// hook a api function, return its trampline
__declspec(dllexport) void* __stdcall hook_api(const char* module_name, const char* proc_name, void* detour);

// hook a virtual function, return its trampline
__declspec(dllexport) void* __stdcall hook_virtual(void* class_pointer, unsigned int index, void* detour);

// unhook a function
__declspec(dllexport) void __stdcall unhook(void* target, void* detour);
