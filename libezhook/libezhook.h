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

// find entry from global entry list
__declspec(dllexport) ezhook_entry* __stdcall find_entry(void* target);

// find hook from entry
__declspec(dllexport) ezhook* __stdcall find_hook(ezhook_entry* entry, void* detour);

// set trampline's owner
__declspec(dllexport) void __stdcall tl_set_owner(void* trampline, ezhook* hook);

// hook a function, return its trampline
__declspec(dllexport) void* __stdcall hook(void* target, void* detour);

// hook a api function, return its trampline
__declspec(dllexport) void* __stdcall hook_api(const char* module_name, const char* proc_name, void* detour);

// unhook a function
__declspec(dllexport) void __stdcall unhook(void* target, void* detour);
