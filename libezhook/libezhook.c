#include "libezhook.h"

ezhook_entry* g_entries;

unsigned char g_trampline[0x74] = 
{
	0x89, 0x1D, 0x00, 0x00, 0x00, 0x00, //save ebx
	0x89, 0x35, 0x00, 0x00, 0x00, 0x00, // save esi
	0x89, 0x3D, 0x7B, 0x00, 0x00, 0x00, // save edi
	0xBE, 0x00, 0x00, 0x00, 0x00, // original bytes
	0xBB, 0x00, 0x00, 0x00, 0x00, // new bytes
	0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00, // target function
	0xB9, 0x05, 0x00, 0x00, 0x00, 0x83, 0xF9, 0x00, 0x74, 0x09, 0x8A, 0x06, 0x88, 0x07,
	0x46, 0x47, 0x49, 0xEB, 0xF2, 0x83, 0xEE, 0x05, 0x83, 0xEF, 0x05, 0x58, 
	0xA3, 0x00, 0x00, 0x00, 0x00,       // return address
	0xFF, 0xD7, 0x8B, 0xD0, 0xB9, 0x05, 0x00, 0x00, 0x00, 0x83, 0xF9, 0x00, 0x74, 0x09, 0x8A,
	0x03, 0x88, 0x07, 0x43, 0x47, 0x49, 0xEB, 0xF2, 0x8B, 0xC3, 
	0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00, // restore edi
	0x8B, 0x35, 0x00, 0x00, 0x00, 0x00, // restore esi 
	0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, // restore ebx
	0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, // return address
	0xC3
};

ezhook_entry* __stdcall find_entry(void* target)
{
	for (ezhook_entry* entry = g_entries; entry; entry = entry->next)
	{
		if (entry->target == target)
			return entry;
	}
	return NULL;
}

ezhook* __stdcall find_hook(ezhook_entry* entry, void* detour)
{
	for (ezhook* hook = entry->hooks; hook; hook = hook->next)
	{
		if (hook->detour == detour)
			return hook;
	}
	return NULL;
}

void __stdcall tl_set_owner(void* trampline, ezhook * hook)
{
	if (trampline == NULL || hook == NULL)
		return;

	unsigned char* utrampline = (unsigned char*)trampline;
	// set ebx
	*(unsigned int*)(utrampline + 0x2) = &hook->ebx;
	// set esi
	*(unsigned int*)(utrampline + 0x8) = &hook->esi;
	// set edi
	*(unsigned int*)(utrampline + 0xE) = &hook->edi;
	// set original bytes
	*(unsigned int*)(utrampline + 0x13) = &hook->original_bytes;
	// set new bytes
	*(unsigned int*)(utrampline + 0x18) = &hook->new_bytes;
	// set target function
	*(unsigned int*)(utrampline + 0x1E) = &hook->target;
	// set return address
	*(unsigned int*)(utrampline + 0x3D) = &hook->ret_addr;
	// set edi
	*(unsigned int*)(utrampline + 0x5C) = &hook->edi;
	// set esi
	*(unsigned int*)(utrampline + 0x62) = &hook->esi;
	// set ebx
	*(unsigned int*)(utrampline + 0x68) = &hook->ebx;
	// set return address
	*(unsigned int*)(utrampline + 0x6E) = &hook->ret_addr;
}

void* __stdcall hook(void* target, void* detour)
{
	// invalid hook
	if (target == NULL || detour == NULL)
		return;

	unsigned char* utarget = (unsigned char*)target;
	unsigned char* udetour = (unsigned char*)detour;

	// find entry fist
	ezhook_entry* entry = find_entry(target);

	// haven't hooked before
	if (entry == NULL)
	{
		// malloc a entry obj
		entry = (ezhook_entry*)malloc(sizeof(ezhook_entry));

		// malloc failed
		if (entry == NULL)
			return NULL;

		// init entry and add it to entry list
		entry->target = target;
		entry->hooks = NULL;
		entry->next = g_entries;
		g_entries = entry;
	}

	// malloc a hook object
	ezhook* hook = (ezhook*)malloc(sizeof(ezhook));

	// malloc failed
	if (hook == NULL)
		return NULL;

	// init hook
	hook->target = target;
	hook->detour = detour;

	// read original bytes
	memcpy(hook->original_bytes, target, 5);

	// construct new bytes
	hook->new_bytes[0] = 0xE9;
	// caculate offset
	unsigned int offset = udetour - (utarget + 5);
	// fill offset
	*(unsigned int*)&hook->new_bytes[1] = offset;

	// create a trampline 
	void* trampline = VirtualAlloc(NULL, 0x74, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// alloc failed?
	if (trampline == NULL)
		return NULL;

	// copy shell code
	memcpy(trampline, g_trampline, 0x74);

	// set trampline's owner
	tl_set_owner(trampline, hook);

	// set hook's trampline
	hook->trampline = trampline;

	// apply hook
	unsigned int old_protect;
	VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect);
	memcpy(target, hook->new_bytes, 5);

	// add hook to entry's list
	if (entry->hooks != NULL)
		entry->hooks->prev = hook;
	hook->prev = NULL;
	hook->next = entry->hooks;
	entry->hooks = hook;

	// return trampline
	return trampline;
}

void* __stdcall hook_api(const char* module_name, const char* proc_name, void* detour)
{
	// load library
	HMODULE module = LoadLibraryA(module_name);

	// load library failed?
	if (module == INVALID_HANDLE_VALUE)
		return NULL;

	// get proc
	void* proc = GetProcAddress(module, proc_name);

	// after works will prcocessed by hook
	return hook(proc, detour);
}

void __stdcall unhook(void* target, void* detour)
{
	// find entry
	ezhook_entry* entry = find_entry(target);

	// no entry?
	if (entry == NULL)
		return;
	
	// find hook
	ezhook* hook = find_hook(entry, detour);

	// no hook?
	if (hook == NULL)
		return;

	ezhook* prev_hook = hook->prev;
	ezhook* next_hook = hook->next;

	// if the hook is the last one
	if (prev_hook == NULL)
	{
		// restore bytes
		memcpy(hook->target, hook->original_bytes, 5);

		// remove from list 
		if (next_hook)
			next_hook->prev = prev_hook;

		// set entry hooks
		entry->hooks = next_hook;
	}
	else
	{
		// set prev_hook's new bytes to hook's original bytes
		memcpy(prev_hook->original_bytes, hook->original_bytes, 5);


		// remove from list
		if (next_hook)
			next_hook->prev = prev_hook;
		prev_hook->next = next_hook;
	}

	// free trampline
	VirtualFree(hook->trampline, 0x74, MEM_RELEASE);

	// free hook
	free(hook);
}

typedef int(__stdcall* MessageBoxAFn)(HWND, LPCSTR, LPCSTR, UINT);

MessageBoxAFn OMessageBoxA = NULL;

int __stdcall HookedMessageBoxA(HWND hwnd, LPCSTR text, LPCSTR title, UINT type)
{
	OMessageBoxA(hwnd, "SUCCESS", "SUCCESS", type);
}

int main()
{
	OMessageBoxA = hook_api("user32.dll", "MessageBoxA", HookedMessageBoxA);
	MessageBoxA(NULL, "FAILED", "FAILED", 0);
}
