#pragma once

extern "C"
{
	// hook a function, return its trampline
	void* __stdcall hook(void* target, void* detour);

	// hook a api function, return its trampline
	void* __stdcall hook_api(const char* module_name, const char* proc_name, void* detour);

	// hook a virtual function, return its trampline
	void* __stdcall hook_virtual(void* class_pointer, unsigned int index, void* detour);

	// unhook a function
	void __stdcall unhook(void* target, void* detour);
}
