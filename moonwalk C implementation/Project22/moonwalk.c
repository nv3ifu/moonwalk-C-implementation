#include <windows.h>
#include <stdio.h>
#include <string.h>

// External ASM functions
extern void* get_teb(void);
extern void* get_stack_base(void);
extern void* get_stack_limit(void);
extern void* get_rsp(void);

// Convert string to lowercase
void str_tolower(char* str) {
	while (*str) {
		if (*str >= 'A' && *str <= 'Z') {
			*str = *str + 32;
		}
		str++;
	}
}

// Check if the given base address is the target DLL
int is_target_dll(void* base_address, const char* target_name) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_address;

	// Check MZ signature
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((char*)base_address + dos_header->e_lfanew);

	// Check PE signature
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	// Check if it's a DLL
	if ((nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
		return 0;
	}

	// Check if it's 64-bit
	if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		return 0;
	}

	// Get export directory
	DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (export_dir_rva == 0) {
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((char*)base_address + export_dir_rva);

	// Get name RVA
	DWORD name_rva = export_dir->Name;
	if (name_rva == 0) {
		return 0;
	}

	// Get DLL name
	const char* dll_name = (const char*)base_address + name_rva;

	// Copy and convert to lowercase for comparison
	char found_name[256];
	char search_name[256];

	strncpy_s(found_name, sizeof(found_name), dll_name, _TRUNCATE);
	strncpy_s(search_name, sizeof(search_name), target_name, _TRUNCATE);

	str_tolower(found_name);
	str_tolower(search_name);

	// Strip .dll extension if present
	char* dot_pos = strstr(found_name, ".dll");
	if (dot_pos) *dot_pos = '\0';

	dot_pos = strstr(search_name, ".dll");
	if (dot_pos) *dot_pos = '\0';

	return strcmp(found_name, search_name) == 0;
}

// Find the base address of a loaded DLL using stack walking technique
void* find_dll_base(const char* dll_name) {
	void* stack_base = get_stack_base();
	void* stack_limit = get_stack_limit();
	void* rsp = get_rsp();

	MEMORY_BASIC_INFORMATION mbi;
	const SIZE_T PAGE_SIZE = 0x1000;
	const SIZE_T MAX_WALK_SIZE = 0x10000000; // 256MB

	UINT64 current_rsp = (UINT64)rsp;

	// Walk the stack looking for return addresses
	while (current_rsp < (UINT64)stack_base && current_rsp >(UINT64)stack_limit) {
		// Check if we can read this memory
		if (!VirtualQuery((LPCVOID)current_rsp, &mbi, sizeof(mbi))) {
			current_rsp += 8;
			continue;
		}

		// Only read if it's committed memory
		if (mbi.State != MEM_COMMIT) {
			current_rsp += 8;
			continue;
		}

		// Read the potential return address
		UINT64 return_address = *(UINT64*)current_rsp;

		// Check if this is executable memory
		if (VirtualQuery((LPCVOID)return_address, &mbi, sizeof(mbi)) &&
			mbi.State == MEM_COMMIT) {

			// Check if memory is executable
			int is_executable = (mbi.Protect & PAGE_EXECUTE) ||
				(mbi.Protect & PAGE_EXECUTE_READ) ||
				(mbi.Protect & PAGE_EXECUTE_READWRITE) ||
				(mbi.Protect & PAGE_EXECUTE_WRITECOPY);

			if (is_executable) {
				// Found executable memory, try to find PE header
				SIZE_T current_address = return_address;
				SIZE_T walk_count = 0;

				while (walk_count < MAX_WALK_SIZE) {
					// Align to page boundary
					current_address &= ~(PAGE_SIZE - 1);

					// Check if we can read this memory
					if (!VirtualQuery((LPCVOID)current_address, &mbi, sizeof(mbi))) {
						break;
					}

					// Only check committed memory
					if (mbi.State != MEM_COMMIT) {
						break;
					}

					// Check for MZ signature
					WORD* dos_signature = (WORD*)current_address;
					if (*dos_signature == IMAGE_DOS_SIGNATURE) {
						// Found potential PE header, verify it
						PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)current_address;
						SIZE_T pe_header_addr = current_address + dos_header->e_lfanew;

						if (pe_header_addr > current_address) {
							DWORD* pe_signature = (DWORD*)pe_header_addr;

							if (*pe_signature == IMAGE_NT_SIGNATURE) {
								// Validate it's our target DLL
								if (is_target_dll((void*)current_address, dll_name)) {
									return (void*)current_address;
								}
							}
						}
					}

					// Move to previous page
					if (current_address <= PAGE_SIZE) {
						break;
					}
					current_address -= PAGE_SIZE;
					walk_count += PAGE_SIZE;
				}
			}
		}

		// Move to next stack frame
		current_rsp += 8;
	}

	return NULL;
}

int main(int argc, char* argv[]) {
	// Get target DLL name from command line or default to "ntdll.dll"
	const char* target_dll = (argc > 1) ? argv[1] : "kernel32.dll";

	printf("Searching for: %s\n", target_dll);

	void* base_address = find_dll_base(target_dll);

	if (base_address) {
		printf("Found %s at: 0x%p\n", target_dll, base_address);
	}
	else {
		printf("Failed to find %s\n", target_dll);
	}

	return 0;
}