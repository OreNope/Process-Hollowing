#pragma once

#include <windows.h>
#include <winternl.h>

#include <iostream>
#include <string>

#include "RelocStructures.h"

// Custom exceptions
#include "ImportException.h"
#include "CreationFailedException.h"
#include "AllocationException.h"
#include "FileSizeException.h"
#include "ReadingException.h"
#include "ProccessAccessException.h"
#include "WritingException.h"
#include "CompatibilityException.h"

//// For native api access
typedef NTSTATUS(NTAPI* pdef_NtUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);

class Hollowing
{
public:
	// C'tor
	Hollowing(const std::string& hostPath, const std::string& payloadPath);

	void hollow() const;

// methods
private:
	void validateBinaries() const;
	void loadNativeApiFuncs() const;
	PROCESS_INFORMATION createHostSuspended() const;
	LPVOID getPayloadImage() const;
	PIMAGE_NT_HEADERS getNtHeadersFromImage(const LPVOID image) const;
	LPVOID getProcBaseImageAddr(const PROCESS_INFORMATION& procInfo) const;
	void hollowProcMemory(const PROCESS_INFORMATION& procInfo, const LPVOID baseImg) const;
	PVOID rebindProcHeaders(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr, const LPVOID image) const;
	PIMAGE_SECTION_HEADER rebindProcSections(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr, const LPVOID image) const;
	void relocateHostProc(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PIMAGE_SECTION_HEADER piRelocSection, const PVOID hostBaseAddr, const PVOID image, const DWORD baseAddrDelta) const;
	void updateProcBaseImageAddr(const PROCESS_INFORMATION& procInfo, const PVOID hostBaseAddr) const;
	void updateProcEntryPoint(const PROCESS_INFORMATION& procInfo, const PIMAGE_NT_HEADERS piNtHeaders, const PVOID hostBaseAddr) const;
	void resumeHost(const PROCESS_INFORMATION& procInfo) const;

// fields
private:
	std::string m_hostPath;
	std::string m_payloadPath;
	
// consts
private: 
	static const std::string RELOC_SECTION_NAME; // ".reloc"
	static constexpr BYTE BITS_IN_BYTE = 8;
	static constexpr WORD PE32_MAGIC = 0x10b;
	static constexpr BYTE BASE_IMG_OFFSET_FROM_PEB = 8;
};
