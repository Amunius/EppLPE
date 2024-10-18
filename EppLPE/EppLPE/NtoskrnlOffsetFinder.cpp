#include "NtoskrnlOffsetFinder.h"
#include <iostream>

NtoskrnlOffsetFinder::NtoskrnlOffsetFinder()
{
	Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
	if (Ntoskrnl == NULL)
	{
		std::cout << "Failed to load ntoskrnl.exe, last error: 0x" << std::hex << GetLastError() << std::endl;
		return;
	}

	void* PsGetProcessId = GetProcAddress(Ntoskrnl, "PsGetProcessId");
	if (PsGetProcessId)
	{
		UniqueProcessIdOffset = *(DWORD*)((BYTE*)PsGetProcessId + 3);
		std::cout << "UniqueProcessId offset: 0x" << std::hex << UniqueProcessIdOffset << std::endl;
		ActiveProcessLinksOffset = UniqueProcessIdOffset + 8;
		std::cout << "ActiveProcessLinks offset: 0x" << std::hex << ActiveProcessLinksOffset << std::endl;
	}
	else
	{
		std::cout << "Could not find PsGetProcessId :(" << std::endl;
	}

	void* IoGetTopLevelIrp = GetProcAddress(Ntoskrnl, "IoGetTopLevelIrp");
	if (IoGetTopLevelIrp)
	{
		IrpListOffset = *(DWORD*)((BYTE*)IoGetTopLevelIrp + 0xC);
		IrpListOffset -= sizeof(LIST_ENTRY);
		std::cout << "IrpList offset: 0x" << std::hex << IrpListOffset << std::endl;
	}
	else
	{
		std::cout << "Could not find IoGetTopLevelIrp :(" << std::endl;
	}

	void* IoThreadToProcess = GetProcAddress(Ntoskrnl, "IoThreadToProcess");
	if (IoThreadToProcess)
	{
		ProcessOffset = *(DWORD*)((BYTE*)IoThreadToProcess + 3);
		std::cout << "Process offset: 0x" << std::hex << ProcessOffset << std::endl;
	}
	else
	{
		std::cout << "Could not find IoThreadToProcess :(" << std::endl;
	}

	void* PsGetProcessJob = GetProcAddress(Ntoskrnl, "PsGetProcessJob");
	if (PsGetProcessJob)
	{
		TokenOffset = (*(DWORD*)((BYTE*)PsGetProcessJob + 3)) - 0x58;
		std::cout << "Token offset: 0x" << std::hex << TokenOffset << std::endl;
	}
	else
	{
		std::cout << "Could not find PsGetProcessJob :(" << std::endl;
	}

	FreeLibrary(Ntoskrnl);
}

const UINT64 NtoskrnlOffsetFinder::GetUniqueProcessIdOffset()
{
	return UniqueProcessIdOffset;
}

const UINT64 NtoskrnlOffsetFinder::GetActiveProcessLinksOffset()
{
	return ActiveProcessLinksOffset;
}

const UINT64 NtoskrnlOffsetFinder::GetIrpListOffset()
{
	return IrpListOffset;
}

const UINT64 NtoskrnlOffsetFinder::GetProcessOffset()
{
	return ProcessOffset;
}

const UINT64 NtoskrnlOffsetFinder::GetTokenOffset()
{
	return TokenOffset;
}