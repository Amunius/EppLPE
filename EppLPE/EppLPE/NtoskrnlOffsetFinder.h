#pragma once
#include <windows.h>

class NtoskrnlOffsetFinder
{
	HMODULE Ntoskrnl = nullptr;

	UINT64 UniqueProcessIdOffset = 0;
	UINT64 ActiveProcessLinksOffset = 0;
	UINT64 IrpListOffset = 0;
	UINT64 ProcessOffset = 0;
	UINT64 TokenOffset = 0;
public:
	NtoskrnlOffsetFinder();

	const UINT64 GetUniqueProcessIdOffset();
	const UINT64 GetActiveProcessLinksOffset();
	const UINT64 GetIrpListOffset();
	const UINT64 GetProcessOffset();
	const UINT64 GetTokenOffset();
};