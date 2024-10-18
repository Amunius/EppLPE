#include "Utils.h"

PPEB GetCurrentProcessPEB()
{
    return (PPEB)__readgsqword(0x60);
}

void CreateCmd()
{
    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInformation;

    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

    wchar_t CmdPath[] = L"C:\\Windows\\System32\\cmd.exe";

    if (!CreateProcessW(CmdPath, nullptr, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, L"C:\\", &StartupInfo, &ProcessInformation))
    {
        std::cout << "CreateProcess failed, last error: " << std::dec << GetLastError() << std::endl;
    }
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
}

void XorWord(XorParams* Params)
{
    volatile unsigned __int16* AddressToXor = Params->AddressToXor;
    unsigned __int16 ValueToXor = Params->ValueToXor;
    while (true)
    {
        *AddressToXor ^= ValueToXor;
    }
}