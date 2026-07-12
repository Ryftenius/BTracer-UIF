#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    return reason == DLL_PROCESS_ATTACH ? FALSE : TRUE;
}
