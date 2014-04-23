#include <windows.h>
#include <ITH\IHF_DLL.h>
#include <ITH\IHF_SYS.h>
#include <ITH\ntdll.h>
#include "util.h"
#include "ITH\version.h"



namespace Engine {
DWORD IdentifyEngine();
DWORD DetermineEngineType();
DWORD DetermineEngineByFile1();
DWORD DetermineEngineByFile2();
DWORD DetermineEngineByFile3();
DWORD DetermineEngineByFile4();
DWORD DetermineEngineByProcessName();
DWORD DetermineEngineOther();
DWORD DetermineNoHookEngine();
DWORD InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack);

/*wchar_t process_name_[MAX_PATH];

void inline GetName()
{
	PLDR_DATA_TABLE_ENTRY it;
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov eax,[eax+0xC]
		mov it,eax
	}
	wcscpy(process_name_,it->BaseDllName.Buffer);
}*/

}


