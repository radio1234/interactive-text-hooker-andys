/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <intrin.h>
#include "IHF_CLIENT.h"
//#include "md5.h"
#include "ITH\AVL.h"
#include "ITH\ntdll.h"
#define HOOK_BUFFER_SIZE (MAX_HOOK*sizeof(TextHook))
//#define MAX_HOOK (HOOK_BUFFER_SIZE/sizeof(TextHook))
WCHAR dll_mutex[0x100];
WCHAR dll_name[0x100];
WCHAR hm_mutex[0x100];
WCHAR hm_section[0x100];
HINSTANCE hDLL;
HANDLE hSection;
bool running,live=false;
int current_hook=0,user_hook_count=0;
DWORD trigger=0;
HANDLE hSendThread,hCmdThread,hFile,hMutex,hmMutex;
DWORD hook_buff_len=HOOK_BUFFER_SIZE;
//DWORD current_process_id;
extern DWORD enter_count;
//extern LPWSTR current_dir;
extern DWORD engine_type;
extern DWORD module_base;
AVLTree<char, FunctionInfo, SCMP, SCPY, SLEN> *tree;


void AddModule(DWORD hModule, DWORD size, LPWSTR name)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	IMAGE_EXPORT_DIRECTORY *ExtDir;
	UINT uj;
	FunctionInfo info={0,hModule,size,name};
	char* pcFuncPtr,*pcBuffer;
	DWORD dwReadAddr,dwFuncName,dwExportAddr;
	WORD wOrd;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			dwExportAddr=NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (dwExportAddr==0) return;
			dwExportAddr+=hModule;
			ExtDir=(IMAGE_EXPORT_DIRECTORY*)dwExportAddr;
			dwExportAddr=hModule+ExtDir->AddressOfNames;
			for (uj=0;uj<ExtDir->NumberOfNames;uj++)
			{
				dwFuncName=*(DWORD*)dwExportAddr;
				pcBuffer=(char*)(hModule+dwFuncName);
				pcFuncPtr=(char*)(hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
				wOrd=*(WORD*)pcFuncPtr;
				pcFuncPtr=(char*)(hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
				info.addr=hModule+*(DWORD*)pcFuncPtr;
				tree->Insert(pcBuffer,info);
				dwExportAddr+=sizeof(DWORD);
			}
		}
	}
}
void GetFunctionNames()
{
	tree=new AVLTree<char, FunctionInfo, SCMP,SCPY,SLEN>;
	PPEB ppeb;
	__asm
	{
		mov eax,fs:[0x30]
		mov ppeb,eax
	}
	DWORD temp=*(DWORD*)(&ppeb->Ldr->InLoadOrderModuleList);
	PLDR_DATA_TABLE_ENTRY it=(PLDR_DATA_TABLE_ENTRY) temp;
	while (it->SizeOfImage)
	{
		AddModule((DWORD)it->DllBase,it->SizeOfImage,it->BaseDllName.Buffer);
		it=(PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
		if (*(DWORD*)it==temp) break;
	}
}
DWORD IHFAPI GetFunctionAddr(char* name, DWORD* addr, DWORD* base, DWORD* size, LPWSTR* base_name)
{
	TreeNode<char*,FunctionInfo>* node=tree->Search(name);
	if (node)
	{
		if (addr) *addr=node->data.addr;
		if (base) *base=node->data.module;
		if (size) *size=node->data.size;
		if (base_name) *base_name=node->data.name;
		return 1;
	}
	else return 0;
}
void RequestRefreshProfile()
{
	if (live)
	{
		BYTE buffer[0x80];
		*(DWORD*)buffer=-1;
		*(DWORD*)(buffer+4)=1;
		*(DWORD*)(buffer+8)=0;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buffer,HEADER_SIZE,0,0);
	}
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	static WCHAR dll_exist[] = L"ITH_DLL_RUNNING";
	static HANDLE hDllExist;
	switch (fdwReason) 
	{ 
	case DLL_PROCESS_ATTACH:
		{
		LdrDisableThreadCalloutsForDll(hinstDLL);	
		IthBreak();
		module_base = (DWORD)hinstDLL;
		IthInitSystemService();
		DWORD s;
		swprintf(hm_section,L"ITH_SECTION_%d",current_process_id);
		hSection=IthCreateSection(hm_section,0x2000,PAGE_EXECUTE_READWRITE);	
		NtMapViewOfSection(hSection,NtCurrentProcess(),(PVOID*)&hookman,0,
			hook_buff_len,0,&hook_buff_len,ViewUnmap,0,PAGE_EXECUTE_READWRITE);
		LPWSTR p;		
		for (p = GetMainModulePath(); *p; p++);
		for (p = p; *p != L'\\'; p--);
		wcscpy(dll_name,p+1);
		//swprintf(dll_mutex,L"ITH_%.4d_%s",current_process_id,current_dir);
		swprintf(dll_mutex,L"ITH_%d",current_process_id);
		swprintf(hm_mutex,L"ITH_HOOKMAN_%d",current_process_id);
		hmMutex=IthCreateMutex(hm_mutex,0);
		hMutex=IthCreateMutex(dll_mutex,1,&s);
		if (s) return FALSE;
		hDllExist = IthCreateMutex(dll_exist, 0);
		hDLL=hinstDLL; running=true;
		current_available=hookman;
		GetFunctionNames();
		InitFilterTable();
		InitDefaultHook();
		
		hSendThread=IthCreateThread(WaitForPipe,0);
		hCmdThread=IthCreateThread(CommandPipe,0);
		}
		break; 
	case DLL_PROCESS_DETACH:
	{		
		running=false;
		live=false;
		NtWaitForSingleObject(hSendThread,0,0);
		NtWaitForSingleObject(hCmdThread,0,0);
		NtClose(hCmdThread);
		NtClose(hSendThread);
		for (TextHook* man=hookman;man->RemoveHook();man++);
		LARGE_INTEGER lint={-10000,-1};
		while (enter_count) NtDelayExecution(0,&lint);
		for (TextHook* man=hookman;man<hookman+MAX_HOOK;man++) man->ClearHook();
		NtUnmapViewOfSection(NtCurrentProcess(),hookman);
		NtClose(hSection);	
		NtClose(hMutex);

		delete tree;
		IthCloseSystemService();
		NtClose(hmMutex);
		NtClose(hDllExist);
		break;
	}
	default: 
		break; 
	 } 
	return TRUE; 
}

extern "C" {

DWORD IHFAPI NewHook(const HookParam &hp, LPCWSTR name, DWORD flag)
{
  WCHAR str[0x80];
  int current = ::current_available - ::hookman;
  if (current < MAX_HOOK) {
    //flag &= 0xffff;
    //if ((flag & HOOK_AUXILIARY) == 0)
    flag |= HOOK_ADDITIONAL;
      if (name == 0 || *name == 0) {
        swprintf(str,L"UserHook%d",user_hook_count++);
		name = str;
      }

    ConsoleOutput("vnrcli:NewHook: try inserting hook.");

    ::hookman[current].InitHook(hp, name, flag & 0xffff);
    if (::hookman[current].InsertHook() == 0) {
      ConsoleOutput("vnrcli:NewHook: hook inserted");
      //ConsoleOutputW(name);
      swprintf(str,L"Insert address 0x%.8X.", hookman[current].Address());
      RequestRefreshProfile();
    } else
      ConsoleOutput("vnrcli:NewHook:WARNING: failed to insert hook");


    //else
    //  ConsoleOutput(L"Unable to insert hook.");
  }
  return 0;
}

DWORD IHFAPI RemoveHook(DWORD addr)
{
	for (int i=0;i<MAX_HOOK;i++)
	{
		if (hookman[i].Address()==addr)
		{
			hookman[i].ClearHook();
			return 0;
		}
	}
	return 0;
}
DWORD IHFAPI SwitchTrigger(DWORD t) 
{
	trigger = t;
	return 0;
}

}

static int filter_count;
static DWORD recv_esp, recv_addr;
static CONTEXT recover_context;
static __declspec(naked) void MySEH()
{
	__asm{
	mov eax, [esp+0xC]
	mov edi,eax
	mov ecx,0xB3
	mov esi, offset recover_context
	rep movs
	mov ecx, [recv_esp]
	mov [eax+0xC4],ecx
	mov edx, [recv_addr]
	mov [eax+0xB8],edx
	xor eax,eax
	retn
	}
}
EXCEPTION_DISPOSITION ExceptHandler(
	EXCEPTION_RECORD *ExceptionRecord,
	void * EstablisherFrame,
	CONTEXT *ContextRecord,
	void * DispatcherContext )
{
	ContextRecord->Esp=recv_esp;
	ContextRecord->Eip=recv_addr;
	return ExceptionContinueExecution;
}
int GuardRange(LPWSTR module, DWORD* a, DWORD* b)
{
	int flag=0;
	__asm
	{
		mov eax,seh_recover
		mov recv_addr,eax
		push ExceptHandler
		push fs:[0]
		mov recv_esp,esp
		mov fs:[0],esp
	}
	flag=FillRange(module,a,b);
	__asm
	{
seh_recover:
		mov eax,[esp]
		mov fs:[0],eax
		add esp,8
	}
	return flag;
}
void AddRange(LPWSTR dll)
{
	if (GuardRange(dll,&filter[filter_count].lower,&filter[filter_count].upper))
		filter_count++;
}
void InitFilterTable()
{
	filter_count=0;
	AddRange(L"uxtheme.dll");
	AddRange(L"usp10.dll");
	AddRange(L"msctf.dll");
	AddRange(L"gdiplus.dll");
	AddRange(L"lpk.dll");
	AddRange(L"psapi.dll");
	AddRange(L"user32.dll");
}
// jichi 10/2/2013
// Note: All functions does not have NO_CONTEXT attribute and will be filtered.
void IHFAPI InsertNonGuiHooks() { InsertLstrHooks(); }


#define ADD_HOOK(_name, _addr, _data, _data_ind, _split_off, _split_ind, _type, _len_off) \
  { \
    HookParam hp = {}; \
    hp.addr = (DWORD)_addr; \
    hp.off = _data; \
    hp.ind = _data_ind; \
    hp.split = _split_off; \
    hp.split_ind = _split_ind; \
    hp.type = _type; \
    hp.length_offset = _len_off; \
    NewHook(hp, _name); \
  }

// jichi 10/2/2013
// Note: All functions does not have NO_CONTEXT attribute and will be filtered.
void IHFAPI InsertLstrHooks()
{
  ConsoleOutput("vnrcli:InsertLstrHooks: enter");
  // int TextHook::InitHook(LPVOID addr, DWORD data, DWORD data_ind, DWORD split_off, DWORD split_ind, WORD type, DWORD len_off)

  // http://msdn.microsoft.com/en-us/library/78zh94ax.aspx
  // int WINAPI lstrlen(LPCTSTR lpString);
  // Lstr functions usually extracts rubbish, and might crash certain games like ?Magical Marriage Lunatics!!?
  // Needed by Gift
  ADD_HOOK(L"lstrlenA", lstrlenA, 0x4,  0,4,0, USING_STRING,  0) // 9/8/2013 jichi: int WINAPI lstrlen(LPCTSTR lpString);
  ADD_HOOK(L"lstrlenW", lstrlenW, 0x4,  0,4,0, USING_UNICODE|USING_STRING, 0) // 9/8/2013 jichi: add lstrlen

  // size_t strlen(const char *str);
  // size_t strlen_l(const char *str, _locale_t locale);
  // size_t wcslen(const wchar_t *str);
  // size_t wcslen_l(const wchar_t *str, _locale_t locale);
  // size_t _mbslen(const unsigned char *str);
  // size_t _mbslen_l(const unsigned char *str, _locale_t locale);
  // size_t _mbstrlen(const char *str);
  // size_t _mbstrlen_l(const char *str, _locale_t locale);

  // http://msdn.microsoft.com/en-us/library/ex0hs2ad.aspx
  // Needed by ???
  //
  // <tchar.h>
  // char *_strinc(const char *current, _locale_t locale);
  // wchar_t *_wcsinc(const wchar_t *current, _locale_t locale);
  // <mbstring.h>
  // unsigned char *_mbsinc(const unsigned char *current);
  // unsigned char *_mbsinc_l(const unsigned char *current, _locale_t locale);
  //_(L"_strinc", _strinc, 0x4,  0,4,0, USING_STRING, 0) // 12/13/2013 jichi
  //_(L"_wcsinc", _wcsinc, 0x4,  0,4,0, USING_UNICODE|USING_STRING, 0)
  ConsoleOutput("vnrcli:InsertLstrHooks: leave");
}

void IHFAPI InsertWcharHooks()
{
  ConsoleOutput("vnrcli:InsertWcharHooks: enter");
  // 12/1/2013 jichi:
  // AlterEgo
  // http://tieba.baidu.com/p/2736475133
  // http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page355
  //
  // MultiByteToWideChar
  // http://blgames.proboards.com/thread/265
  //
  // WideCharToMultiByte
  // http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page156
  //
  // int MultiByteToWideChar(
  //   _In_       UINT CodePage,
  //   _In_       DWORD dwFlags,
  //   _In_       LPCSTR lpMultiByteStr, // hook here
  //   _In_       int cbMultiByte,
  //   _Out_opt_  LPWSTR lpWideCharStr,
  //   _In_       int cchWideChar
  // );
  // int WideCharToMultiByte(
  //   _In_       UINT CodePage,
  //   _In_       DWORD dwFlags,
  //   _In_       LPCWSTR lpWideCharStr,
  //   _In_       int cchWideChar,
  //   _Out_opt_  LPSTR lpMultiByteStr,
  //   _In_       int cbMultiByte,
  //   _In_opt_   LPCSTR lpDefaultChar,
  //   _Out_opt_  LPBOOL lpUsedDefaultChar
  // );

  // 3/17/2014 jichi: Temporarily disabled
  // http://sakuradite.com/topic/159
  ADD_HOOK(L"MultiByteToWideChar", MultiByteToWideChar, 0xc,  0,4,0, USING_STRING, 4)
  ADD_HOOK(L"WideCharToMultiByte", WideCharToMultiByte, 0xc,  0,4,0, USING_UNICODE|USING_STRING, 4)
  ConsoleOutput("vnrcli:InsertWcharHooks: leave");
}


