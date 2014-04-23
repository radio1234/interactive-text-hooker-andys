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

#include "engine.h"
#include "engine_p.h"
#include "common\const.h"
#include "cc\ccmacro.h"
#include "config.h"

static wchar_t engine_version[] = L"3.1.0000";
enum { MAX_REL_ADDR = 0x300000 };


BOOL WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	switch(reason)
	{
	case DLL_PROCESS_ATTACH:
		{
		LdrDisableThreadCalloutsForDll(hModule);
		IthInitSystemService();
		Engine::GetName();
		RegisterEngineModule((DWORD)hModule, (DWORD)Engine::IdentifyEngine, (DWORD)Engine::InsertDynamicHook);
		//swprintf(engine,L"ITH_ENGINE_%d",current_process_id);
		//hEngineOn=IthCreateEvent(engine);
		//NtSetEvent(hEngineOn,0);
		}
		break;
	case DLL_PROCESS_DETACH:	
		//NtClearEvent(hEngineOn);
		//NtClose(hEngineOn);
		IthCloseSystemService();
		break;
	}
	return TRUE;
}


namespace Engine {

//HANDLE hEngineOn;
struct CodeSection
{
	DWORD base;
	DWORD size;
};
static WCHAR engine[0x20];
extern DWORD module_base_, module_limit_;
static LPVOID trigger_addr;



static union {
	char text_buffer[0x1000];
	wchar_t wc_buffer[0x800];
	CodeSection code_section[0x200];
};
static char text_buffer_prev[0x1000];
static DWORD buffer_index,buffer_length;
extern BYTE LeadByteTable[0x100];
bool (*trigger_fun_)(LPVOID addr, DWORD frame, DWORD stack);

DWORD GetCodeRange(DWORD hModule,DWORD *low, DWORD *high)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	DWORD dwReadAddr;
	IMAGE_SECTION_HEADER *shdr;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			shdr=(PIMAGE_SECTION_HEADER)((DWORD)(&NtHdr->OptionalHeader)+NtHdr->FileHeader.SizeOfOptionalHeader);
			while ((shdr->Characteristics&IMAGE_SCN_CNT_CODE)==0) shdr++;
			*low=hModule+shdr->VirtualAddress;
				*high=*low+(shdr->Misc.VirtualSize&0xFFFFF000)+0x1000;
		}
	}
	return 0;
}
inline DWORD SigMask(DWORD sig)
{
	__asm
	{
		xor ecx,ecx
		mov eax,sig
_mask:
		shr eax,8
		inc ecx
		test eax,eax
		jnz _mask
		sub ecx,4
		neg ecx
		or eax,-1
		shl ecx,3
		shr eax,cl
	}
}


BOOL SafeFillRange(LPCWSTR dll, DWORD *lower, DWORD *upper)
{
  BOOL ret = FALSE;
  ret = FillRange((LPWSTR)dll, lower, upper);
  return ret;
}



static DWORD recv_esp, recv_eip;
static EXCEPTION_DISPOSITION ExceptHandler(EXCEPTION_RECORD *ExceptionRecord,void * EstablisherFrame, CONTEXT *ContextRecord, void * DispatcherContext )
{
	if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		module_limit_=ExceptionRecord->ExceptionInformation[1];
		OutputDWORD(module_limit_);
		__asm
		{
			mov eax,fs:[0x30]
			mov eax,[eax+0xC]
			mov eax,[eax+0xC]
			mov ecx,module_limit_
			sub ecx,module_base_
			mov [eax+0x20],ecx
		}
	}
	ContextRecord->Esp=recv_esp;
	ContextRecord->Eip=recv_eip;
	return ExceptionContinueExecution;
}

// jichi 3/11/2014: The original FindEntryAligned function could raise exceptions without admin priv
DWORD SafeFindEntryAligned(DWORD start, DWORD back_range)
{
  DWORD ret = 0;
  ret = Util::FindEntryAligned(start, back_range);
  return ret;
}

DWORD Engine::IdentifyEngine()
{
	FillRange(process_name_,&module_base_,&module_limit_);
	BYTE status=0;
	status=0;
	__asm
	{
		mov eax,seh_recover
		mov recv_eip,eax
		push ExceptHandler
		push fs:[0]
		mov fs:[0],esp
		pushad
		mov recv_esp,esp
	}
	DetermineEngineType();status++;
	__asm
	{
seh_recover:
		popad
		mov eax,[esp]
		mov fs:[0],eax
		add esp,8
	}
	if (status==0) OutputConsole(L"Fail to identify engine type.");		
	else OutputConsole(L"Initialized successfully.");
}



//******    DETECT FUNCTIONS DOWN HERE (



DWORD DetermineEngineType()
{
	WCHAR engine_info[0x100];
	swprintf(engine_info, L"Engine support module %s", build_date);
	OutputConsole(engine_info);
	if (DetermineEngineByFile1()==0) return 0;
	if (DetermineEngineByFile2()==0) return 0;
	if (DetermineEngineByFile3()==0) return 0;
	if (DetermineEngineByFile4()==0) return 0;
	if (DetermineEngineByProcessName()==0) return 0;
	if (DetermineEngineOther()==0) return 0;
	if (DetermineNoHookEngine()==0)
	{
		OutputConsole(L"No special hook.");
		return 0;
	}
	OutputConsole(L"Unknown engine.");
	return 0;
}

// Copy/Paste from VNR down here

DWORD InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{ return !trigger_fun_(addr,frame,stack); }

DWORD DetermineEngineByFile1()
{
  enum : DWORD { yes = 0, no = 1 }; // return value
  if (IthFindFile(L"*.xp3") || Util::SearchResourceString(L"TVP(KIRIKIRI)")) {
    InsertKiriKiriHook();
    return yes;
  }
  if (IthFindFile(L"bgi.*")) {
    InsertBGIHook();
    return yes;
  }
  if (IthFindFile(L"data*.arc") && IthFindFile(L"stream*.arc")) {
    InsertMajiroHook();
    return yes;
  }
  if (IthFindFile(L"data\\pack\\*.cpz")) {
    InsertCMVSHook();
    return yes;
  }
  // jichi 10/12/2013: Restore wolf engine
  // jichi 10/18/2013: Check for data/*.wolf
  if (IthFindFile(L"data.wolf") || IthFindFile(L"data\\*.wolf")) {
    InsertWolfHook();
    return yes;
  }
  if (IthCheckFile(L"advdata\\dat\\names.dat")) {
    InsertCircusHook1();
    return yes;
  }
  if (IthCheckFile(L"advdata\\grp\\names.dat")) {
    InsertCircusHook2();
    return yes;
  }
  if (IthFindFile(L"*.noa")) {
    InsertCotophaHook();
    return yes;
  }
  if (IthFindFile(L"*.pfs")) { // jichi 10/1/2013
    InsertArtemisHook();
    return yes;
  }
  if (IthFindFile(L"*.int")) {
    InsertCatSystem2Hook();
    return yes;
  }
  if (IthCheckFile(L"message.dat")) {
    InsertAtelierHook();
    return yes;
  }
  if (IthCheckFile(L"Check.mdx")) { // jichi 4/1/2014: AUGame
    InsertTencoHook();
    return yes;
  }
  // jichi 12/25/2013: It may or may not be QLIE.
  // AlterEgo also has GameData/sound.pack but is not QLIE
  if (IthFindFile(L"GameData\\*.pack") && InsertQLIEHook())
    return yes;
  // jichi 9/16/2013: Add Gesen18
  if (IthFindFile(L"*.szs") || IthFindFile(L"Data\\*.szs")) {
    InsertGesen18Hook();
    return yes;
  }
  // jichi 12/22/2013: Add rejet
  if (IthCheckFile(L"gd.dat") && IthCheckFile(L"pf.dat") && IthCheckFile(L"sd.dat")) {
    InsertRejetHook();
    return yes;
  }
   // Only examined with version 1.0
  //if (IthFindFile(L"Adobe AIR\\Versions\\*\\Adobe AIR.dll")) { // jichi 4/15/2014: FIXME: Wildcard not working
  if (IthCheckFile(L"Adobe AIR\\Versions\\1.0\\Adobe AIR.dll")) { // jichi 4/15/2014: Adobe AIR
    InsertAdobeAirHook();
    return yes;
  }
  //if (IthFindFile(L"*\\Mono\\mono.dll")) { // jichi 4/21/2014: Mono
  //if (IthCheckFile(L"bsz2_Data\\Mono\\mono.dll")) { // jichi 4/21/2014: Mono
  //  InsertMonoHook();
  //  return yes;
  //}
  return no;
}

DWORD DetermineEngineByFile2()
{
  enum : DWORD { yes = 0, no = 1 }; // return value
  if (IthCheckFile(L"resident.dll")) {
    InsertRetouchHook();
    return yes;
  }
  if (IthCheckFile(L"malie.ini")) {
    InsertMalieHook();
    return yes;
  }
  if (IthCheckFile(L"live.dll")) {
    InsertLiveHook();
    return yes;
  }
  // 9/5/2013 jichi
  if (IthCheckFile(L"aInfo.db")) {
    InsertNextonHook();
    return yes;
  }
  if (IthFindFile(L"*.lpk")) {
    InsertLucifenHook();
    return yes;
  }
  if (IthCheckFile(L"cfg.pak")) {
    InsertWaffleHook();
    return yes;
  }
  if (IthCheckFile(L"Arc00.dat")) {
    InsertTinkerBellHook();
    return yes;
  }
  if (IthFindFile(L"*.vfs")) {
    InsertSoftHouseHook();
    return yes;
  }
  if (IthFindFile(L"*.mbl")) {
    InsertLuneHook();
    return yes;
  }
  if (IthFindFile(L"pac\\*.ypf") || IthFindFile(L"*.ypf")) {
    // jichi 8/14/2013: CLOCLUP: "ノーブレスオブリージュ" would crash the game.
    if (!IthCheckFile(L"noblesse.exe"))
      InsertWhirlpoolHook();
    return yes;
  }
  if (IthFindFile(L"*.npa")) {
    InsertNitroPlusHook();
    return yes;
  }
  return no;
}

DWORD DetermineEngineByFile3()
{
  enum : DWORD { yes = 0, no = 1 }; // return value
  //if (IthCheckFile(L"libscr.dll")) { // already checked
  //  InsertBrunsHook();
  //  return yes;
  //}

  // jichi 10/12/2013: Sample args.txt:
  // See: http://tieba.baidu.com/p/2631413816
  // -workdir
  // .
  // -loadpath
  // .
  // am.cfg
  if (IthCheckFile(L"args.txt")) {
    InsertBrunsHook();
    return yes;
  }
  if (IthCheckFile(L"emecfg.ecf")) {
    InsertEMEHook();
    return yes;
  }
  if (IthCheckFile(L"rrecfg.rcf")) {
    InsertRREHook();
    return yes;
  }
  if (IthFindFile(L"*.fpk") || IthFindFile(L"data\\*.fpk")) {
    InsertCandyHook();
    return yes;
  }
  if (IthFindFile(L"arc.a*")) {
    InsertApricotHook();
    return yes;
  }
  if (IthFindFile(L"*.mpk")) {
    InsertStuffScriptHook();
    return yes;
  }
  if (IthCheckFile(L"Execle.exe")) {
    InsertTriangleHook();
    return yes;
  }
  if (IthCheckFile(L"PSetup.exe")) {
    InsertPensilHook();
    return yes;
  }
  if (IthCheckFile(L"Yanesdk.dll")) {
    InsertAB2TryHook();
    return yes;
  }
  if (IthFindFile(L"*.med")) {
    InsertMEDHook();
    return yes;
  }
  return no;
}

DWORD DetermineEngineByFile4()
{
  enum : DWORD { yes = 0, no = 1 }; // return value
  if (IthCheckFile(L"bmp.pak") && IthCheckFile(L"dsetup.dll")) {
    InsertDebonosuHook();
    return yes;
  }
  if (IthCheckFile(L"C4.EXE") || IthCheckFile(L"XEX.EXE")) {
    InsertC4Hook();
    return yes;
  }
  if (IthCheckFile(L"Rio.arc") && IthFindFile(L"Chip*.arc")) {
    InsertWillPlusHook();
    return yes;
  }
  if (IthFindFile(L"*.tac")) {
    InsertTanukiHook();
    return yes;
  }
  if (IthFindFile(L"*.gxp")) {
    InsertGXPHook();
    return yes;
  }
  if (IthFindFile(L"*.aos")) { // jichi 4/2/2014: AOS hook
    InsertAOSHook();
    return yes;
  }
  if (IthFindFile(L"*.iar") && InsertSolfaHook()) // jichi 4/18/2014: Other game engine could also have *.iar such as Ryokucha
    return yes;
  return no;
}

DWORD DetermineEngineByProcessName()
{
  enum : DWORD { yes = 0, no = 1 }; // return value
  WCHAR str[MAX_PATH];
  wcscpy(str, process_name_);
  _wcslwr(str); // lower case

  if (wcsstr(str,L"reallive")) {
    InsertRealliveHook();
    return yes;
  }

  // jichi 8/19/2013: DO NOT WORK for games like「ハピメア」
  //if (wcsstr(str,L"cmvs32") || wcsstr(str,L"cmvs64")) {
  //  InsertCMVSHook();
  //  return yes;
  //}

  // jichi 8/17/2013: Handle "~"
  if (wcsstr(str, L"siglusengine") || !wcsncmp(str, L"siglus~", 7)) {
    InsertSiglusHook();
    return yes;
  }

  if (wcsstr(str, L"taskforce2") || !wcsncmp(str, L"taskfo~", 7)) {
    InsertTaskforce2Hook();
    return yes;
  }

  if (wcsstr(str,L"rugp")) {
    InsertRUGPHook();
    return yes;
  }

  // jichi 8/17/2013: Handle "~"
  if (wcsstr(str, L"igs_sample") || !wcsncmp(str, L"igs_sa~", 7)) {
    InsertIronGameSystemHook();
    return yes;
  }

  if (wcsstr(str, L"bruns")) {
    InsertBrunsHook();
    return yes;
  }

  if (wcsstr(str, L"anex86")) {
    InsertAnex86Hook();
    return yes;
  }

  // jichi 8/17/2013: Handle "~"
  if (wcsstr(str, L"shinydays") || !wcsncmp(str, L"shinyd~", 7)) {
    InsertShinyDaysHook();
    return yes;
  }

  // jichi 10/3/2013: FIXME: Does not work
  // Raise C0000005 even with admin priv
  //if (wcsstr(str, L"bsz")) { // BALDRSKY ZERO
  //  InsertBaldrHook();
  //  return yes;
  //}

  if (wcsstr(process_name_, L"SAISYS")) { // jichi 4/19/2014: Marine Heart
    InsertMarineHeartHook();
    return yes;
  }

  DWORD len = wcslen(str);

  static WCHAR saveman[] = L"_checksum.exe";
  wcscpy(str + len - 4, saveman);
  if (IthCheckFile(str)) {
    InsertRyokuchaHook();
    return yes;
  }

  // jichi 8/24/2013: Checking for Rio.ini or $procname.ini
  //wcscpy(str+len-4, L"_?.war");
  //if (IthFindFile(str)) {
  //  InsertShinaHook();
  //  return yes;
  //}
  if (InsertShinaHook())
    return yes;

  // jichi 8/10/2013: Since *.bin is common, move CaramelBox to the end
  str[len - 3] = L'b';
  str[len - 2] = L'i';
  str[len - 1] = L'n';
  str[len] = 0;
  if (IthCheckFile(str)) {
    InsertCaramelBoxHook();
    return yes;
  }
  return no;
}

DWORD DetermineEngineOther()
{
  enum : DWORD { yes = 0, no = 1 }; // return value
  if (InsertAliceHook())
    return yes;
  // jichi 12/26/2013: Add this after alicehook
  if (IthCheckFile(L"AliceStart.ini")) {
    InsertSystem43Hook();
    return yes;
  }

  // jichi 8/24/2013: Move into functions
  static BYTE static_file_info[0x1000];
  if (IthGetFileInfo(L"*01", static_file_info))
    if (*(DWORD*)static_file_info == 0) {
      STATUS_INFO_LENGTH_MISMATCH;
      static WCHAR static_search_name[MAX_PATH];
      LPWSTR name=(LPWSTR)(static_file_info+0x5E);
      int len = wcslen(name);
      name[len-2] = L'.';
      name[len-1] = L'e';
      name[len] = L'x';
      name[len+1] = L'e';
      name[len+2] = 0;
      if (IthCheckFile(name)) {
        name[len-2] = L'*';
        name[len-1] = 0;
        wcscpy(static_search_name,name);
        IthGetFileInfo(static_search_name,static_file_info);
        union {
          FILE_BOTH_DIR_INFORMATION *both_info;
          DWORD addr;
        };
        both_info = (FILE_BOTH_DIR_INFORMATION *)static_file_info;
        //BYTE* ptr=static_file_info;
        len=0;
        while (both_info->NextEntryOffset) {
          addr += both_info->NextEntryOffset;
          len++;
        }
        if (len > 3) {
          InsertAbelHook();
          return yes;
        }
      }
    }
  return no;
}

DWORD DetermineNoHookEngine()
{
  enum : DWORD { yes = 0, no = 1 }; // return value

  //if (IthFindFile(L"*\\Managed\\UnityEngine.dll")) { // jichi 12/3/2013: Unity (BALDRSKY ZERO)
  //  ConsoleOutput("vnreng: IGNORE Unity");
  //  return yes;
  //}

  if (IthCheckFile(L"AGERC.DLL")) { // jichi 3/17/2014: Eushully, AGE.EXE
    ConsoleOutput("vnreng: IGNORE Eushully");
    return yes;
  }

  if (IthCheckFile(L"EAGLS.dll")) { // jichi 3/24/2014: E.A.G.L.S
    ConsoleOutput("vnreng: IGNORE EAGLS");
    return yes;
  }

  if (IthCheckFile(L"game_sys.exe")) {
    ConsoleOutput("vnreng: IGNORE Atelier Kaguya BY/TH");
    return yes;
  }

  if (IthFindFile(L"*.ykc")) {
    ConsoleOutput("vnreng: IGNORE YKC:Feng/HookSoft(SMEE)");
    return yes;
  }
  if (IthFindFile(L"*.bsa")) {
    ConsoleOutput("vnreng: IGNORE Bishop");
    return yes;
  }
  if (IthFindFile(L"*.pac")) {
    //if (IthCheckFile(L"Thumbnail.pac")) {
    //  ConsoleOutput(L"GIGA");
    //  return yes;
    //}
    if (Util::SearchResourceString(L"SOFTPAL")) {
      ConsoleOutput("vnreng: IGNORE SoftPal UNiSONSHIFT");
      return yes;
    }
  }

  if (wcsstr(process_name_, L"lcsebody") || !wcsncmp(process_name_, L"lcsebo~", 7)) { // jichi 3/19/2014: lcsebody.exe, GetGlyphOutlineA
    ConsoleOutput("vnreng: IGNORE lcsebody");
    return yes;
  }

  wchar_t str[MAX_PATH];
  DWORD i;
  for (i = 0; process_name_[i]; i++) {
    str[i] = process_name_[i];
    if (process_name_[i] == L'.')
      break;
  }
  *(DWORD *)(str + i + 1) = 0x630068; //.hcb
  *(DWORD *)(str + i + 3) = 0x62;
  if (IthCheckFile(str)) {
    ConsoleOutput("vnreng: IGNORE FVP"); // jichi 10/3/2013: such like アトリエかぐや
    return yes;
  }
  return no;
}

//*****************************************************************************************


} // Engine End