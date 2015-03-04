// eng/engine_p.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "engine_p.h"
#include "engine.h"
#include "hookdefs.h"
#include "util.h"
#include "ith/cli/cli.h"
#include "ith/sys/sys.h"
#include "ith/common/except.h"
#include "memdbg/memsearch.h"
#include "ntinspect/ntinspect.h"
#include "disasm/disasm.h"
#include "winversion/winversion.h"
#include "cc/ccmacro.h"
#include "ITH\IHF_DLL.h"

// jichi 7/6/2014: read esp_base
#define retof(esp_base)         *(DWORD *)(esp_base) // return address
#define regof(name, esp_base)   *(DWORD *)((esp_base) + pusha_##name##_off - 4)
#define argof(count, esp_base)  *(DWORD *)((esp_base) + 4 * (count)) // starts from 1 instead of 0

//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

#define DEBUG "engine_p.h"

enum { VNR_TEXT_CAPACITY = 1500 }; // estimated max number of bytes allowed in VNR, slightly larger than VNR's text limit (1000)

#ifdef DEBUG
# include "ith/common/growl.h"
//# include "uniquemap.h"
//# include "uniquemap.cc"
namespace { // unnamed debug functions
// jichi 12/17/2013: Copied from int TextHook::GetLength(DWORD base, DWORD in)
int GetHookDataLength(const HookParam &hp, DWORD base, DWORD in)
{
  if (CC_UNLIKELY(!base))
    return 0;
  int len;
  switch (hp.length_offset) {
  default: // jichi 12/26/2013: I should not put this default branch to the end
    len = *((int *)base + hp.length_offset);
    if (len >= 0) {
      if (hp.type & USING_UNICODE)
        len <<= 1;
      break;
    }
    else if (len != -1)
      break;
    //len == -1 then continue to case 0.
  case 0:
    if (hp.type & USING_UNICODE)
      len = wcslen((LPCWSTR)in) << 1;
    else
      len = strlen((LPCSTR)in);
    break;
  case 1:
    if (hp.type & USING_UNICODE)
      len = 2;
    else {
      if (hp.type & BIG_ENDIAN)
        in >>= 8;
      len = LeadByteTable[in&0xff];  //Slightly faster than IsDBCSLeadByte
    }
    break;
  }
  // jichi 12/25/2013: This function originally return -1 if failed
  //return len;
  return max(0, len);
}
} // unnamed
#endif // DEBUG

namespace { // unnamed helpers

enum : DWORD {
  PPSSPP_MEMORY_SEARCH_STEP_98 = 0x01000000
  , PPSSPP_MEMORY_SEARCH_STEP_99 = 0x00050000
  //, step = 0x1000 // step  must be at least 0x1000 (offset in SearchPattern)
  //, step = 0x00010000 // crash otoboku PSP on 0.9.9 since 5pb is wrongly inserted
};

enum : BYTE { XX = MemDbg::WidecardByte }; // 0x11
#define XX2 XX,XX       // WORD
#define XX4 XX2,XX2     // DWORD
#define XX8 XX4,XX4     // QWORD

// jichi 8/18/2013: Original maximum relative address in ITH
//enum { MAX_REL_ADDR = 0x200000 };

// jichi 10/1/2013: Increase relative address limit. Certain game engine like Artemis has larger code region
enum : DWORD { MAX_REL_ADDR = 0x00300000 };

static union {
  char text_buffer[0x1000];
  wchar_t wc_buffer[0x800];

  struct { // CodeSection
    DWORD base;
    DWORD size;
  } code_section[0x200];
};

char text_buffer_prev[0x1000];
DWORD buffer_index,
      buffer_length;

BOOL SafeFillRange(LPCWSTR dll, DWORD *lower, DWORD *upper)
{
  BOOL r = FALSE;
  ITH_WITH_SEH(r = FillRange(dll, lower, upper));
  return r;
}

// jichi 3/11/2014: The original FindEntryAligned function could raise exceptions without admin priv
DWORD SafeFindEntryAligned(DWORD start, DWORD back_range)
{
  DWORD r = 0;
  ITH_WITH_SEH(r = Util::FindEntryAligned(start, back_range));
  return r;
}

ULONG SafeFindEnclosingAlignedFunction(DWORD addr, DWORD range)
{
  ULONG r = 0;
  ITH_WITH_SEH(r = MemDbg::findEnclosingAlignedFunction(addr, range)); // this function might raise if failed
  return r;
}

ULONG SafeFindBytes(LPCVOID pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound)
{
  ULONG r = 0;
  ITH_WITH_SEH(r = MemDbg::findBytes(pattern, patternSize, lowerBound, upperBound));
  return r;
}

ULONG SafeMatchBytes(LPCVOID pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound, BYTE wildcard = XX)
{
  ULONG r = 0;
  ITH_WITH_SEH(r = MemDbg::matchBytes(pattern, patternSize, lowerBound, upperBound, wildcard));
  return r;
}

// jichi 7/17/2014: Search mapped memory for emulators
ULONG _SafeMatchBytesInMappedMemory(LPCVOID pattern, DWORD patternSize, BYTE wildcard,
                                   ULONG start, ULONG stop, ULONG step)
{
  for (ULONG i = start; i < stop && Engine::processAttached_; i += step) // + patternSize to avoid overlap
    if (ULONG r = SafeMatchBytes(pattern, patternSize, i, i + step + patternSize + 1, wildcard))
      return r;
  return 0;
}

inline ULONG SafeMatchBytesInGCMemory(LPCVOID pattern, DWORD patternSize)
{
  enum : ULONG {
    start = MemDbg::MappedMemoryStartAddress // 0x01000000
    , stop = MemDbg::MemoryStopAddress // 0x7ffeffff
    , step = start
  };
  return _SafeMatchBytesInMappedMemory(pattern, patternSize, XX, start, stop, step);
}


inline ULONG SafeMatchBytesInPS2Memory(LPCVOID pattern, DWORD patternSize)
{
  // PCSX2 memory range
  // ds: begin from 0x20000000
  // cs: begin from 0x30000000
  enum : ULONG {
    //start = MemDbg::MappedMemoryStartAddress // 0x01000000
    start = 0x30000000 // larger than PSP to skip the garbage memory
    , stop = 0x40000000 // larger than PSP as PS2 has larger memory
    , step = 0x00010000 // smaller than PPS
    //, step = 0x00050000 // the same as PPS
    //, step = 0x1000 // step  must be at least 0x1000 (offset in SearchPattern)
  };
  return _SafeMatchBytesInMappedMemory(pattern, patternSize, XX, start, stop, step);
}

// 7/29/2014 jichi: I should move these functions to different files
// String utilities
// Return the address of the first non-zero address
LPCSTR reverse_search_begin(const char * s)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (*s)
    for (size_t i = 0; i < MAX_LENGTH; i++, s--)
      if (!*s)
        return s + 1;
  return nullptr;
}

bool all_ascii(const char *s)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (s)
    for (size_t i = 0; i < MAX_LENGTH && *s; i++, s--)
      if (*s < 0) // signed char
        return false;
  return true;
}

} // unnamed namespace

namespace Engine {

/********************************************************************************************
KiriKiri hook:
  Usually there are xp3 files in the game folder but also exceptions.
  Find TVP(KIRIKIRI) in the version description is a much more precise way.

  KiriKiri1 correspond to AGTH KiriKiri hook, but this doesn't always work well.
  Find call to GetGlyphOutlineW and go to function header. EAX will point to a
  structure contains character (at 0x14, [EAX+0x14]) we want. To split names into
  different threads AGTH uses [EAX], seems that this value stands for font size.
  Since KiriKiri is compiled by BCC and BCC fastcall uses EAX to pass the first
  parameter. Here we choose EAX is reasonable.
  KiriKiri2 is a redundant hook to catch text when 1 doesn't work. When this happens,
  usually there is a single GetTextExtentPoint32W contains irregular repetitions which
  is out of the scope of KS or KF. This time we find a point and split them into clean
  text threads. First find call to GetTextExtentPoint32W and step out of this function.
  Usually there is a small loop. It is this small loop messed up the text. We can find
  one ADD EBX,2 in this loop. It's clear that EBX is a string pointer goes through the
  string. After the loop EBX will point to the end of the string. So EBX-2 is the last
  char and we insert hook here to extract it.
********************************************************************************************/

bool FindKiriKiriHook(DWORD fun, DWORD size, DWORD pt, DWORD flag) // jichi 10/20/2014: change return value to bool
{
  enum : DWORD {
    // jichi 10/20/2014: mov ebp,esp, sub esp,*
    kirikiri1_sig = 0xec8b55,

    // jichi 10/20/2014:
    // 00e01542   53               push ebx
    // 00e01543   56               push esi
    // 00e01544   57               push edi
    kirikiri2_sig = 0x575653
  };
  enum : DWORD { StartAddress = 0x1000 };
  enum : DWORD { StartRange = 0x6000, StopRange = 0x8000 }; // jichi 10/20/2014: ITH original pattern range

  // jichi 10/20/2014: The KiriKiri patterns exist in multiple places of the game.
  //enum : DWORD { StartRange = 0x8000, StopRange = 0x9000 }; // jichi 10/20/2014: change to a different range

  //WCHAR str[0x40];
  DWORD sig = flag ? kirikiri2_sig : kirikiri1_sig;
  DWORD t = 0;
  for (DWORD i = StartAddress; i < size - 4; i++)
    if (*(WORD *)(pt + i) == 0x15ff) { // jichi 10/20/2014: call dword ptr ds
      DWORD addr = *(DWORD *)(pt + i + 2);

      // jichi 10/20/2014: There are multiple function calls. The flag+1 one is selected.
      // i.e. KiriKiri1: The first call to GetGlyphOutlineW is selected
      //      KiriKiri2: The second call to GetTextExtentPoint32W is selected
      if (addr >= pt && addr <= pt + size - 4
          && *(DWORD *)addr == fun)
        t++;
      if (t == flag + 1)  // We find call to GetGlyphOutlineW or GetTextExtentPoint32W.
        //swprintf(str, L"CALL addr:0x%.8X",i+pt);
        //ConsoleOutput(str);
        for (DWORD j = i; j > i - StartAddress; j--)
          if (((*(DWORD *)(pt + j)) & 0xffffff) == sig) {
            if (flag)  { // We find the function entry. flag indicate 2 hooks.
              t = 0;  // KiriKiri2, we need to find call to this function.
              for (DWORD k = j + StartRange; k < j + StopRange; k++) // Empirical range.
                if (*(BYTE *)(pt + k) == 0xe8) {
                  if (k + 5 + *(DWORD *)(pt + k + 1) == j)
                    t++;
                  if (t == 2) {
                    //for (k+=pt+0x14; *(WORD*)(k)!=0xC483;k++);
                    //swprintf(str, L"Hook addr: 0x%.8X",pt+k);
                    //ConsoleOutput(str);
                    HookParam hp = {};
                    hp.addr = pt + k + 0x14;
                    hp.off = -0x14;
                    hp.ind = -0x2;
                    hp.split = -0xc;
                    hp.length_offset = 1;
                    hp.type = USING_UNICODE|NO_CONTEXT|USING_SPLIT|DATA_INDIRECT;
                    ConsoleOutput("vnreng: INSERT KiriKiri2");
                    NewHook(hp, L"KiriKiri2");
                    return true;
                  }
                }
            } else {
              //swprintf(str, L"Hook addr: 0x%.8X",pt+j);
              //ConsoleOutput(str);
              HookParam hp = {};
              hp.addr = (DWORD)pt + j;
              hp.off = -0x8;
              hp.ind = 0x14;
              hp.split = -0x8;
              hp.length_offset = 1;
              hp.type = USING_UNICODE|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
              ConsoleOutput("vnreng: INSERT KiriKiri1");
              NewHook(hp, L"KiriKiri1");
              return true;
            }
            return false;
          }
        //ConsoleOutput("vnreng:KiriKiri: FAILED to find function entry");
    }
  if (flag)
    ConsoleOutput("vnreng:KiriKiri2: failed");
  else
    ConsoleOutput("vnreng:KiriKiri1: failed");
  return false;
}

bool InsertKiriKiriHook() // 9/20/2014 jichi: change return type to bool
{
  bool k1 = FindKiriKiriHook((DWORD)GetGlyphOutlineW,      module_limit_ - module_base_, module_base_, 0),  // KiriKiri1
       k2 = FindKiriKiriHook((DWORD)GetTextExtentPoint32W, module_limit_ - module_base_, module_base_, 1); // KiriKiri2
  //RegisterEngineType(ENGINE_KIRIKIRI);
  if (k1 && k2) {
    ConsoleOutput("vnreng:KiriKiri1: disable GDI hooks");
    DisableGDIHooks();
  }
  return k1 || k2;
}

namespace { // unnamed

// Skip individual L'\n' which might cause repetition.
//bool NewLineWideCharSkipper(LPVOID data, DWORD *size, HookParam *)
//{
//  LPCWSTR text = (LPCWSTR)data;
//  if (*size == 2 && *text == L'\n')
//    return false;
//  return true;
//}
//

void NewKiriKiriZHook(DWORD addr)
{
  HookParam hp = {};
  hp.addr = addr;
  hp.off = pusha_ecx_off - 4;
  hp.split = hp.off;    // the same logic but diff value as KiriKiri1, use [ecx] as split
  hp.ind = 0x14;        // the same as KiriKiri1
  hp.length_offset = 1; // the same as KiriKiri1
  hp.type = USING_UNICODE|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
  //hp.filter_fun = NewLineWideCharFilter;
  ConsoleOutput("vnreng: INSERT KiriKiriZ");
  NewHook(hp, L"KiriKiriZ");

  ConsoleOutput("vnreng:KiriKiriZ: disable GDI hooks");
  DisableGDIHooks();
}

bool KiriKiriZHook1(DWORD esp_base, HookParam *)
{
  DWORD addr = retof(esp_base); // retaddr
  addr = MemDbg::findEnclosingAlignedFunction(addr, 0x400); // range is around 0x377c50 - 0x377a40 = 0x210
  if (!addr) {
    ConsoleOutput("vnreng:KiriKiriZ: failed to find enclosing function");
    return false; // stop looking
  }
  NewKiriKiriZHook(addr);
  ConsoleOutput("vnreng: KiriKiriZ1 inserted");
  return false; // stop looking
}

bool InsertKiriKiriZHook1()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:KiriKiriZ1: failed to get memory range");
    return false;
  }

  ULONG addr = MemDbg::findCallerAddressAfterInt3((DWORD)::GetGlyphOutlineW, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:KiriKiriZ1: could not find caller of GetGlyphOutlineW");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = EXTERN_HOOK;
  hp.extern_fun = (HookParam::extern_fun_t)KiriKiriZHook1;
  ConsoleOutput("vnreng: INSERT KiriKiriZ1 empty hook");
  NewHook(hp, L"KiriKiriZ Hook");
  return true;
}

// jichi 1/30/2015: Add KiriKiriZ2 for サノバウィッチ
// It inserts to the same location as the old KiriKiriZ, but use a different way to find it.
bool InsertKiriKiriZHook2()
{
  const BYTE bytes[] = {
    0x38,0x4b, 0x21,     // 0122812f   384b 21          cmp byte ptr ds:[ebx+0x21],cl
    0x0f,0x95,0xc1,      // 01228132   0f95c1           setne cl
    0x33,0xc0,           // 01228135   33c0             xor eax,eax
    0x38,0x43, 0x20,     // 01228137   3843 20          cmp byte ptr ds:[ebx+0x20],al
    0x0f,0x95,0xc0,      // 0122813a   0f95c0           setne al
    0x33,0xc8,           // 0122813d   33c8             xor ecx,eax
    0x33,0x4b, 0x10,     // 0122813f   334b 10          xor ecx,dword ptr ds:[ebx+0x10]
    0x0f,0xb7,0x43, 0x14 // 01228142   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
  };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:KiriKiriZ2: pattern not found");
    return false;
  }

  // 012280e0   55               push ebp
  // 012280e1   8bec             mov ebp,esp
  addr = MemDbg::findEnclosingAlignedFunction(addr, 0x100); // 0x0122812f - 0x 012280dc = 83
  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (!addr || *(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:KiriKiriZ2: pattern found but the function offset is invalid");
    return false;
  }

  NewKiriKiriZHook(addr);
  ConsoleOutput("vnreng: KiriKiriZ2 inserted");
  return true;
}

} // unnamed namespace

// jichi 1/30/2015: Do KiriKiriZ2 first, which might insert to the same location as KiriKiri1.
bool InsertKiriKiriZHook()
{ return InsertKiriKiriZHook2() || InsertKiriKiriZHook1(); }

/********************************************************************************************
BGI hook:
  Usually game folder contains BGI.*. After first run BGI.gdb appears.

  BGI engine has font caching issue so the strategy is simple.
  First find call to TextOutA or TextOutW then reverse to function entry point,
  until full text is caught.
  After 2 tries we will get to the right place. Use ESP value to split text since
  it's likely to be different for different calls.
********************************************************************************************/
namespace { // unnamed

/** jichi 5/12/2014
 *  Sample game:  FORTUNE ARTERIAL, case 2 at 0x41ebd0
 *
 *  sub_41EBD0 proc near, seems to take 5 parameters
 *
 *  0041ebd0  /$ 83ec 28        sub esp,0x28 ; jichi: hook here, beginning of the function
 *  0041ebd3  |. 55             push ebp
 *  0041ebd4  |. 8b6c24 38      mov ebp,dword ptr ss:[esp+0x38]
 *  0041ebd8  |. 81fd 00ff0000  cmp ebp,0xff00
 *  0041ebde  |. 0f82 e1000000  jb bgi.0041ecc5
 *  0041ebe4  |. 81fd ffff0000  cmp ebp,0xffff
 *  0041ebea  |. 0f87 d5000000  ja bgi.0041ecc5
 *  0041ebf0  |. a1 54634900    mov eax,dword ptr ds:[0x496354]
 *  0041ebf5  |. 8bd5           mov edx,ebp
 *  0041ebf7  |. 81e2 ff000000  and edx,0xff
 *  0041ebfd  |. 53             push ebx
 *  0041ebfe  |. 4a             dec edx
 *  0041ebff  |. 33db           xor ebx,ebx
 *  0041ec01  |. 3bd0           cmp edx,eax
 *  0041ec03  |. 56             push esi
 *  0041ec04  |. 0f8d 8a000000  jge bgi.0041ec94
 *  0041ec0a  |. 57             push edi
 *  0041ec0b  |. b9 06000000    mov ecx,0x6
 *  0041ec10  |. be 5c634900    mov esi,bgi.0049635c
 *  0041ec15  |. 8d7c24 20      lea edi,dword ptr ss:[esp+0x20]
 *  0041ec19  |. f3:a5          rep movs dword ptr es:[edi],dword ptr ds>
 *  0041ec1b  |. 8b0d 58634900  mov ecx,dword ptr ds:[0x496358]
 *  0041ec21  |. 8b7424 3c      mov esi,dword ptr ss:[esp+0x3c]
 *  0041ec25  |. 8bc1           mov eax,ecx
 *  0041ec27  |. 5f             pop edi
 *  0041ec28  |. 0fafc2         imul eax,edx
 *  0041ec2b  |. 8b56 08        mov edx,dword ptr ds:[esi+0x8]
 *  0041ec2e  |. 894424 0c      mov dword ptr ss:[esp+0xc],eax
 *  0041ec32  |. 3bca           cmp ecx,edx
 *  0041ec34  |. 7e 02          jle short bgi.0041ec38
 *  0041ec36  |. 8bca           mov ecx,edx
 *  0041ec38  |> 8d4401 ff      lea eax,dword ptr ds:[ecx+eax-0x1]
 *  0041ec3c  |. 8b4c24 28      mov ecx,dword ptr ss:[esp+0x28]
 *  0041ec40  |. 894424 14      mov dword ptr ss:[esp+0x14],eax
 *  0041ec44  |. 8b46 0c        mov eax,dword ptr ds:[esi+0xc]
 *  0041ec47  |. 3bc8           cmp ecx,eax
 *  0041ec49  |. 895c24 10      mov dword ptr ss:[esp+0x10],ebx
 *  0041ec4d  |. 77 02          ja short bgi.0041ec51
 *  0041ec4f  |. 8bc1           mov eax,ecx
 *  0041ec51  |> 8d4c24 0c      lea ecx,dword ptr ss:[esp+0xc]
 *  0041ec55  |. 8d5424 1c      lea edx,dword ptr ss:[esp+0x1c]
 *  0041ec59  |. 48             dec eax
 *  0041ec5a  |. 51             push ecx
 *  0041ec5b  |. 52             push edx
 *  0041ec5c  |. 894424 20      mov dword ptr ss:[esp+0x20],eax
 *  0041ec60  |. e8 7b62feff    call bgi.00404ee0
 *  0041ec65  |. 8b4424 34      mov eax,dword ptr ss:[esp+0x34]
 *  0041ec69  |. 83c4 08        add esp,0x8
 *  0041ec6c  |. 83f8 03        cmp eax,0x3
 *  0041ec6f  |. 75 15          jnz short bgi.0041ec86
 *  0041ec71  |. 8b4424 48      mov eax,dword ptr ss:[esp+0x48]
 *  0041ec75  |. 8d4c24 1c      lea ecx,dword ptr ss:[esp+0x1c]
 *  0041ec79  |. 50             push eax
 *  0041ec7a  |. 51             push ecx
 *  0041ec7b  |. 56             push esi
 *  0041ec7c  |. e8 1fa0feff    call bgi.00408ca0
 */
bool InsertBGI1Hook()
{
  union {
    DWORD i;
    DWORD *id;
    BYTE *ib;
  };
  HookParam hp = {};
  for (i = module_base_ + 0x1000; i < module_limit_; i++) {
    if (ib[0] == 0x3d) {
      i++;
      if (id[0] == 0xffff) { //cmp eax,0xffff
        hp.addr = SafeFindEntryAligned(i, 0x40);
        if (hp.addr) {
          hp.off = 0xc;
          hp.split = -0x18;
          hp.type = BIG_ENDIAN|USING_SPLIT;
          hp.length_offset = 1;
          ConsoleOutput("vnreng:INSERT BGI#1");
          NewHook(hp, L"BGI");
          //RegisterEngineType(ENGINE_BGI);
          return true;
        }
      }
    }
    if (ib[0] == 0x81 && ((ib[1] & 0xf8) == 0xf8)) {
      i += 2;
      if (id[0] == 0xffff) { //cmp reg,0xffff
        hp.addr = SafeFindEntryAligned(i, 0x40);
        if (hp.addr) {
          hp.off = 0xc;
          hp.split = -0x18;
          hp.type = BIG_ENDIAN|USING_SPLIT;
          hp.length_offset = 1;
          ConsoleOutput("vnreng: INSERT BGI#2");
          NewHook(hp, L"BGI");
          //RegisterEngineType(ENGINE_BGI);
          return true;
        }
      }
    }
  }
  //ConsoleOutput("Unknown BGI engine.");

  //ConsoleOutput("Probably BGI. Wait for text.");
  //SwitchTrigger(true);
  //trigger_fun_=InsertBGIDynamicHook;
  ConsoleOutput("vnreng:BGI: failed");
  return false;
}

/**
 *  jichi 2/5/2014: Add an alternative BGI hook
 *
 *  Issue: This hook cannot extract character name for コトバの消えた日
 *
 *  See: http://tieba.baidu.com/p/2845113296
 *  世界と世界の真ん中で
 *  - /HSN4@349E0:sekachu.exe // Disabled BGI3, floating split char
 *  - /HS-1C:-4@68E56 // Not used, cannot detect character name
 *  - /HSC@34C80:sekachu.exe  // BGI2, extract both scenario and character names
 *
 *  [Lump of Sugar] 世界と世界の真ん中で
 *  /HSC@34C80:sekachu.exe
 *  - addr: 216192 = 0x34c80
 *  - module: 3599131534
 *  - off: 12 = 0xc
 *  - type: 65 = 0x41
 *
 *  base: 0x11a0000
 *  hook_addr = base + addr = 0x11d4c80
 *
 *  011d4c7e     cc             int3
 *  011d4c7f     cc             int3
 *  011d4c80  /$ 55             push ebp    ; jichi: hook here
 *  011d4c81  |. 8bec           mov ebp,esp
 *  011d4c83  |. 6a ff          push -0x1
 *  011d4c85  |. 68 e6592601    push sekachu.012659e6
 *  011d4c8a  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  011d4c90  |. 50             push eax
 *  011d4c91  |. 81ec 300d0000  sub esp,0xd30
 *  011d4c97  |. a1 d8c82801    mov eax,dword ptr ds:[0x128c8d8]
 *  011d4c9c  |. 33c5           xor eax,ebp
 *  011d4c9e  |. 8945 f0        mov dword ptr ss:[ebp-0x10],eax
 *  011d4ca1  |. 53             push ebx
 *  011d4ca2  |. 56             push esi
 *  011d4ca3  |. 57             push edi
 *  011d4ca4  |. 50             push eax
 *  011d4ca5  |. 8d45 f4        lea eax,dword ptr ss:[ebp-0xc]
 *  011d4ca8  |. 64:a3 00000000 mov dword ptr fs:[0],eax
 *  011d4cae  |. 8b4d 0c        mov ecx,dword ptr ss:[ebp+0xc]
 *  011d4cb1  |. 8b55 18        mov edx,dword ptr ss:[ebp+0x18]
 *  011d4cb4  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  011d4cb7  |. 8b5d 10        mov ebx,dword ptr ss:[ebp+0x10]
 *  011d4cba  |. 8b7d 38        mov edi,dword ptr ss:[ebp+0x38]
 *  011d4cbd  |. 898d d8f3ffff  mov dword ptr ss:[ebp-0xc28],ecx
 *  011d4cc3  |. 8b4d 28        mov ecx,dword ptr ss:[ebp+0x28]
 *  011d4cc6  |. 8995 9cf3ffff  mov dword ptr ss:[ebp-0xc64],edx
 *  011d4ccc  |. 51             push ecx
 *  011d4ccd  |. 8b0d 305c2901  mov ecx,dword ptr ds:[0x1295c30]
 *  011d4cd3  |. 8985 e0f3ffff  mov dword ptr ss:[ebp-0xc20],eax
 *  011d4cd9  |. 8b45 1c        mov eax,dword ptr ss:[ebp+0x1c]
 *  011d4cdc  |. 8d95 4cf4ffff  lea edx,dword ptr ss:[ebp-0xbb4]
 *  011d4ce2  |. 52             push edx
 *  011d4ce3  |. 899d 40f4ffff  mov dword ptr ss:[ebp-0xbc0],ebx
 *  011d4ce9  |. 8985 1cf4ffff  mov dword ptr ss:[ebp-0xbe4],eax
 *  011d4cef  |. 89bd f0f3ffff  mov dword ptr ss:[ebp-0xc10],edi
 *  011d4cf5  |. e8 862efdff    call sekachu.011a7b80
 *  011d4cfa  |. 33c9           xor ecx,ecx
 *  011d4cfc  |. 8985 60f3ffff  mov dword ptr ss:[ebp-0xca0],eax
 *  011d4d02  |. 3bc1           cmp eax,ecx
 *  011d4d04  |. 0f84 0f1c0000  je sekachu.011d6919
 *  011d4d0a  |. e8 31f6ffff    call sekachu.011d4340
 *  011d4d0f  |. e8 6cf8ffff    call sekachu.011d4580
 *  011d4d14  |. 8985 64f3ffff  mov dword ptr ss:[ebp-0xc9c],eax
 *  011d4d1a  |. 8a03           mov al,byte ptr ds:[ebx]
 *  011d4d1c  |. 898d 90f3ffff  mov dword ptr ss:[ebp-0xc70],ecx
 *  011d4d22  |. 898d 14f4ffff  mov dword ptr ss:[ebp-0xbec],ecx
 *  011d4d28  |. 898d 38f4ffff  mov dword ptr ss:[ebp-0xbc8],ecx
 *  011d4d2e  |. 8d71 01        lea esi,dword ptr ds:[ecx+0x1]
 *  011d4d31  |. 3c 20          cmp al,0x20                 ; jichi: pattern starts
 *  011d4d33  |. 7d 75          jge short sekachu.011d4daa
 *  011d4d35  |. 0fbec0         movsx eax,al
 *  011d4d38  |. 83c0 fe        add eax,-0x2                             ;  switch (cases 2..8)
 *  011d4d3b  |. 83f8 06        cmp eax,0x6
 *  011d4d3e  |. 77 6a          ja short sekachu.011d4daa
 *  011d4d40  |. ff2485 38691d0>jmp dword ptr ds:[eax*4+0x11d6938]
 *
 *  蒼の彼方 体験版 (8/6/2014)
 *  01312cce     cc             int3    ; jichi: reladdr = 0x32cd0
 *  01312ccf     cc             int3
 *  01312cd0   $ 55             push ebp
 *  01312cd1   . 8bec           mov ebp,esp
 *  01312cd3   . 83e4 f8        and esp,0xfffffff8
 *  01312cd6   . 6a ff          push -0x1
 *  01312cd8   . 68 86583a01    push 蒼の彼方.013a5886
 *  01312cdd   . 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  01312ce3   . 50             push eax
 *  01312ce4   . 81ec 38090000  sub esp,0x938
 *  01312cea   . a1 24673c01    mov eax,dword ptr ds:[0x13c6724]
 *  01312cef   . 33c4           xor eax,esp
 *  01312cf1   . 898424 3009000>mov dword ptr ss:[esp+0x930],eax
 *  01312cf8   . 53             push ebx
 *  01312cf9   . 56             push esi
 *  01312cfa   . 57             push edi
 *  01312cfb   . a1 24673c01    mov eax,dword ptr ds:[0x13c6724]
 *  01312d00   . 33c4           xor eax,esp
 *  01312d02   . 50             push eax
 *  01312d03   . 8d8424 4809000>lea eax,dword ptr ss:[esp+0x948]
 *  01312d0a   . 64:a3 00000000 mov dword ptr fs:[0],eax
 *  01312d10   . 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  01312d13   . 8b7d 0c        mov edi,dword ptr ss:[ebp+0xc]
 *  01312d16   . 8b5d 30        mov ebx,dword ptr ss:[ebp+0x30]
 *  01312d19   . 898424 8800000>mov dword ptr ss:[esp+0x88],eax
 *  01312d20   . 8b45 14        mov eax,dword ptr ss:[ebp+0x14]
 *  01312d23   . 898c24 8c00000>mov dword ptr ss:[esp+0x8c],ecx
 *  01312d2a   . 8b0d a8734a01  mov ecx,dword ptr ds:[0x14a73a8]
 *  01312d30   . 894424 4c      mov dword ptr ss:[esp+0x4c],eax
 *  01312d34   . 899424 bc00000>mov dword ptr ss:[esp+0xbc],edx
 *  01312d3b   . 8b55 20        mov edx,dword ptr ss:[ebp+0x20]
 *  01312d3e   . 51             push ecx                                 ; /arg1 => 00000000
 *  01312d3f   . 8d8424 0c02000>lea eax,dword ptr ss:[esp+0x20c]         ; |
 *  01312d46   . 897c24 34      mov dword ptr ss:[esp+0x34],edi          ; |
 *  01312d4a   . 899c24 8800000>mov dword ptr ss:[esp+0x88],ebx          ; |
 *  01312d51   . e8 ca59fdff    call 蒼の彼方.012e8720                       ; \蒼の彼方.012e8720
 *  01312d56   . 33c9           xor ecx,ecx
 *  01312d58   . 898424 f400000>mov dword ptr ss:[esp+0xf4],eax
 *  01312d5f   . 3bc1           cmp eax,ecx
 *  01312d61   . 0f84 391b0000  je 蒼の彼方.013148a0
 *  01312d67   . e8 54280000    call 蒼の彼方.013155c0
 *  01312d6c   . e8 7f2a0000    call 蒼の彼方.013157f0
 *  01312d71   . 898424 f800000>mov dword ptr ss:[esp+0xf8],eax
 *  01312d78   . 8a07           mov al,byte ptr ds:[edi]
 *  01312d7a   . 898c24 c400000>mov dword ptr ss:[esp+0xc4],ecx
 *  01312d81   . 894c24 2c      mov dword ptr ss:[esp+0x2c],ecx
 *  01312d85   . 894c24 1c      mov dword ptr ss:[esp+0x1c],ecx
 *  01312d89   . b9 01000000    mov ecx,0x1
 *  01312d8e   . 3c 20          cmp al,0x20     ; jichi: pattern starts
 *  01312d90   . 7d 58          jge short 蒼の彼方.01312dea
 *  01312d92   . 0fbec0         movsx eax,al
 *  01312d95   . 83c0 fe        add eax,-0x2                             ;  switch (cases 2..8)
 *  01312d98   . 83f8 06        cmp eax,0x6
 *  01312d9b   . 77 4d          ja short 蒼の彼方.01312dea
 *  01312d9d   . ff2485 c448310>jmp dword ptr ds:[eax*4+0x13148c4]
 *  01312da4   > 898c24 c400000>mov dword ptr ss:[esp+0xc4],ecx          ;  case 2 of switch 01312d95
 *  01312dab   . 03f9           add edi,ecx
 *  01312dad   . eb 37          jmp short 蒼の彼方.01312de6
 *  01312daf   > 894c24 2c      mov dword ptr ss:[esp+0x2c],ecx          ;  case 3 of switch 01312d95
 *  01312db3   . 03f9           add edi,ecx
 *  01312db5   . eb 2f          jmp short 蒼の彼方.01312de6
 *  01312db7   > ba e0103b01    mov edx,蒼の彼方.013b10e0                    ;  case 4 of switch 01312d95
 *  01312dbc   . eb 1a          jmp short 蒼の彼方.01312dd8
 *  01312dbe   > ba e4103b01    mov edx,蒼の彼方.013b10e4                    ;  case 5 of switch 01312d95
 *  01312dc3   . eb 13          jmp short 蒼の彼方.01312dd8
 *  01312dc5   > ba e8103b01    mov edx,蒼の彼方.013b10e8                    ;  case 6 of switch 01312d95
 *  01312dca   . eb 0c          jmp short 蒼の彼方.01312dd8
 *  01312dcc   > ba ec103b01    mov edx,蒼の彼方.013b10ec                    ;  case 7 of switch 01312d95
 *  01312dd1   . eb 05          jmp short 蒼の彼方.01312dd8
 *  01312dd3   > ba f0103b01    mov edx,蒼の彼方.013b10f0                    ;  case 8 of switch 01312d95
 *  01312dd8   > 8d7424 14      lea esi,dword ptr ss:[esp+0x14]
 *  01312ddc   . 894c24 1c      mov dword ptr ss:[esp+0x1c],ecx
 *  01312de0   . e8 1b8dffff    call 蒼の彼方.0130bb00
 *  01312de5   . 47             inc edi
 *  01312de6   > 897c24 30      mov dword ptr ss:[esp+0x30],edi
 *  01312dea   > 8d8424 0802000>lea eax,dword ptr ss:[esp+0x208]         ;  default case of switch 01312d95
 *  01312df1   . e8 ba1b0000    call 蒼の彼方.013149b0
 *  01312df6   . 837d 10 00     cmp dword ptr ss:[ebp+0x10],0x0
 *  01312dfa   . 8bb424 2802000>mov esi,dword ptr ss:[esp+0x228]
 *  01312e01   . 894424 5c      mov dword ptr ss:[esp+0x5c],eax
 *  01312e05   . 74 12          je short 蒼の彼方.01312e19
 *  01312e07   . 56             push esi                                 ; /arg1
 *  01312e08   . e8 c31b0000    call 蒼の彼方.013149d0                       ; \蒼の彼方.013149d0
 *  01312e0d   . 83c4 04        add esp,0x4
 *  01312e10   . 898424 c000000>mov dword ptr ss:[esp+0xc0],eax
 *  01312e17   . eb 0b          jmp short 蒼の彼方.01312e24
 *  01312e19   > c78424 c000000>mov dword ptr ss:[esp+0xc0],0x0
 *  01312e24   > 8b4b 04        mov ecx,dword ptr ds:[ebx+0x4]
 *  01312e27   . 0fafce         imul ecx,esi
 *  01312e2a   . b8 1f85eb51    mov eax,0x51eb851f
 *  01312e2f   . f7e9           imul ecx
 *  01312e31   . c1fa 05        sar edx,0x5
 *  01312e34   . 8bca           mov ecx,edx
 *  01312e36   . c1e9 1f        shr ecx,0x1f
 *  01312e39   . 03ca           add ecx,edx
 *  01312e3b   . 894c24 70      mov dword ptr ss:[esp+0x70],ecx
 *  01312e3f   . 85c9           test ecx,ecx
 *  01312e41   . 7f 09          jg short 蒼の彼方.01312e4c
 *  01312e43   . b9 01000000    mov ecx,0x1
 *  01312e48   . 894c24 70      mov dword ptr ss:[esp+0x70],ecx
 *  01312e4c   > 8b53 08        mov edx,dword ptr ds:[ebx+0x8]
 *  01312e4f   . 0fafd6         imul edx,esi
 *  01312e52   . b8 1f85eb51    mov eax,0x51eb851f
 *  01312e57   . f7ea           imul edx
 *  01312e59   . c1fa 05        sar edx,0x5
 *  01312e5c   . 8bc2           mov eax,edx
 *  01312e5e   . c1e8 1f        shr eax,0x1f
 *  01312e61   . 03c2           add eax,edx
 *  01312e63   . 894424 78      mov dword ptr ss:[esp+0x78],eax
 *  01312e67   . 85c0           test eax,eax
 *  01312e69   . 7f 09          jg short 蒼の彼方.01312e74
 *  01312e6b   . b8 01000000    mov eax,0x1
 *  01312e70   . 894424 78      mov dword ptr ss:[esp+0x78],eax
 *  01312e74   > 33d2           xor edx,edx
 *  01312e76   . 895424 64      mov dword ptr ss:[esp+0x64],edx
 *  01312e7a   . 895424 6c      mov dword ptr ss:[esp+0x6c],edx
 *  01312e7e   . 8b13           mov edx,dword ptr ds:[ebx]
 *  01312e80   . 4a             dec edx                                  ;  switch (cases 1..2)
 *  01312e81   . 74 0e          je short 蒼の彼方.01312e91
 *  01312e83   . 4a             dec edx
 *  01312e84   . 75 13          jnz short 蒼の彼方.01312e99
 *  01312e86   . 8d1409         lea edx,dword ptr ds:[ecx+ecx]           ;  case 2 of switch 01312e80
 *  01312e89   . 895424 64      mov dword ptr ss:[esp+0x64],edx
 *  01312e8d   . 03c0           add eax,eax
 *  01312e8f   . eb 04          jmp short 蒼の彼方.01312e95
 *  01312e91   > 894c24 64      mov dword ptr ss:[esp+0x64],ecx          ;  case 1 of switch 01312e80
 *  01312e95   > 894424 6c      mov dword ptr ss:[esp+0x6c],eax
 *  01312e99   > 8b9c24 3802000>mov ebx,dword ptr ss:[esp+0x238]         ;  default case of switch 01312e80
 *  01312ea0   . 8bc3           mov eax,ebx
 *  01312ea2   . e8 d98bffff    call 蒼の彼方.0130ba80
 *  01312ea7   . 8bc8           mov ecx,eax
 *  01312ea9   . 8bc3           mov eax,ebx
 *  01312eab   . e8 e08bffff    call 蒼の彼方.0130ba90
 *  01312eb0   . 6a 01          push 0x1                                 ; /arg1 = 00000001
 *  01312eb2   . 8bd0           mov edx,eax                              ; |
 *  01312eb4   . 8db424 1c01000>lea esi,dword ptr ss:[esp+0x11c]         ; |
 *  01312ebb   . e8 3056fdff    call 蒼の彼方.012e84f0                       ; \蒼の彼方.012e84f0
 *  01312ec0   . 8bc7           mov eax,edi
 *  01312ec2   . 83c4 04        add esp,0x4
 *  01312ec5   . 8d70 01        lea esi,dword ptr ds:[eax+0x1]
 *  01312ec8   > 8a08           mov cl,byte ptr ds:[eax]
 *  01312eca   . 40             inc eax
 *  01312ecb   . 84c9           test cl,cl
 *  01312ecd   .^75 f9          jnz short 蒼の彼方.01312ec8
 *  01312ecf   . 2bc6           sub eax,esi
 *  01312ed1   . 40             inc eax
 *  01312ed2   . 50             push eax
 *  01312ed3   . e8 e74c0600    call 蒼の彼方.01377bbf
 *  01312ed8   . 33f6           xor esi,esi
 *  01312eda   . 83c4 04        add esp,0x4
 */
//static inline size_t _bgistrlen(LPCSTR text)
//{
//  size_t r = ::strlen(text);
//  if (r >=2 && *(WORD *)(text + r - 2) == 0xa581) // remove trailing ▼ = \x81\xa5
//    r -= 2;
//  return r;
//}
//
//static void SpecialHookBGI2(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
//{
//  LPCSTR text = (LPCSTR)*(DWORD *)(esp_base + hp->off);
//  if (text) {
//    *data = (DWORD)text;
//    *len = _bgistrlen(text);
//  }
//}

bool InsertBGI2Hook()
{
  const BYTE bytes[] = {
    0x3c, 0x20,      // 011d4d31  |. 3c 20          cmp al,0x20
    0x7d, XX,        // 011d4d33  |. 7d 75          jge short sekachu.011d4daa ; jichi: 0x75 or 0x58
    0x0f,0xbe,0xc0,  // 011d4d35  |. 0fbec0         movsx eax,al
    0x83,0xc0, 0xfe, // 011d4d38  |. 83c0 fe        add eax,-0x2               ;  switch (cases 2..8)
    0x83,0xf8, 0x06  // 011d4d3b  |. 83f8 06        cmp eax,0x6
    // The following code does not exist in newer BGI games after 蒼の彼方
    //0x77, 0x6a     // 011d4d3e  |. 77 6a          ja short sekachu.011d4daa
  };
  enum {  // distance to the beginning of the function
    hook_offset_3 = 0x34c80 - 0x34d31 // for old BGI2 game, text is in arg2
    , hook_offset_2 = 0x01312cd0 - 0x01312d8e // for new BGI2 game since 蒼の彼方 (2014/08), text is in arg3
  };

  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::matchBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:BGI2: pattern not found");
    return false;
  }

  DWORD funaddr = MemDbg::findEnclosingAlignedFunction(addr, 0x100); // range is around 177 ~ 190

  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (!funaddr || *(BYTE *)funaddr != push_ebp) {
    ConsoleOutput("vnreng:BGI2: pattern found but the function offset is invalid");
    return false;
  }

  HookParam hp = {};
  switch (funaddr - addr) {
  case hook_offset_3: hp.off = 4 * 3; break; // arg3
  case hook_offset_2: hp.off = 4 * 2; break; // arg2
  default:
    ConsoleOutput("vnreng:BGI2: function found bug unrecognized hook offset");
    return false;
  }
  hp.addr = funaddr;

  // jichi 5/12/2014: Using split could distinguish name and choices. But the signature might become unstable
  hp.type = USING_STRING|USING_SPLIT;
  hp.split = 4 * 8; // pseudo arg8
  //hp.split = -0x18;

  //ITH_GROWL_DWORD2(hp.addr, module_base_);

  ConsoleOutput("vnreng: INSERT BGI2");
  NewHook(hp, L"BGI2");

  // Disable TextOutA, which is cached and hence missing characters.
  ConsoleOutput("vnreng:BGI2: disable GDI hooks");
  DisableGDIHooks();
  return true;
}


} // unnamed

// jichi 5/12/2014: BGI1 and BGI2 game can co-exist, such as 世界と世界の真ん中で
// BGI1 can exist in both old and new games
// BGI2 only exist in new games
// Insert BGI2 first.
bool InsertBGIHook()
{ return InsertBGI2Hook() ||  InsertBGI1Hook(); }

/********************************************************************************************
Reallive hook:
  Process name is reallive.exe or reallive*.exe.

  Technique to find Reallive hook is quite different from 2 above.
  Usually Reallive engine has a font caching issue. This time we wait
  until the first call to GetGlyphOutlineA. Reallive engine usually set
  up stack frames so we can just refer to EBP to find function entry.

********************************************************************************************/
static bool InsertRealliveDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetGlyphOutlineA)
    return false;
  if (DWORD i = frame) {
    i = *(DWORD *)(i + 4);
    for (DWORD j = i; j > i - 0x100; j--)
      if (*(WORD *)j == 0xec83) { // jichi 7/26/2014: function starts
        HookParam hp = {};
        hp.addr = j;
        hp.off = 0x14;
        hp.split = -0x18;
        hp.length_offset = 1;
        hp.type = BIG_ENDIAN|USING_SPLIT;
        NewHook(hp, L"RealLive");
        //RegisterEngineType(ENGINE_REALLIVE);
        return true;
      }
  }
  return true; // jichi 12/25/2013: return true
}
void InsertRealliveHook()
{
  //ConsoleOutput("Probably Reallive. Wait for text.");
  ConsoleOutput("vnreng: TRIGGER Reallive");
  trigger_fun_ = InsertRealliveDynamicHook;
  SwitchTrigger(true);
}

namespace { // unnamed

/**
 *  jichi 8/17/2013:  SiglusEngine from siglusengine.exe
 *  The old hook does not work for new games.
 *  The new hook cannot recognize character names.
 *  Insert old first. As the pattern could also be found in the old engine.
 */

/** jichi 10/25/2014: new SiglusEngine2 that can extract character name
 *
 *  Sample game: リア充クラスメイト孕ませ催眠 -- /HW-4@F67DC:SiglusEngine.exe
 *  The character is in [edx+ecx*2]. Text in edx, and offset in ecx.
 *
 *  002667be   cc               int3
 *  002667bf   cc               int3
 *  002667c0   55               push ebp ; jichi: hook here
 *  002667c1   8bec             mov ebp,esp
 *  002667c3   8bd1             mov edx,ecx
 *  002667c5   8b4d 0c          mov ecx,dword ptr ss:[ebp+0xc]
 *  002667c8   83f9 01          cmp ecx,0x1
 *  002667cb   75 17            jnz short .002667e4
 *  002667cd   837a 14 08       cmp dword ptr ds:[edx+0x14],0x8
 *  002667d1   72 02            jb short .002667d5
 *  002667d3   8b12             mov edx,dword ptr ds:[edx]
 *  002667d5   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  002667d8   66:8b45 10       mov ax,word ptr ss:[ebp+0x10]
 *  002667dc   66:89044a        mov word ptr ds:[edx+ecx*2],ax  ; jichi: wchar_t is in ax
 *  002667e0   5d               pop ebp
 *  002667e1   c2 0c00          retn 0xc
 *  002667e4   837a 14 08       cmp dword ptr ds:[edx+0x14],0x8
 *  002667e8   72 02            jb short .002667ec
 *  002667ea   8b12             mov edx,dword ptr ds:[edx]
 *  002667ec   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  002667ef   57               push edi
 *  002667f0   8d3c42           lea edi,dword ptr ds:[edx+eax*2]
 *  002667f3   85c9             test ecx,ecx
 *  002667f5   74 16            je short .0026680d
 *  002667f7   8b45 10          mov eax,dword ptr ss:[ebp+0x10]
 *  002667fa   0fb7d0           movzx edx,ax
 *  002667fd   8bc2             mov eax,edx
 *  002667ff   c1e2 10          shl edx,0x10
 *  00266802   0bc2             or eax,edx
 *  00266804   d1e9             shr ecx,1
 *  00266806   f3:ab            rep stos dword ptr es:[edi]
 *  00266808   13c9             adc ecx,ecx
 *  0026680a   66:f3:ab         rep stos word ptr es:[edi]
 *  0026680d   5f               pop edi
 *  0026680e   5d               pop ebp
 *  0026680f   c2 0c00          retn 0xc
 *  00266812   cc               int3
 *  00266813   cc               int3
 *
 *  Stack when enter function call:
 *  04cee270   00266870  return to .00266870 from .002667c0
 *  04cee274   00000002  jichi: arg1, ecx
 *  04cee278   00000001  jichi: arg2, always 1
 *  04cee27c   000050ac  jichi: arg3, wchar_t
 *  04cee280   04cee4fc  jichi: text address
 *  04cee284   0ead055c  arg5
 *  04cee288   0ead0568  arg6, last text when arg6 = arg5 = 2
 *  04cee28c  /04cee2c0
 *  04cee290  |00266969  return to .00266969 from .00266820
 *  04cee294  |00000001
 *  04cee298  |000050ac
 *  04cee29c  |e1466fb2
 *  04cee2a0  |072f45f0
 *
 *  Target address (edx) is at [[ecx]] when enter function.
 */

// jichi: 8/17/2013: Change return type to bool
bool InsertSiglus3Hook()
{
  const BYTE bytes[] = {
    0x8b,0x12,             // 002667d3   8b12             mov edx,dword ptr ds:[edx]
    0x8b,0x4d, 0x08,       // 002667d5   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
    0x66,0x8b,0x45, 0x10,  // 002667d8   66:8b45 10       mov ax,word ptr ss:[ebp+0x10]
    0x66,0x89,0x04,0x4a    // 002667dc   66:89044a        mov word ptr ds:[edx+ecx*2],ax ; jichi: wchar_t in ax
                           // 002667e0   5d               pop ebp
                           // 002667e1   c2 0c00          retn 0xc
  };
  enum { hook_offset = sizeof(bytes) - 4 };
  ULONG range = max(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) { // jichi 8/17/2013: Add "== 0" check to prevent breaking new games
    //ConsoleOutput("Unknown SiglusEngine");
    ConsoleOutput("vnreng:Siglus3: pattern not found");
    return false;
  }

  //addr = MemDbg::findEnclosingAlignedFunction(addr, 50); // 0x002667dc - 0x002667c0 = 28
  //if (!addr) {
  //  ConsoleOutput("vnreng:Siglus3: enclosing function not found");
  //  return false;
  //}

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = pusha_eax_off - 4;
  hp.type = USING_UNICODE;
  hp.length_offset = 1;
  //hp.text_fun = SpecialHookSiglus3;

  ConsoleOutput("vnreng: INSERT Siglus3");
  NewHook(hp, L"SiglusEngine3");

  ConsoleOutput("vnreng:Siglus3: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

/**
 *  jichi 8/16/2013: Insert new siglus hook
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2531786952
 *  Issue: floating text
 *  Example:
 *  0153588b9534fdffff8b43583bd7
 *  0153 58          add dword ptr ds:[ebx+58],edx
 *  8b95 34fdffff    mov edx,dword ptr ss:[ebp-2cc]
 *  8b43 58          mov eax,dword ptr ds:[ebx+58]
 *  3bd7             cmp edx,edi    ; hook here
 *
 *  /HW-1C@D9DB2:SiglusEngine.exe
 *  - addr: 892338 (0xd9db2)
 *  - text_fun: 0x0
 *  - function: 0
 *  - hook_len: 0
 *  - ind: 0
 *  - length_offset: 1
 *  - module: 356004490 (0x1538328a)
 *  - off: 4294967264 (0xffffffe0L, 0x-20)
 *  - recover_len: 0
 *  - split: 0
 *  - split_ind: 0
 *  - type: 66   (0x42)
 *
 *  10/19/2014: There are currently two patterns to find the function to render scenario text.
 *  In the future, if both of them do not work again, try the following pattern instead.
 *  It is used to infer SiglusEngine2's logic in vnragent.
 *
 *  01140f8d   56               push esi
 *  01140f8e   8d8b 0c010000    lea ecx,dword ptr ds:[ebx+0x10c]
 *  01140f94   e8 67acfcff      call .0110bc00
 *  01140f99   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  01140f9d   72 04            jb short .01140fa3
 *  01140f9f   8b37             mov esi,dword ptr ds:[edi]
 *  01140fa1   eb 02            jmp short .01140fa5
 *
 *  Type1 (聖娼女):
 *
 *  013aac6c   cc               int3
 *  013aac6d   cc               int3
 *  013aac6e   cc               int3
 *  013aac6f   cc               int3
 *  013aac70   55               push ebp    ; jichi: vnragent hooked here
 *  013aac71   8bec             mov ebp,esp
 *  013aac73   6a ff            push -0x1
 *  013aac75   68 d8306101      push .016130d8
 *  013aac7a   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  013aac80   50               push eax
 *  013aac81   81ec dc020000    sub esp,0x2dc
 *  013aac87   a1 90f46a01      mov eax,dword ptr ds:[0x16af490]
 *  013aac8c   33c5             xor eax,ebp
 *  013aac8e   8945 f0          mov dword ptr ss:[ebp-0x10],eax
 *  013aac91   53               push ebx
 *  013aac92   56               push esi
 *  013aac93   57               push edi
 *  013aac94   50               push eax
 *  013aac95   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  013aac98   64:a3 00000000   mov dword ptr fs:[0],eax
 *  013aac9e   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  013aaca1   8b5d 08          mov ebx,dword ptr ss:[ebp+0x8]
 *  013aaca4   8bf9             mov edi,ecx
 *  013aaca6   8b77 10          mov esi,dword ptr ds:[edi+0x10]
 *  013aaca9   89bd 20fdffff    mov dword ptr ss:[ebp-0x2e0],edi
 *  013aacaf   8985 18fdffff    mov dword ptr ss:[ebp-0x2e8],eax
 *  013aacb5   85f6             test esi,esi
 *  013aacb7   0f84 77040000    je .013ab134
 *  013aacbd   8b93 18010000    mov edx,dword ptr ds:[ebx+0x118]
 *  013aacc3   2b93 14010000    sub edx,dword ptr ds:[ebx+0x114]
 *  013aacc9   8d8b 14010000    lea ecx,dword ptr ds:[ebx+0x114]
 *  013aaccf   b8 67666666      mov eax,0x66666667
 *  013aacd4   f7ea             imul edx
 *  013aacd6   c1fa 08          sar edx,0x8
 *  013aacd9   8bc2             mov eax,edx
 *  013aacdb   c1e8 1f          shr eax,0x1f
 *  013aacde   03c2             add eax,edx
 *  013aace0   03c6             add eax,esi
 *  013aace2   50               push eax
 *  013aace3   e8 5896fcff      call .01374340
 *  013aace8   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  013aacec   72 04            jb short .013aacf2
 *  013aacee   8b07             mov eax,dword ptr ds:[edi]
 *  013aacf0   eb 02            jmp short .013aacf4
 *  013aacf2   8bc7             mov eax,edi
 *  013aacf4   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  013aacfa   8b57 14          mov edx,dword ptr ds:[edi+0x14]
 *  013aacfd   83fa 08          cmp edx,0x8
 *  013aad00   72 04            jb short .013aad06
 *  013aad02   8b0f             mov ecx,dword ptr ds:[edi]
 *  013aad04   eb 02            jmp short .013aad08
 *  013aad06   8bcf             mov ecx,edi
 *  013aad08   8b47 10          mov eax,dword ptr ds:[edi+0x10]
 *  013aad0b   8bb5 24fdffff    mov esi,dword ptr ss:[ebp-0x2dc]
 *  013aad11   03c0             add eax,eax
 *  013aad13   03c8             add ecx,eax
 *  013aad15   3bf1             cmp esi,ecx
 *  013aad17   0f84 17040000    je .013ab134
 *  013aad1d   c785 34fdffff 00>mov dword ptr ss:[ebp-0x2cc],0x0
 *  013aad27   c785 2cfdffff ff>mov dword ptr ss:[ebp-0x2d4],-0x1
 *  013aad31   89b5 1cfdffff    mov dword ptr ss:[ebp-0x2e4],esi
 *  013aad37   83fa 08          cmp edx,0x8
 *  013aad3a   72 04            jb short .013aad40
 *  013aad3c   8b0f             mov ecx,dword ptr ds:[edi]
 *  013aad3e   eb 02            jmp short .013aad42
 *  013aad40   8bcf             mov ecx,edi
 *  013aad42   03c1             add eax,ecx
 *  013aad44   8d8d 2cfdffff    lea ecx,dword ptr ss:[ebp-0x2d4]
 *  013aad4a   51               push ecx
 *  013aad4b   8d95 34fdffff    lea edx,dword ptr ss:[ebp-0x2cc]
 *  013aad51   52               push edx
 *  013aad52   50               push eax
 *  013aad53   8d85 24fdffff    lea eax,dword ptr ss:[ebp-0x2dc]
 *  013aad59   50               push eax
 *  013aad5a   e8 b183faff      call .01353110
 *  013aad5f   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  013aad65   83c4 10          add esp,0x10
 *  013aad68   83fe 0a          cmp esi,0xa
 *  013aad6b   75 09            jnz short .013aad76
 *  013aad6d   8bcb             mov ecx,ebx
 *  013aad6f   e8 ac050000      call .013ab320
 *  013aad74  ^eb 84            jmp short .013aacfa
 *  013aad76   83fe 07          cmp esi,0x7
 *  013aad79   75 2a            jnz short .013aada5
 *  013aad7b   33c9             xor ecx,ecx
 *  013aad7d   33c0             xor eax,eax
 *  013aad7f   66:898b ec000000 mov word ptr ds:[ebx+0xec],cx
 *  013aad86   8bcb             mov ecx,ebx
 *  013aad88   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  013aad8e   8983 f0000000    mov dword ptr ds:[ebx+0xf0],eax
 *  013aad94   e8 87050000      call .013ab320
 *  013aad99   c683 f9000000 01 mov byte ptr ds:[ebx+0xf9],0x1
 *  013aada0  ^e9 55ffffff      jmp .013aacfa
 *  013aada5   8b85 34fdffff    mov eax,dword ptr ss:[ebp-0x2cc]
 *  013aadab   85c0             test eax,eax
 *  013aadad   75 37            jnz short .013aade6
 *  013aadaf   85f6             test esi,esi
 *  013aadb1  ^0f84 43ffffff    je .013aacfa
 *  013aadb7   85c0             test eax,eax
 *  013aadb9   75 2b            jnz short .013aade6
 *  013aadbb   f605 c0be9f05 01 test byte ptr ds:[0x59fbec0],0x1
 *  013aadc2   75 0c            jnz short .013aadd0
 *  013aadc4   830d c0be9f05 01 or dword ptr ds:[0x59fbec0],0x1
 *  013aadcb   e8 f02a0b00      call .0145d8c0
 *  013aadd0   0fb7d6           movzx edx,si
 *  013aadd3   80ba c0be9e05 01 cmp byte ptr ds:[edx+0x59ebec0],0x1
 *  013aadda   75 0a            jnz short .013aade6
 *  013aaddc   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  013aaddf   99               cdq
 *  013aade0   2bc2             sub eax,edx
 *  013aade2   d1f8             sar eax,1
 *  013aade4   eb 03            jmp short .013aade9
 *  013aade6   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  013aade9   8b8b a0000000    mov ecx,dword ptr ds:[ebx+0xa0]
 *  013aadef   8b53 18          mov edx,dword ptr ds:[ebx+0x18]
 *  013aadf2   8985 30fdffff    mov dword ptr ss:[ebp-0x2d0],eax
 *  013aadf8   0343 58          add eax,dword ptr ds:[ebx+0x58]
 *  013aadfb   03d1             add edx,ecx
 *  013aadfd   3bc2             cmp eax,edx
 *  013aadff   7f 0f            jg short .013aae10
 *  013aae01   3bc1             cmp eax,ecx
 *  013aae03   7e 30            jle short .013aae35
 *  013aae05   8bc6             mov eax,esi
 *  013aae07   e8 94faffff      call .013aa8a0
 *  013aae0c   84c0             test al,al
 *  013aae0e   75 25            jnz short .013aae35
 *  013aae10   8bcb             mov ecx,ebx
 *  013aae12   e8 09050000      call .013ab320
 *  013aae17   83bd 34fdffff 00 cmp dword ptr ss:[ebp-0x2cc],0x0
 *  013aae1e   75 15            jnz short .013aae35
 *  013aae20   83fe 20          cmp esi,0x20
 *  013aae23  ^0f84 d1feffff    je .013aacfa
 *  013aae29   81fe 00300000    cmp esi,0x3000
 *  013aae2f  ^0f84 c5feffff    je .013aacfa
 *  013aae35   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  013aae38   3b83 a4000000    cmp eax,dword ptr ds:[ebx+0xa4]
 *  013aae3e   0f8d 7e020000    jge .013ab0c2
 *  013aae44   8d8d 38fdffff    lea ecx,dword ptr ss:[ebp-0x2c8]
 *  013aae4a   51               push ecx
 *  013aae4b   e8 30e4ffff      call .013a9280
 *  013aae50   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  013aae57   8b43 74          mov eax,dword ptr ds:[ebx+0x74]
 *  013aae5a   8b0d 88b26c01    mov ecx,dword ptr ds:[0x16cb288]
 *  013aae60   83f8 ff          cmp eax,-0x1
 *  013aae63   74 04            je short .013aae69
 *  013aae65   8bd0             mov edx,eax
 *  013aae67   eb 19            jmp short .013aae82
 *  013aae69   80b9 60010000 00 cmp byte ptr ds:[ecx+0x160],0x0
 *  013aae70   74 0d            je short .013aae7f
 *  013aae72   8b83 e0000000    mov eax,dword ptr ds:[ebx+0xe0]
 *  013aae78   8bd0             mov edx,eax
 *  013aae7a   83f8 ff          cmp eax,-0x1
 *  013aae7d   75 03            jnz short .013aae82
 *  013aae7f   8b53 24          mov edx,dword ptr ds:[ebx+0x24]
 *  013aae82   8b43 78          mov eax,dword ptr ds:[ebx+0x78]
 *  013aae85   83f8 ff          cmp eax,-0x1
 *  013aae88   75 17            jnz short .013aaea1
 *  013aae8a   80b9 60010000 00 cmp byte ptr ds:[ecx+0x160],0x0
 *  013aae91   74 0b            je short .013aae9e
 *  013aae93   8b83 e4000000    mov eax,dword ptr ds:[ebx+0xe4]
 *  013aae99   83f8 ff          cmp eax,-0x1
 *  013aae9c   75 03            jnz short .013aaea1
 *  013aae9e   8b43 28          mov eax,dword ptr ds:[ebx+0x28]
 *  013aaea1   8b4b 60          mov ecx,dword ptr ds:[ebx+0x60]
 *  013aaea4   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  013aaeaa   034b 58          add ecx,dword ptr ds:[ebx+0x58]
 *  013aaead   8b7b 68          mov edi,dword ptr ds:[ebx+0x68]
 *  013aaeb0   8985 28fdffff    mov dword ptr ss:[ebp-0x2d8],eax
 *  013aaeb6   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  013aaeb9   0343 64          add eax,dword ptr ds:[ebx+0x64]
 *  013aaebc   83fe 01          cmp esi,0x1
 *  013aaebf   75 02            jnz short .013aaec3
 *  013aaec1   33d2             xor edx,edx
 *  013aaec3   80bb fa000000 00 cmp byte ptr ds:[ebx+0xfa],0x0
 *  013aaeca   89b5 38fdffff    mov dword ptr ss:[ebp-0x2c8],esi
 *  013aaed0   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  013aaed6   8995 44fdffff    mov dword ptr ss:[ebp-0x2bc],edx
 *  013aaedc   8b95 28fdffff    mov edx,dword ptr ss:[ebp-0x2d8]
 *  013aaee2   89b5 3cfdffff    mov dword ptr ss:[ebp-0x2c4],esi
 *  013aaee8   89bd 40fdffff    mov dword ptr ss:[ebp-0x2c0],edi
 *  013aaeee   8995 48fdffff    mov dword ptr ss:[ebp-0x2b8],edx
 *  013aaef4   898d 4cfdffff    mov dword ptr ss:[ebp-0x2b4],ecx
 *  013aaefa   8985 50fdffff    mov dword ptr ss:[ebp-0x2b0],eax
 *  013aaf00   74 19            je short .013aaf1b
 *  013aaf02   8b43 58          mov eax,dword ptr ds:[ebx+0x58]
 *  013aaf05   8b4b 5c          mov ecx,dword ptr ds:[ebx+0x5c]
 *  013aaf08   8983 fc000000    mov dword ptr ds:[ebx+0xfc],eax
 *  013aaf0e   898b 00010000    mov dword ptr ds:[ebx+0x100],ecx
 *  013aaf14   c683 fa000000 00 mov byte ptr ds:[ebx+0xfa],0x0
 *  013aaf1b   8b53 6c          mov edx,dword ptr ds:[ebx+0x6c]
 *  013aaf1e   0395 30fdffff    add edx,dword ptr ss:[ebp-0x2d0]
 *  013aaf24   33ff             xor edi,edi
 *  013aaf26   0153 58          add dword ptr ds:[ebx+0x58],edx
 *  013aaf29   8b95 34fdffff    mov edx,dword ptr ss:[ebp-0x2cc]
 *  013aaf2f   8b43 58          mov eax,dword ptr ds:[ebx+0x58]
 *  013aaf32   3bd7             cmp edx,edi             ; jichi: hook here
 *  013aaf34   75 4b            jnz short .013aaf81
 *  013aaf36   81fe 0c300000    cmp esi,0x300c  ; jichi 10/18/2014: searched here found the new siglus function
 *  013aaf3c   74 10            je short .013aaf4e
 *  013aaf3e   81fe 0e300000    cmp esi,0x300e
 *  013aaf44   74 08            je short .013aaf4e
 *  013aaf46   81fe 08ff0000    cmp esi,0xff08
 *  013aaf4c   75 33            jnz short .013aaf81
 *  013aaf4e   80bb f9000000 00 cmp byte ptr ds:[ebx+0xf9],0x0
 *  013aaf55   74 19            je short .013aaf70
 *  013aaf57   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  013aaf5d   66:89b3 ec000000 mov word ptr ds:[ebx+0xec],si
 *  013aaf64   c783 f0000000 01>mov dword ptr ds:[ebx+0xf0],0x1
 *  013aaf6e   eb 11            jmp short .013aaf81
 *  013aaf70   0fb783 ec000000  movzx eax,word ptr ds:[ebx+0xec]
 *  013aaf77   3bf0             cmp esi,eax
 *  013aaf79   75 06            jnz short .013aaf81
 *  013aaf7b   ff83 f0000000    inc dword ptr ds:[ebx+0xf0]
 *  013aaf81   8b8b f0000000    mov ecx,dword ptr ds:[ebx+0xf0]
 *  013aaf87   3bcf             cmp ecx,edi
 *  013aaf89   7e 71            jle short .013aaffc
 *  013aaf8b   3bd7             cmp edx,edi
 *  013aaf8d   75 50            jnz short .013aafdf
 *  013aaf8f   0fb783 ec000000  movzx eax,word ptr ds:[ebx+0xec]
 *  013aaf96   ba 0c300000      mov edx,0x300c
 *  013aaf9b   66:3bc2          cmp ax,dx
 *  013aaf9e   75 0f            jnz short .013aafaf
 *  013aafa0   81fe 0d300000    cmp esi,0x300d
 *  013aafa6   75 07            jnz short .013aafaf
 *  013aafa8   49               dec ecx
 *  013aafa9   898b f0000000    mov dword ptr ds:[ebx+0xf0],ecx
 *  013aafaf   b9 0e300000      mov ecx,0x300e
 *  013aafb4   66:3bc1          cmp ax,cx
 *  013aafb7   75 0e            jnz short .013aafc7
 *  013aafb9   81fe 0f300000    cmp esi,0x300f
 *  013aafbf   75 06            jnz short .013aafc7
 *  013aafc1   ff8b f0000000    dec dword ptr ds:[ebx+0xf0]
 *  013aafc7   ba 08ff0000      mov edx,0xff08
 *  013aafcc   66:3bc2          cmp ax,dx
 *  013aafcf   75 0e            jnz short .013aafdf
 *  013aafd1   81fe 09ff0000    cmp esi,0xff09
 *  013aafd7   75 06            jnz short .013aafdf
 *  013aafd9   ff8b f0000000    dec dword ptr ds:[ebx+0xf0]
 *  013aafdf   39bb f0000000    cmp dword ptr ds:[ebx+0xf0],edi
 *  013aafe5   75 15            jnz short .013aaffc
 *  013aafe7   33c0             xor eax,eax
 *  013aafe9   89bb e8000000    mov dword ptr ds:[ebx+0xe8],edi
 *  013aafef   66:8983 ec000000 mov word ptr ds:[ebx+0xec],ax
 *  013aaff6   89bb f0000000    mov dword ptr ds:[ebx+0xf0],edi
 *  013aaffc   8d8d 38fdffff    lea ecx,dword ptr ss:[ebp-0x2c8]
 *  013ab002   8dbb 14010000    lea edi,dword ptr ds:[ebx+0x114]
 *  013ab008   e8 b390fcff      call .013740c0
 *  013ab00d   33ff             xor edi,edi
 *  013ab00f   39bd 34fdffff    cmp dword ptr ss:[ebp-0x2cc],edi
 *  013ab015   75 0e            jnz short .013ab025
 *  013ab017   56               push esi
 *  013ab018   8d83 a8000000    lea eax,dword ptr ds:[ebx+0xa8]
 *  013ab01e   e8 5d080000      call .013ab880
 *  013ab023   eb 65            jmp short .013ab08a
 *  013ab025   8b85 1cfdffff    mov eax,dword ptr ss:[ebp-0x2e4]
 *  013ab02b   33c9             xor ecx,ecx
 *  013ab02d   66:894d d4       mov word ptr ss:[ebp-0x2c],cx
 *  013ab031   8b8d 24fdffff    mov ecx,dword ptr ss:[ebp-0x2dc]
 *  013ab037   c745 e8 07000000 mov dword ptr ss:[ebp-0x18],0x7
 *  013ab03e   897d e4          mov dword ptr ss:[ebp-0x1c],edi
 *  013ab041   3bc1             cmp eax,ecx
 *  013ab043   74 0d            je short .013ab052
 *  013ab045   2bc8             sub ecx,eax
 *  013ab047   d1f9             sar ecx,1
 *  013ab049   51               push ecx
 *  013ab04a   8d75 d4          lea esi,dword ptr ss:[ebp-0x2c]
 *  013ab04d   e8 de72f2ff      call .012d2330
 *  013ab052   6a ff            push -0x1
 *  013ab054   57               push edi
 *  013ab055   8d55 d4          lea edx,dword ptr ss:[ebp-0x2c]
 *  013ab058   52               push edx
 *  013ab059   8db3 a8000000    lea esi,dword ptr ds:[ebx+0xa8]
 *  013ab05f   c645 fc 02       mov byte ptr ss:[ebp-0x4],0x2
 *  013ab063   e8 3879f2ff      call .012d29a0
 *  013ab068   837d e8 08       cmp dword ptr ss:[ebp-0x18],0x8
 *  013ab06c   72 0c            jb short .013ab07a
 *  013ab06e   8b45 d4          mov eax,dword ptr ss:[ebp-0x2c]
 *  013ab071   50               push eax
 *  013ab072   e8 5fbe1900      call .01546ed6
 *  013ab077   83c4 04          add esp,0x4
 *  013ab07a   33c9             xor ecx,ecx
 *  013ab07c   c745 e8 07000000 mov dword ptr ss:[ebp-0x18],0x7
 *  013ab083   897d e4          mov dword ptr ss:[ebp-0x1c],edi
 *  013ab086   66:894d d4       mov word ptr ss:[ebp-0x2c],cx
 *  013ab08a   8bbd 20fdffff    mov edi,dword ptr ss:[ebp-0x2e0]
 *  013ab090   c683 f9000000 00 mov byte ptr ds:[ebx+0xf9],0x0
 *  013ab097   8d95 88feffff    lea edx,dword ptr ss:[ebp-0x178]
 *  013ab09d   52               push edx
 *  013ab09e   c745 fc 03000000 mov dword ptr ss:[ebp-0x4],0x3
 *  013ab0a5   e8 d6c70800      call .01437880
 *  013ab0aa   8d85 58fdffff    lea eax,dword ptr ss:[ebp-0x2a8]
 *  013ab0b0   50               push eax
 *  013ab0b1   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  013ab0b8   e8 c3c70800      call .01437880
 *  013ab0bd  ^e9 38fcffff      jmp .013aacfa
 *  013ab0c2   8b9d 18fdffff    mov ebx,dword ptr ss:[ebp-0x2e8]
 *  013ab0c8   85db             test ebx,ebx
 *  013ab0ca   74 68            je short .013ab134
 *  013ab0cc   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  013ab0d0   72 04            jb short .013ab0d6
 *  013ab0d2   8b07             mov eax,dword ptr ds:[edi]
 *  013ab0d4   eb 02            jmp short .013ab0d8
 *  013ab0d6   8bc7             mov eax,edi
 *  013ab0d8   8b4f 10          mov ecx,dword ptr ds:[edi+0x10]
 *  013ab0db   8d0448           lea eax,dword ptr ds:[eax+ecx*2]
 *  013ab0de   8b8d 1cfdffff    mov ecx,dword ptr ss:[ebp-0x2e4]
 *  013ab0e4   33d2             xor edx,edx
 *  013ab0e6   c745 cc 07000000 mov dword ptr ss:[ebp-0x34],0x7
 *  013ab0ed   c745 c8 00000000 mov dword ptr ss:[ebp-0x38],0x0
 *  013ab0f4   66:8955 b8       mov word ptr ss:[ebp-0x48],dx
 *  013ab0f8   3bc8             cmp ecx,eax
 *  013ab0fa   74 0f            je short .013ab10b
 *  013ab0fc   2bc1             sub eax,ecx
 *  013ab0fe   d1f8             sar eax,1
 *  013ab100   50               push eax
 *  013ab101   8bc1             mov eax,ecx
 *  013ab103   8d75 b8          lea esi,dword ptr ss:[ebp-0x48]
 *  013ab106   e8 2572f2ff      call .012d2330
 *  013ab10b   6a 00            push 0x0
 *  013ab10d   8d45 b8          lea eax,dword ptr ss:[ebp-0x48]
 *  013ab110   50               push eax
 *  013ab111   83c8 ff          or eax,0xffffffff
 *  013ab114   8bcb             mov ecx,ebx
 *  013ab116   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  013ab11d   e8 2e6ef2ff      call .012d1f50
 *  013ab122   837d cc 08       cmp dword ptr ss:[ebp-0x34],0x8
 *  013ab126   72 0c            jb short .013ab134
 *  013ab128   8b4d b8          mov ecx,dword ptr ss:[ebp-0x48]
 *  013ab12b   51               push ecx
 *  013ab12c   e8 a5bd1900      call .01546ed6
 *  013ab131   83c4 04          add esp,0x4
 *  013ab134   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  013ab137   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  013ab13e   59               pop ecx
 *  013ab13f   5f               pop edi
 *  013ab140   5e               pop esi
 *  013ab141   5b               pop ebx
 *  013ab142   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  013ab145   33cd             xor ecx,ebp
 *  013ab147   e8 6ab30e00      call .014964b6
 *  013ab14c   8be5             mov esp,ebp
 *  013ab14e   5d               pop ebp
 *  013ab14f   c2 0800          retn 0x8
 *  013ab152   cc               int3
 *  013ab153   cc               int3
 *  013ab154   cc               int3
 *
 *  10/18/2014 Type2: リア充クラスメイト孕ませ催眠
 *
 *  01140edb   cc               int3
 *  01140edc   cc               int3
 *  01140edd   cc               int3
 *  01140ede   cc               int3
 *  01140edf   cc               int3
 *  01140ee0   55               push ebp
 *  01140ee1   8bec             mov ebp,esp
 *  01140ee3   6a ff            push -0x1
 *  01140ee5   68 c6514a01      push .014a51c6
 *  01140eea   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  01140ef0   50               push eax
 *  01140ef1   81ec dc020000    sub esp,0x2dc
 *  01140ef7   a1 10745501      mov eax,dword ptr ds:[0x1557410]
 *  01140efc   33c5             xor eax,ebp
 *  01140efe   8945 f0          mov dword ptr ss:[ebp-0x10],eax
 *  01140f01   53               push ebx
 *  01140f02   56               push esi
 *  01140f03   57               push edi
 *  01140f04   50               push eax
 *  01140f05   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  01140f08   64:a3 00000000   mov dword ptr fs:[0],eax
 *  01140f0e   8bd9             mov ebx,ecx
 *  01140f10   8b7d 08          mov edi,dword ptr ss:[ebp+0x8]
 *  01140f13   837f 10 00       cmp dword ptr ds:[edi+0x10],0x0
 *  01140f17   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  01140f1a   8985 1cfdffff    mov dword ptr ss:[ebp-0x2e4],eax
 *  01140f20   8d47 10          lea eax,dword ptr ds:[edi+0x10]
 *  01140f23   89bd 38fdffff    mov dword ptr ss:[ebp-0x2c8],edi
 *  01140f29   8985 20fdffff    mov dword ptr ss:[ebp-0x2e0],eax
 *  01140f2f   0f84 2a050000    je .0114145f
 *  01140f35   8b8b 10010000    mov ecx,dword ptr ds:[ebx+0x110]
 *  01140f3b   b8 67666666      mov eax,0x66666667
 *  01140f40   2b8b 0c010000    sub ecx,dword ptr ds:[ebx+0x10c]
 *  01140f46   f7e9             imul ecx
 *  01140f48   8b85 20fdffff    mov eax,dword ptr ss:[ebp-0x2e0]
 *  01140f4e   8b8b 14010000    mov ecx,dword ptr ds:[ebx+0x114]
 *  01140f54   2b8b 0c010000    sub ecx,dword ptr ds:[ebx+0x10c]
 *  01140f5a   c1fa 08          sar edx,0x8
 *  01140f5d   8bf2             mov esi,edx
 *  01140f5f   c1ee 1f          shr esi,0x1f
 *  01140f62   03f2             add esi,edx
 *  01140f64   0330             add esi,dword ptr ds:[eax]
 *  01140f66   b8 67666666      mov eax,0x66666667
 *  01140f6b   f7e9             imul ecx
 *  01140f6d   c1fa 08          sar edx,0x8
 *  01140f70   8bc2             mov eax,edx
 *  01140f72   c1e8 1f          shr eax,0x1f
 *  01140f75   03c2             add eax,edx
 *  01140f77   3bc6             cmp eax,esi
 *  01140f79   73 1e            jnb short .01140f99
 *  01140f7b   81fe 66666600    cmp esi,0x666666                         ; unicode "s the data.
 *  01140f81   76 0a            jbe short .01140f8d
 *  01140f83   68 c00f4f01      push .014f0fc0                           ; ascii "vector<t> too long"
 *  01140f88   e8 b1a30e00      call .0122b33e
 *  01140f8d   56               push esi
 *  01140f8e   8d8b 0c010000    lea ecx,dword ptr ds:[ebx+0x10c]
 *  01140f94   e8 67acfcff      call .0110bc00
 *  01140f99   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  01140f9d   72 04            jb short .01140fa3
 *  01140f9f   8b37             mov esi,dword ptr ds:[edi]
 *  01140fa1   eb 02            jmp short .01140fa5
 *  01140fa3   8bf7             mov esi,edi
 *  01140fa5   89b5 34fdffff    mov dword ptr ss:[ebp-0x2cc],esi
 *  01140fab   eb 03            jmp short .01140fb0
 *  01140fad   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  01140fb0   8b57 14          mov edx,dword ptr ds:[edi+0x14]
 *  01140fb3   83fa 08          cmp edx,0x8
 *  01140fb6   72 04            jb short .01140fbc
 *  01140fb8   8b07             mov eax,dword ptr ds:[edi]
 *  01140fba   eb 02            jmp short .01140fbe
 *  01140fbc   8bc7             mov eax,edi
 *  01140fbe   8b8d 20fdffff    mov ecx,dword ptr ss:[ebp-0x2e0]
 *  01140fc4   8b09             mov ecx,dword ptr ds:[ecx]
 *  01140fc6   03c9             add ecx,ecx
 *  01140fc8   03c1             add eax,ecx
 *  01140fca   3bf0             cmp esi,eax
 *  01140fcc   0f84 8d040000    je .0114145f
 *  01140fd2   8b85 38fdffff    mov eax,dword ptr ss:[ebp-0x2c8]
 *  01140fd8   8bfe             mov edi,esi
 *  01140fda   c785 3cfdffff 00>mov dword ptr ss:[ebp-0x2c4],0x0
 *  01140fe4   c785 2cfdffff ff>mov dword ptr ss:[ebp-0x2d4],-0x1
 *  01140fee   83fa 08          cmp edx,0x8
 *  01140ff1   72 02            jb short .01140ff5
 *  01140ff3   8b00             mov eax,dword ptr ds:[eax]
 *  01140ff5   03c1             add eax,ecx
 *  01140ff7   8d95 3cfdffff    lea edx,dword ptr ss:[ebp-0x2c4]
 *  01140ffd   8d8d 2cfdffff    lea ecx,dword ptr ss:[ebp-0x2d4]
 *  01141003   51               push ecx
 *  01141004   50               push eax
 *  01141005   8d8d 34fdffff    lea ecx,dword ptr ss:[ebp-0x2cc]
 *  0114100b   e8 e033fbff      call .010f43f0
 *  01141010   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  01141016   83c4 08          add esp,0x8
 *  01141019   83fe 0a          cmp esi,0xa
 *  0114101c   75 18            jnz short .01141036
 *  0114101e   8bcb             mov ecx,ebx
 *  01141020   e8 2b060000      call .01141650
 *  01141025   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  0114102b   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  01141031  ^e9 7affffff      jmp .01140fb0
 *  01141036   83fe 07          cmp esi,0x7
 *  01141039   75 38            jnz short .01141073
 *  0114103b   33c0             xor eax,eax
 *  0114103d   c783 e0000000 00>mov dword ptr ds:[ebx+0xe0],0x0
 *  01141047   8bcb             mov ecx,ebx
 *  01141049   66:8983 e4000000 mov word ptr ds:[ebx+0xe4],ax
 *  01141050   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  01141056   e8 f5050000      call .01141650
 *  0114105b   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  01141061   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  01141067   c683 f1000000 01 mov byte ptr ds:[ebx+0xf1],0x1
 *  0114106e  ^e9 3dffffff      jmp .01140fb0
 *  01141073   8b85 3cfdffff    mov eax,dword ptr ss:[ebp-0x2c4]
 *  01141079   85c0             test eax,eax
 *  0114107b   75 36            jnz short .011410b3
 *  0114107d   85f6             test esi,esi
 *  0114107f   74 7f            je short .01141100
 *  01141081   85c0             test eax,eax
 *  01141083   75 2e            jnz short .011410b3
 *  01141085   a1 00358905      mov eax,dword ptr ds:[0x5893500]
 *  0114108a   a8 01            test al,0x1
 *  0114108c   75 0d            jnz short .0114109b
 *  0114108e   83c8 01          or eax,0x1
 *  01141091   a3 00358905      mov dword ptr ds:[0x5893500],eax
 *  01141096   e8 65160b00      call .011f2700
 *  0114109b   0fb7c6           movzx eax,si
 *  0114109e   80b8 10358905 01 cmp byte ptr ds:[eax+0x5893510],0x1
 *  011410a5   75 0c            jnz short .011410b3
 *  011410a7   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  011410aa   99               cdq
 *  011410ab   2bc2             sub eax,edx
 *  011410ad   8bc8             mov ecx,eax
 *  011410af   d1f9             sar ecx,1
 *  011410b1   eb 03            jmp short .011410b6
 *  011410b3   8b4b 68          mov ecx,dword ptr ds:[ebx+0x68]
 *  011410b6   8b43 18          mov eax,dword ptr ds:[ebx+0x18]
 *  011410b9   8b93 a0000000    mov edx,dword ptr ds:[ebx+0xa0]
 *  011410bf   03c2             add eax,edx
 *  011410c1   898d 28fdffff    mov dword ptr ss:[ebp-0x2d8],ecx
 *  011410c7   034b 58          add ecx,dword ptr ds:[ebx+0x58]
 *  011410ca   3bc8             cmp ecx,eax
 *  011410cc   7f 0f            jg short .011410dd
 *  011410ce   3bca             cmp ecx,edx
 *  011410d0   7e 3f            jle short .01141111
 *  011410d2   8bce             mov ecx,esi
 *  011410d4   e8 37faffff      call .01140b10
 *  011410d9   84c0             test al,al
 *  011410db   75 34            jnz short .01141111
 *  011410dd   8bcb             mov ecx,ebx
 *  011410df   e8 6c050000      call .01141650
 *  011410e4   83bd 3cfdffff 00 cmp dword ptr ss:[ebp-0x2c4],0x0
 *  011410eb   75 24            jnz short .01141111
 *  011410ed   83fe 20          cmp esi,0x20
 *  011410f0   74 0e            je short .01141100
 *  011410f2   81fe 00300000    cmp esi,0x3000
 *  011410f8   75 17            jnz short .01141111
 *  011410fa   8d9b 00000000    lea ebx,dword ptr ds:[ebx]
 *  01141100   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  01141106   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  0114110c  ^e9 9ffeffff      jmp .01140fb0
 *  01141111   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  01141114   3b83 a4000000    cmp eax,dword ptr ds:[ebx+0xa4]
 *  0114111a   0f8d cb020000    jge .011413eb
 *  01141120   8d8d 40fdffff    lea ecx,dword ptr ss:[ebp-0x2c0]
 *  01141126   e8 d5e3ffff      call .0113f500
 *  0114112b   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  01141132   8b4b 74          mov ecx,dword ptr ds:[ebx+0x74]
 *  01141135   8b15 98285701    mov edx,dword ptr ds:[0x1572898]
 *  0114113b   898d 30fdffff    mov dword ptr ss:[ebp-0x2d0],ecx
 *  01141141   83f9 ff          cmp ecx,-0x1
 *  01141144   75 23            jnz short .01141169
 *  01141146   80ba 58010000 00 cmp byte ptr ds:[edx+0x158],0x0
 *  0114114d   74 11            je short .01141160
 *  0114114f   8b8b d8000000    mov ecx,dword ptr ds:[ebx+0xd8]
 *  01141155   898d 30fdffff    mov dword ptr ss:[ebp-0x2d0],ecx
 *  0114115b   83f9 ff          cmp ecx,-0x1
 *  0114115e   75 09            jnz short .01141169
 *  01141160   8b43 24          mov eax,dword ptr ds:[ebx+0x24]
 *  01141163   8985 30fdffff    mov dword ptr ss:[ebp-0x2d0],eax
 *  01141169   8b43 78          mov eax,dword ptr ds:[ebx+0x78]
 *  0114116c   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  01141172   83f8 ff          cmp eax,-0x1
 *  01141175   75 23            jnz short .0114119a
 *  01141177   80ba 58010000 00 cmp byte ptr ds:[edx+0x158],0x0
 *  0114117e   74 11            je short .01141191
 *  01141180   8b83 dc000000    mov eax,dword ptr ds:[ebx+0xdc]
 *  01141186   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  0114118c   83f8 ff          cmp eax,-0x1
 *  0114118f   75 09            jnz short .0114119a
 *  01141191   8b43 28          mov eax,dword ptr ds:[ebx+0x28]
 *  01141194   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  0114119a   8b53 64          mov edx,dword ptr ds:[ebx+0x64]
 *  0114119d   0353 5c          add edx,dword ptr ds:[ebx+0x5c]
 *  011411a0   8b4b 60          mov ecx,dword ptr ds:[ebx+0x60]
 *  011411a3   034b 58          add ecx,dword ptr ds:[ebx+0x58]
 *  011411a6   83bd 3cfdffff 01 cmp dword ptr ss:[ebp-0x2c4],0x1
 *  011411ad   8bb5 30fdffff    mov esi,dword ptr ss:[ebp-0x2d0]
 *  011411b3   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  011411b6   c785 18fdffff 00>mov dword ptr ss:[ebp-0x2e8],0x0
 *  011411c0   0f44b5 18fdffff  cmove esi,dword ptr ss:[ebp-0x2e8]
 *  011411c7   80bb f2000000 00 cmp byte ptr ds:[ebx+0xf2],0x0
 *  011411ce   89b5 30fdffff    mov dword ptr ss:[ebp-0x2d0],esi
 *  011411d4   8bb5 3cfdffff    mov esi,dword ptr ss:[ebp-0x2c4]
 *  011411da   8985 48fdffff    mov dword ptr ss:[ebp-0x2b8],eax
 *  011411e0   8b85 30fdffff    mov eax,dword ptr ss:[ebp-0x2d0]
 *  011411e6   89b5 40fdffff    mov dword ptr ss:[ebp-0x2c0],esi
 *  011411ec   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  011411f2   8985 4cfdffff    mov dword ptr ss:[ebp-0x2b4],eax
 *  011411f8   8b85 24fdffff    mov eax,dword ptr ss:[ebp-0x2dc]
 *  011411fe   89b5 44fdffff    mov dword ptr ss:[ebp-0x2bc],esi
 *  01141204   8985 50fdffff    mov dword ptr ss:[ebp-0x2b0],eax
 *  0114120a   898d 54fdffff    mov dword ptr ss:[ebp-0x2ac],ecx
 *  01141210   8995 58fdffff    mov dword ptr ss:[ebp-0x2a8],edx
 *  01141216   74 19            je short .01141231
 *  01141218   8b43 58          mov eax,dword ptr ds:[ebx+0x58]
 *  0114121b   8983 f4000000    mov dword ptr ds:[ebx+0xf4],eax
 *  01141221   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  01141224   8983 f8000000    mov dword ptr ds:[ebx+0xf8],eax
 *  0114122a   c683 f2000000 00 mov byte ptr ds:[ebx+0xf2],0x0
 *  01141231   8b43 6c          mov eax,dword ptr ds:[ebx+0x6c]
 *  01141234   0385 28fdffff    add eax,dword ptr ss:[ebp-0x2d8]
 *  0114123a   0143 58          add dword ptr ds:[ebx+0x58],eax
 *  0114123d   8b85 3cfdffff    mov eax,dword ptr ss:[ebp-0x2c4]
 *  01141243   8b4b 58          mov ecx,dword ptr ds:[ebx+0x58]
 *  01141246   85c0             test eax,eax
 *  01141248   75 51            jnz short .0114129b
 *  0114124a   81fe 0c300000    cmp esi,0x300c  ; jichi: hook here, utf16 character is in esi
 *  01141250   74 10            je short .01141262
 *  01141252   81fe 0e300000    cmp esi,0x300e
 *  01141258   74 08            je short .01141262
 *  0114125a   81fe 08ff0000    cmp esi,0xff08
 *  01141260   75 39            jnz short .0114129b
 *  01141262   80bb f1000000 00 cmp byte ptr ds:[ebx+0xf1],0x0
 *  01141269   74 19            je short .01141284
 *  0114126b   898b e0000000    mov dword ptr ds:[ebx+0xe0],ecx
 *  01141271   66:89b3 e4000000 mov word ptr ds:[ebx+0xe4],si
 *  01141278   c783 e8000000 01>mov dword ptr ds:[ebx+0xe8],0x1
 *  01141282   eb 17            jmp short .0114129b
 *  01141284   0fb783 e4000000  movzx eax,word ptr ds:[ebx+0xe4]
 *  0114128b   3bf0             cmp esi,eax
 *  0114128d   8b85 3cfdffff    mov eax,dword ptr ss:[ebp-0x2c4]
 *  01141293   75 06            jnz short .0114129b
 *  01141295   ff83 e8000000    inc dword ptr ds:[ebx+0xe8]
 *  0114129b   8b93 e8000000    mov edx,dword ptr ds:[ebx+0xe8]
 *  011412a1   85d2             test edx,edx
 *  011412a3   7e 78            jle short .0114131d
 *  011412a5   85c0             test eax,eax
 *  011412a7   75 52            jnz short .011412fb
 *  011412a9   0fb78b e4000000  movzx ecx,word ptr ds:[ebx+0xe4]
 *  011412b0   b8 0c300000      mov eax,0x300c
 *  011412b5   66:3bc8          cmp cx,ax
 *  011412b8   75 11            jnz short .011412cb
 *  011412ba   81fe 0d300000    cmp esi,0x300d
 *  011412c0   75 09            jnz short .011412cb
 *  011412c2   8d42 ff          lea eax,dword ptr ds:[edx-0x1]
 *  011412c5   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  011412cb   b8 0e300000      mov eax,0x300e
 *  011412d0   66:3bc8          cmp cx,ax
 *  011412d3   75 0e            jnz short .011412e3
 *  011412d5   81fe 0f300000    cmp esi,0x300f
 *  011412db   75 06            jnz short .011412e3
 *  011412dd   ff8b e8000000    dec dword ptr ds:[ebx+0xe8]
 *  011412e3   b8 08ff0000      mov eax,0xff08
 *  011412e8   66:3bc8          cmp cx,ax
 *  011412eb   75 0e            jnz short .011412fb
 *  011412ed   81fe 09ff0000    cmp esi,0xff09
 *  011412f3   75 06            jnz short .011412fb
 *  011412f5   ff8b e8000000    dec dword ptr ds:[ebx+0xe8]
 *  011412fb   83bb e8000000 00 cmp dword ptr ds:[ebx+0xe8],0x0
 *  01141302   75 19            jnz short .0114131d
 *  01141304   33c0             xor eax,eax
 *  01141306   c783 e0000000 00>mov dword ptr ds:[ebx+0xe0],0x0
 *  01141310   66:8983 e4000000 mov word ptr ds:[ebx+0xe4],ax
 *  01141317   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  0114131d   8d85 40fdffff    lea eax,dword ptr ss:[ebp-0x2c0]
 *  01141323   50               push eax
 *  01141324   8d8b 0c010000    lea ecx,dword ptr ds:[ebx+0x10c]
 *  0114132a   e8 31a6fcff      call .0110b960
 *  0114132f   83bd 3cfdffff 00 cmp dword ptr ss:[ebp-0x2c4],0x0
 *  01141336   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  0114133c   75 13            jnz short .01141351
 *  0114133e   ffb5 2cfdffff    push dword ptr ss:[ebp-0x2d4]
 *  01141344   8d8b a8000000    lea ecx,dword ptr ds:[ebx+0xa8]
 *  0114134a   e8 010a0000      call .01141d50
 *  0114134f   eb 64            jmp short .011413b5
 *  01141351   33c0             xor eax,eax
 *  01141353   c745 ec 07000000 mov dword ptr ss:[ebp-0x14],0x7
 *  0114135a   c745 e8 00000000 mov dword ptr ss:[ebp-0x18],0x0
 *  01141361   66:8945 d8       mov word ptr ss:[ebp-0x28],ax
 *  01141365   3bfe             cmp edi,esi
 *  01141367   74 10            je short .01141379
 *  01141369   8bc6             mov eax,esi
 *  0114136b   8d4d d8          lea ecx,dword ptr ss:[ebp-0x28]
 *  0114136e   2bc7             sub eax,edi
 *  01141370   d1f8             sar eax,1
 *  01141372   50               push eax
 *  01141373   57               push edi
 *  01141374   e8 b7daf2ff      call .0106ee30
 *  01141379   6a ff            push -0x1
 *  0114137b   6a 00            push 0x0
 *  0114137d   8d45 d8          lea eax,dword ptr ss:[ebp-0x28]
 *  01141380   c645 fc 02       mov byte ptr ss:[ebp-0x4],0x2
 *  01141384   50               push eax
 *  01141385   8d8b a8000000    lea ecx,dword ptr ds:[ebx+0xa8]
 *  0114138b   e8 205cf3ff      call .01076fb0
 *  01141390   837d ec 08       cmp dword ptr ss:[ebp-0x14],0x8
 *  01141394   72 0b            jb short .011413a1
 *  01141396   ff75 d8          push dword ptr ss:[ebp-0x28]
 *  01141399   e8 fccb0e00      call .0122df9a
 *  0114139e   83c4 04          add esp,0x4
 *  011413a1   33c0             xor eax,eax
 *  011413a3   c745 ec 07000000 mov dword ptr ss:[ebp-0x14],0x7
 *  011413aa   c745 e8 00000000 mov dword ptr ss:[ebp-0x18],0x0
 *  011413b1   66:8945 d8       mov word ptr ss:[ebp-0x28],ax
 *  011413b5   c683 f1000000 00 mov byte ptr ds:[ebx+0xf1],0x0
 *  011413bc   8d8d 90feffff    lea ecx,dword ptr ss:[ebp-0x170]
 *  011413c2   c745 fc 03000000 mov dword ptr ss:[ebp-0x4],0x3
 *  011413c9   e8 42bb0800      call .011ccf10
 *  011413ce   8d8d 60fdffff    lea ecx,dword ptr ss:[ebp-0x2a0]
 *  011413d4   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  011413db   e8 30bb0800      call .011ccf10
 *  011413e0   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  011413e6  ^e9 c5fbffff      jmp .01140fb0
 *  011413eb   8b9d 1cfdffff    mov ebx,dword ptr ss:[ebp-0x2e4]
 *  011413f1   85db             test ebx,ebx
 *  011413f3   74 6a            je short .0114145f
 *  011413f5   8b8d 38fdffff    mov ecx,dword ptr ss:[ebp-0x2c8]
 *  011413fb   8379 14 08       cmp dword ptr ds:[ecx+0x14],0x8
 *  011413ff   72 02            jb short .01141403
 *  01141401   8b09             mov ecx,dword ptr ds:[ecx]
 *  01141403   8b85 20fdffff    mov eax,dword ptr ss:[ebp-0x2e0]
 *  01141409   c745 d4 07000000 mov dword ptr ss:[ebp-0x2c],0x7
 *  01141410   c745 d0 00000000 mov dword ptr ss:[ebp-0x30],0x0
 *  01141417   8b00             mov eax,dword ptr ds:[eax]
 *  01141419   8d0441           lea eax,dword ptr ds:[ecx+eax*2]
 *  0114141c   33c9             xor ecx,ecx
 *  0114141e   66:894d c0       mov word ptr ss:[ebp-0x40],cx
 *  01141422   3bf8             cmp edi,eax
 *  01141424   74 0e            je short .01141434
 *  01141426   2bc7             sub eax,edi
 *  01141428   8d4d c0          lea ecx,dword ptr ss:[ebp-0x40]
 *  0114142b   d1f8             sar eax,1
 *  0114142d   50               push eax
 *  0114142e   57               push edi
 *  0114142f   e8 fcd9f2ff      call .0106ee30
 *  01141434   8d45 c0          lea eax,dword ptr ss:[ebp-0x40]
 *  01141437   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  0114143e   3bd8             cmp ebx,eax
 *  01141440   74 0c            je short .0114144e
 *  01141442   6a ff            push -0x1
 *  01141444   6a 00            push 0x0
 *  01141446   50               push eax
 *  01141447   8bcb             mov ecx,ebx
 *  01141449   e8 c2def2ff      call .0106f310
 *  0114144e   837d d4 08       cmp dword ptr ss:[ebp-0x2c],0x8
 *  01141452   72 0b            jb short .0114145f
 *  01141454   ff75 c0          push dword ptr ss:[ebp-0x40]
 *  01141457   e8 3ecb0e00      call .0122df9a
 *  0114145c   83c4 04          add esp,0x4
 *  0114145f   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  01141462   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  01141469   59               pop ecx
 *  0114146a   5f               pop edi
 *  0114146b   5e               pop esi
 *  0114146c   5b               pop ebx
 *  0114146d   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  01141470   33cd             xor ecx,ebp
 *  01141472   e8 14cb0e00      call .0122df8b
 *  01141477   8be5             mov esp,ebp
 *  01141479   5d               pop ebp
 *  0114147a   c2 0800          retn 0x8
 *  0114147d   cc               int3
 *  0114147e   cc               int3
 */
bool InsertSiglus2Hook()
{
  //const BYTE bytes[] = { // size = 14
  //  0x01,0x53, 0x58,                // 0153 58          add dword ptr ds:[ebx+58],edx
  //  0x8b,0x95, 0x34,0xfd,0xff,0xff, // 8b95 34fdffff    mov edx,dword ptr ss:[ebp-2cc]
  //  0x8b,0x43, 0x58,                // 8b43 58          mov eax,dword ptr ds:[ebx+58]
  //  0x3b,0xd7                       // 3bd7             cmp edx,edi ; hook here
  //};
  //enum { cur_ins_size = 2 };
  //enum { hook_offset = sizeof(bytes) - cur_ins_size }; // = 14 - 2  = 12, current inst is the last one

  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr;
  { // type 1
    const BYTE bytes[] = {
      0x3b,0xd7,  // cmp edx,edi ; hook here
      0x75,0x4b   // jnz short
    };
    //enum { hook_offset = 0 };
    addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
    if (addr)
      ConsoleOutput("vnreng:Siglus2: type 1 pattern found");
  }
  if (!addr) {
    const BYTE bytes[] = {
      0x81,0xfe, 0x0c,0x30,0x00,0x00 // 0114124a   81fe 0c300000    cmp esi,0x300c  ; jichi: hook here
    };
    //enum { hook_offset = 0 };
    addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
    if (addr)
      ConsoleOutput("vnreng:Siglus2: type 2 pattern found");
  }

  if (!addr) {
    ConsoleOutput("vnreng:Siglus2: both type1 and type2 patterns not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = pusha_esi_off - 4; // -0x20
  hp.type = USING_UNICODE|FIXING_SPLIT; // jichi 6/1/2014: fixing the split value
  hp.length_offset = 1;

  ConsoleOutput("vnreng: INSERT Siglus2");
  NewHook(hp, L"SiglusEngine2");
  //ConsoleOutput("SiglusEngine2");
  return true;
}

static void SpecialHookSiglus1(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  __asm
  {
    mov edx,esp_base
    mov ecx,[edx-0xc]
    mov eax,[ecx+0x14]
    add ecx,4
    cmp eax,0x8
    cmovnb ecx,[ecx]
    mov edx,len
    add eax,eax
    mov [edx],eax
    mov edx,data
    mov [edx],ecx
  }
}

// jichi: 8/17/2013: Change return type to bool
bool InsertSiglus1Hook()
{
  const BYTE bytes[] = {0x33,0xc0,0x8b,0xf9,0x89,0x7c,0x24};
  ULONG range = max(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) { // jichi 8/17/2013: Add "== 0" check to prevent breaking new games
    //ConsoleOutput("Unknown SiglusEngine");
    ConsoleOutput("vnreng:Siglus: pattern not found");
    return false;
  }

  DWORD limit = addr - 0x100;
  while (addr > limit) {
    if (*(WORD*)addr == 0xff6a) {
      HookParam hp = {};
      hp.addr = addr;
      hp.extern_fun = (HookParam::extern_fun_t)SpecialHookSiglus1;
      hp.type = USING_UNICODE;
      ConsoleOutput("vnreng: INSERT Siglus");
      NewHook(hp, L"SiglusEngine");
      //RegisterEngineType(ENGINE_SIGLUS);
      return true;
    }
    addr--;
  }
  ConsoleOutput("vnreng:Siglus: failed");
  return false;
}

} // unnamed namespace

// jichi 8/17/2013: Insert old first. As the pattern could also be found in the old engine.
bool InsertSiglusHook()
{
  if (InsertSiglus1Hook())
    return true;
  bool ok = InsertSiglus2Hook();
  ok = InsertSiglus3Hook() || ok;
  return ok;
}

/********************************************************************************************
MAJIRO hook:
  Game folder contains both data.arc and scenario.arc. arc files is
  quite common seen so we need 2 files to confirm it's MAJIRO engine.

  Font caching issue. Find call to TextOutA and the function entry.

  The original Majiro hook will catch furiga mixed with the text.
  To split them out we need to find a parameter. Seems there's no
  simple way to handle this case.
  At the function entry, EAX seems to point to a structure to describe
  current drawing context. +28 seems to be font size. +48 is negative
  if furigana. I don't know exact meaning of this structure,
  just do memory comparisons and get the value working for current release.

********************************************************************************************/
// jichi 11/28/2014: Disable original Majiro special hook that does not work for new Majiro games, such as: 流され妻
// In the new Majiro engine, arg1 could be zero
#if 0
static void SpecialHookMajiro(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  // jichi 5/12/2014
  // See: http://stackoverflow.com/questions/14210614/bind-function-parameter-to-specific-register
  // x86-64, the first 6 (integral) parameters are passed in the registers %rdi, %rsi, %rdx, %rcx, %r8, and %r9.
  __asm
  {
    mov edx,esp_base
    mov edi,[edx+0xc] ; jichi 5/11/2014: the third function parameter is LPCSTR text
    mov eax,data
    mov [eax],edi
    or ecx,0xffffffff
    xor eax,eax
    repne scasb
    not ecx
    dec ecx
    mov eax,len
    mov [eax],ecx
    mov eax,[edx+4]    ; jichi 5/11/2014: the first function parameter is LPCSTR font name (MS Gothic)
    mov edx,[eax+0x28] ; 0x28 and 0x48 are in the caller of this fuction hook
    mov eax,[eax+0x48] ; *split = ([eax+0x28] & 0xff) | (([eax+0x48] >> 1) & 0xffff00)
    sar eax,0x1f
    mov dh,al
    mov ecx,split
    mov [ecx],edx
  }
}
#endif // 0

/** jichi 12/28/2014: new Majiro hook pattern
 *
 *  Different function starts:
 *
 *  Old Majiro:
 *  enum { sub_esp = 0xec81 }; // caller pattern: sub esp = 0x81,0xec byte
 *
 *  New Majiro since [141128] [アトリエさくら] 流され妻、綾乃の“ネトラレ”報告 体験版
 *  003e9230   55               push ebp
 *  003e9231   8bec             mov ebp,esp
 *  003e9233   83ec 64          sub esp,0x64
 *
 *  Also, function addresses are fixed in old majiro, but floating in new majiro.
 *  In the old Majiro game, caller's address could be used as split.
 *  In the new Majiro game, the hooked function is invoked by the same caller.
 *
 *  Use a split instead.
 *  Sample stack values are as follows.
 *  - Old majiro: arg3 is text, arg1 is font name
 *  - New majiro: arg3 is text, arg4 is font name
 *
 *  Name:
 *  0038f164   003e8163  return to .003e8163 from .003e9230
 *  0038f168   00000000
 *  0038f16c   00000000
 *  0038f170   08b04dbc ; jichi: arg3, text
 *  0038f174   006709f0 ; jichi: arg4, font name
 *  0038f178   006dace8
 *  0038f17c   00000000
 *  0038f180   00000013
 *  0038f184   006fcba8
 *  0038f188   00000078 ; jichi: 0x24, alternative split
 *  0038f18c   00000078
 *  0038f190   00000018
 *  0038f194   00000002
 *  0038f198   08b04dbc
 *  0038f19c   006709f0
 *  0038f1a0   00000000
 *  0038f1a4   00000000
 *  0038f1a8   00000078
 *  0038f1ac   00000018
 *  0038f1b0   08aa0130
 *  0038f1b4   01b6b6c0
 *  0038f1b8   beff26e4
 *  0038f1bc   0038f1fc
 *  0038f1c0   004154af  return to .004154af from .00415400 ; jichi: 0x52, could be used as split
 *  0038f1c4   0000000e
 *  0038f1c8   000001ae
 *  0038f1cc   00000158
 *  0038f1d0   00000023
 *  0038f1d4   beff2680
 *  0038f1d8   0038f208
 *  0038f1dc   003ecfda  return to .003ecfda from .00415400
 *
 *  Scenario:
 *  0038e57c   003e8163  return to .003e8163 from .003e9230
 *  0038e580   00000000
 *  0038e584   00000000
 *  0038e588   0038ee4c  ; jichi: arg3, text
 *  0038e58c   004d5400  .004d5400 ; jichi: arg4, font name
 *  0038e590   006dace8
 *  0038e594   0038ee6d
 *  0038e598   004d7549  .004d7549
 *  0038e59c   00000000
 *  0038e5a0   00000180 ; jichi: 0x24, alternative hook
 *  0038e5a4   00000180
 *  0038e5a8   00000018
 *  0038e5ac   00000002
 *  0038e5b0   0038ee4c
 *  0038e5b4   004d5400  .004d5400
 *  0038e5b8   00000000
 *  0038e5bc   00000000
 *  0038e5c0   00000180
 *  0038e5c4   00000018
 *  0038e5c8   006a0180
 *  0038e5cc   0038e5f8
 *  0038e5d0   0041fc87  return to .0041fc87 from .0041fc99
 *  0038e5d4   0038e5f8
 *  0038e5d8   00418165  return to .00418165 from .0041fc81 ; jichi: used as split
 *  0038e5dc   004d7549  .004d7549
 *  0038e5e0   0038ee6d
 *  0038e5e4   0038e608
 *  0038e5e8   00419555  return to .00419555 from .0041814e
 *  0038e5ec   00000000
 *  0038e5f0   004d7549  .004d7549
 *  0038e5f4   0038ee6d
 *
 *  12/4/2014: Add split for furigana.
 *  Sample game: [141128] [チュアブルソフト] 残念な俺達の青春事情
 *  Following are memory values after arg4 (font name)
 *
 *  Surface: 傍
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... .... ; jichi: first byte as split in parenthesis
 *  00EC5440  00(00 00 00)60 F7 3F 00 F0 D8 FF FF 00 00 00 00  ....`・.   ....  ; jichi: first word without first byte as split
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
 *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  Furigana: そば
 *  00EC5400  82 6C 82 72 20 83 53 83 56 83 62 83 4E 00 4E 00  ＭＳ ゴシック.N.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 0E 00 00 00 06 00 00 00   ....... ... ...
 *  00EC5430 (16)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00   ....... ....
 *  00EC5440  00(00 00 00)60 F7 3F 00 F0 D8 FF FF 00 00 00 00  ....`・.   ....
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 00 00 00 00 00 00 00 00 32 01 00 00  ............2 ..
 *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  Furigana: そば
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 0E 00 00 00 06 00 00 00   ....... ... ...
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... ....
 *  00EC5440  00(00 00 00)60 F7 3F 00 2B 01 00 00 06 00 00 00  ....`・.+ .. ...
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 00 00 00 00 00 00 00 00 32 01 00 00  ............2 ..
 *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  ---- need to split the above and below case
 *
 *  Text: 傍
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... .... ; jichi: first byte as split in parenthesis
 *  00EC5440  FF(FF FF FF)60 F7 3F 00 32 01 00 00 14 00 00 00  `・.2 .. ... ; jichi: first word without first byte as split
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
 *  00EC5470  14 00 00 00 00 00 00 00 82 6C 82 72 20 82 6F 83   .......ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  Text: らには、一人の少女。
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... ....
 *  00EC5440  FF(FF FF FF)60 F7 3F 00 4D 01 00 00 14 00 00 00  `・.M .. ...
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
 *  00EC5470  14 00 00 00 00 00 00 00 82 6C 82 72 20 82 6F 83   .......ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 */

namespace { // unnamed

// These values are the same as the assembly logic of ITH:
//     ([eax+0x28] & 0xff) | (([eax+0x48] >> 1) & 0xffffff00)
// 0x28 = 10 * 4, 0x48 = 18 / 4
inline DWORD MajiroOldFontSplit(const DWORD *arg) // arg is supposed to be a string, though
{ return (arg[10] & 0xff) | ((arg[18] >> 1) & 0xffffff00); }

// Remove lower bytes use 0xffffff00, which are different for furigana
inline DWORD MajiroNewFontSplit(const DWORD *arg) // arg is supposed to be a string, though
{ return (arg[12] & 0xff) | (arg[16] & 0xffffff00); }

void SpecialHookMajiro(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD arg3 = argof(3, esp_base); // text
  *data = arg3;
  *len = ::strlen((LPCSTR)arg3);
  // IsBadReadPtr is not needed for old Majiro game.
  // I am not sure if it is needed by new Majiro game.
  if (hp->userValue) { // new majiro
    if (DWORD arg4 = argof(4, esp_base)) // old majiro
      *split = MajiroNewFontSplit((LPDWORD)arg4);
    else
      *split = *(DWORD *)(esp_base + 0x5c); // = 4 * 23, caller's caller
  } else if (DWORD arg1 = argof(1, esp_base)) // old majiro
    *split = MajiroOldFontSplit((LPDWORD)arg1);
}
} // unnamed namespace
bool InsertMajiroHook()
{
  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:Majiro: failed to get memory range");
    return false;
  }
  // jichi 4/19/2014: There must be a function in Majiro game which contains 6 TextOutA.
  // That function draws all texts.
  //
  // jichi 11/28/2014: Add new function signature
  const DWORD funcs[] = { // caller patterns
    0xec81,     // sub esp = 0x81,0xec byte old majiro
    0x83ec8b55  // mov ebp,esp, sub esp,*  new majiro
  };
  enum { FunctionCount = sizeof(funcs) / sizeof(*funcs) };
  ULONG addr = MemDbg::findMultiCallerAddress((ULONG)::TextOutA, funcs, FunctionCount, startAddress, stopAddress);
  //ULONG addr = MemDbg::findCallerAddress((ULONG)::TextOutA, 0x83ec8b55, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:Majiro: failed");
    return false;
  }

  bool newMajiro = 0x55 == *(BYTE *)addr;

  HookParam hp = {};
  //hp.off=0xc;
  //hp.split=4;
  //hp.split_ind=0x28;
  //hp.type|=USING_STRING|USING_SPLIT|SPLIT_INDIRECT;
  hp.addr = addr;
  hp.extern_fun = (HookParam::extern_fun_t)SpecialHookMajiro;
  hp.userValue = newMajiro;
  if (newMajiro) {
    hp.type = NO_CONTEXT; // do not use return address for new majiro
    ConsoleOutput("vnreng: INSERT Majiro2");
    NewHook(hp, L"Majiro2");
  } else {
    ConsoleOutput("vnreng: INSERT Majiro");
    NewHook(hp, L"Majiro");
  }
  //RegisterEngineType(ENGINE_MAJIRO);
  return true;
}

/********************************************************************************************
CMVS hook:
  Process name is cmvs.exe or cnvs.exe or cmvs*.exe. Used by PurpleSoftware games.

  Font caching issue. Find call to GetGlyphOutlineA and the function entry.
********************************************************************************************/

namespace { // unnamed

// jichi 3/6/2014: This is the original CMVS hook in ITH
// It does not work for パープルソフトウェア games after しあわせ家族部 (2012)
bool InsertCMVS1Hook()
{
  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:CMVS1: failed to get memory range");
    return false;
  }
  // jichi 4/19/2014: There must be a function in Majiro game which contains 6 TextOutA.
  // That function draws all texts.
  enum { sub_esp = 0xec83 }; // caller pattern: sub esp = 0x83,0xec
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:CMVS1: failed");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 0x8;
  hp.split = -0x18;
  hp.type = BIG_ENDIAN|USING_SPLIT;
  hp.length_offset = 1 ;

  ConsoleOutput("vnreng: INSERT CMVS1");
  NewHook(hp, L"CMVS");
  //RegisterEngineType(ENGINE_CMVS);
  return true;
}

/**
 *  CMSV
 *  Sample games:
 *  ハピメア: /HAC@48FF3:cmvs32.exe
 *  ハピメアFD: /HB-1C*0@44EE95
 *
 *  Optional: ハピメアFD: /HB-1C*0@44EE95
 *  This hook has issue that the text will be split to a large amount of threads
 *  - length_offset: 1
 *  - off: 4294967264 = 0xffffffe0 = -0x20
 *  - type: 8
 *
 *  ハピメア: /HAC@48FF3:cmvs32.exe
 *  base: 0x400000
 *  - length_offset: 1
 *  - off: 12 = 0xc
 *  - type: 68 = 0x44
 *
 *  00448fee     cc             int3
 *  00448fef     cc             int3
 *  00448ff0  /$ 55             push ebp
 *  00448ff1  |. 8bec           mov ebp,esp
 *  00448ff3  |. 83ec 68        sub esp,0x68 ; jichi: hook here, it is actually  tagTEXTMETRICA
 *  00448ff6  |. 8b01           mov eax,dword ptr ds:[ecx]
 *  00448ff8  |. 56             push esi
 *  00448ff9  |. 33f6           xor esi,esi
 *  00448ffb  |. 33d2           xor edx,edx
 *  00448ffd  |. 57             push edi
 *  00448ffe  |. 894d fc        mov dword ptr ss:[ebp-0x4],ecx
 *  00449001  |. 3bc6           cmp eax,esi
 *  00449003  |. 74 37          je short cmvs32.0044903c
 *  00449005  |> 66:8b78 08     /mov di,word ptr ds:[eax+0x8]
 *  00449009  |. 66:3b7d 0c     |cmp di,word ptr ss:[ebp+0xc]
 *  0044900d  |. 75 0a          |jnz short cmvs32.00449019
 *  0044900f  |. 66:8b7d 10     |mov di,word ptr ss:[ebp+0x10]
 *  00449013  |. 66:3978 0a     |cmp word ptr ds:[eax+0xa],di
 *  00449017  |. 74 0a          |je short cmvs32.00449023
 *  00449019  |> 8bd0           |mov edx,eax
 *  0044901b  |. 8b00           |mov eax,dword ptr ds:[eax]
 *  0044901d  |. 3bc6           |cmp eax,esi
 *  0044901f  |.^75 e4          \jnz short cmvs32.00449005
 *  00449021  |. eb 19          jmp short cmvs32.0044903c
 *  00449023  |> 3bd6           cmp edx,esi
 *  00449025  |. 74 0a          je short cmvs32.00449031
 *  00449027  |. 8b38           mov edi,dword ptr ds:[eax]
 *  00449029  |. 893a           mov dword ptr ds:[edx],edi
 *  0044902b  |. 8b11           mov edx,dword ptr ds:[ecx]
 *  0044902d  |. 8910           mov dword ptr ds:[eax],edx
 *  0044902f  |. 8901           mov dword ptr ds:[ecx],eax
 *  00449031  |> 8b40 04        mov eax,dword ptr ds:[eax+0x4]
 *  00449034  |. 3bc6           cmp eax,esi
 *  00449036  |. 0f85 64010000  jnz cmvs32.004491a0
 *  0044903c  |> 8b55 08        mov edx,dword ptr ss:[ebp+0x8]
 *  0044903f  |. 53             push ebx
 *  00449040  |. 0fb75d 0c      movzx ebx,word ptr ss:[ebp+0xc]
 *  00449044  |. b8 00000100    mov eax,0x10000
 *  00449049  |. 8945 e4        mov dword ptr ss:[ebp-0x1c],eax
 *  0044904c  |. 8945 f0        mov dword ptr ss:[ebp-0x10],eax
 *  0044904f  |. 8d45 e4        lea eax,dword ptr ss:[ebp-0x1c]
 *  00449052  |. 50             push eax                                 ; /pMat2
 *  00449053  |. 56             push esi                                 ; |Buffer
 *  00449054  |. 56             push esi                                 ; |BufSize
 *  00449055  |. 8d4d d0        lea ecx,dword ptr ss:[ebp-0x30]          ; |
 *  00449058  |. 51             push ecx                                 ; |pMetrics
 *  00449059  |. 6a 05          push 0x5                                 ; |Format = GGO_GRAY4_BITMAP
 *  0044905b  |. 53             push ebx                                 ; |Char
 *  0044905c  |. 52             push edx                                 ; |hDC
 *  0044905d  |. 8975 e8        mov dword ptr ss:[ebp-0x18],esi          ; |
 *  00449060  |. 8975 ec        mov dword ptr ss:[ebp-0x14],esi          ; |
 *  00449063  |. ff15 5cf05300  call dword ptr ds:[<&gdi32.getglyphoutli>; \GetGlyphOutlineA
 *  00449069  |. 8b75 10        mov esi,dword ptr ss:[ebp+0x10]
 *  0044906c  |. 0faff6         imul esi,esi
 *  0044906f  |. 8bf8           mov edi,eax
 *  00449071  |. 8d04bd 0000000>lea eax,dword ptr ds:[edi*4]
 *  00449078  |. 3bc6           cmp eax,esi
 *  0044907a  |. 76 02          jbe short cmvs32.0044907e
 *  0044907c  |. 8bf0           mov esi,eax
 *  0044907e  |> 56             push esi                                 ; /Size
 *  0044907f  |. 6a 00          push 0x0                                 ; |Flags = LMEM_FIXED
 *  00449081  |. ff15 34f25300  call dword ptr ds:[<&kernel32.localalloc>; \LocalAlloc
 */
bool InsertCMVS2Hook()
{
  // There are multiple functions satisfy the pattern below.
  // Hook to any one of them is OK.
  const BYTE bytes[] = {  // function begin
    0x55,               // 00448ff0  /$ 55             push ebp
    0x8b,0xec,          // 00448ff1  |. 8bec           mov ebp,esp
    0x83,0xec, 0x68,    // 00448ff3  |. 83ec 68        sub esp,0x68 ; jichi: hook here
    0x8b,0x01,          // 00448ff6  |. 8b01           mov eax,dword ptr ds:[ecx]
    0x56,               // 00448ff8  |. 56             push esi
    0x33,0xf6,          // 00448ff9  |. 33f6           xor esi,esi
    0x33,0xd2,          // 00448ffb  |. 33d2           xor edx,edx
    0x57,               // 00448ffd  |. 57             push edi
    0x89,0x4d, 0xfc,    // 00448ffe  |. 894d fc        mov dword ptr ss:[ebp-0x4],ecx
    0x3b,0xc6,          // 00449001  |. 3bc6           cmp eax,esi
    0x74, 0x37          // 00449003  |. 74 37          je short cmvs32.0044903c
  };
  enum { hook_offset = 3 }; // offset from the beginning of the function
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) {
    ConsoleOutput("vnreng:CMVS2: pattern not found");
    return false;
  }

  //reladdr = 0x48ff0;
  //reladdr = 0x48ff3;
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = 0xc;
  hp.type = BIG_ENDIAN;
  hp.length_offset = 1 ;

  ConsoleOutput("vnreng: INSERT CMVS2");
  NewHook(hp, L"CMVS2");
  return true;
}

} // unnamed namespace

// jichi 3/7/2014: Insert the old hook first since GetGlyphOutlineA can NOT be found in new games
bool InsertCMVSHook()
{
  // Both CMVS1 and CMVS2 exists in new games.
  // Insert the CMVS2 first. Since CMVS1 could break CMVS2
  // And the CMVS1 games do not have CMVS2 patterns.
  return InsertCMVS2Hook() || InsertCMVS1Hook();
}

namespace { // unnamed rUGP

/********************************************************************************************
rUGP hook:
  Process name is rugp.exe. Used by AGE/GIGA games.

  Font caching issue. Find call to GetGlyphOutlineA and keep stepping out functions.
  After several tries we comes to address in rvmm.dll and everything is catched.
  We see CALL [E*X+0x*] while EBP contains the character data.
  It's not as simple to reverse in rugp at run time as like reallive since rugp dosen't set
  up stack frame. In other words EBP is used for other purpose. We need to find alternative
  approaches.
  The way to the entry of that function gives us clue to find it. There is one CMP EBP,0x8140
  instruction in this function and that's enough! 0x8140 is the start of SHIFT-JIS
  characters. It's determining if ebp contains a SHIFT-JIS character. This function is not likely
  to be used in other ways. We simply search for this instruction and place hook around.
********************************************************************************************/
void SpecialHookRUGP1(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  DWORD *stack = (DWORD *)esp_base;
  DWORD i,val;
  for (i = 0; i < 4; i++) {
    val = *stack++;
    if ((val>>16) == 0) break;

  }
  if (i < 4) {
    hp->off = i << 2;
    *data = val;
    *len = 2;
    hp->extern_fun = 0;
    hp->type &= ~EXTERN_HOOK;
  }
  else
    *len = 0;
}

// jichi 10/1/2013: Change return type to bool
bool InsertRUGP1Hook()
{
  DWORD low, high;
  if (!IthCheckFile(L"rvmm.dll") || !SafeFillRange(L"rvmm.dll", &low, &high)) {
    ConsoleOutput("vnreng:rUGP: rvmm.dll does not exist");
    return false;
  }
  //WCHAR str[0x40];
  LPVOID ch = (LPVOID)0x8140;
  enum { range = 0x20000 };
  DWORD t = SearchPattern(low + range, high - low - range, &ch, 4) + range;
  BYTE *s = (BYTE *)(low + t);
  //if (t) {
  if (t != range) { // jichi 10/1/2013: Changed to compare with 0x20000
    if (*(s - 2) != 0x81)
      return false;
    if (DWORD i = SafeFindEntryAligned((DWORD)s, 0x200)) {
      HookParam hp = {};
      hp.addr = i;
      //hp.off= -8;
      hp.length_offset = 1;
      hp.extern_fun = SpecialHookRUGP1;
      hp.type |= BIG_ENDIAN|EXTERN_HOOK;
      ConsoleOutput("vnreng: INSERT rUGP#1");
      NewHook(hp, L"rUGP");
      return true;
    }
  } else {
    t = SearchPattern(low, range, &s, 4);
    if (!t) {
      ConsoleOutput("vnreng:rUGP: pattern not found");
      //ConsoleOutput("Can't find characteristic instruction.");
      return false;
    }

    s = (BYTE *)(low + t);
    for (int i = 0; i < 0x200; i++, s--)
      if (s[0] == 0x90
          && *(DWORD *)(s - 3) == 0x90909090) {
        t = low+ t - i + 1;
        //swprintf(str, L"HookAddr 0x%.8x", t);
        //ConsoleOutput(str);
        HookParam hp = {};
        hp.addr = t;
        hp.off = 0x4;
        hp.length_offset = 1;
        hp.type |= BIG_ENDIAN;
        ConsoleOutput("vnreng:INSERT rUGP#2");
        NewHook(hp, L"rUGP");
        //RegisterEngineType(ENGINE_RUGP);
        return true;
      }
  }
  ConsoleOutput("vnreng:rUGP: failed");
  return false;
//rt:
  //ConsoleOutput("Unknown rUGP engine.");
}

/** rUGP2 10/11/2014 jichi
 *
 *  Sample game: マブラヴ オルタネイティヴ トータル・イクリプス
 *  The existing rUGP#1/#2 cannot be identified.
 *  H-codes:
 *  - /HAN-4@1E51D:VM60.DLL
 *    - addr: 124189 = 0x1e51d
 *    - length_offset: 1
 *    - module: 3037492083 = 0xb50c7373
 *    - off: 4294967288 = 0xfffffff8 = -8
 *    - type: 1092 = 0x444
 *  - /HAN-4@1001E51D ( alternative)
 *    - addr: 268559645 = 0x1001e51d
 *    - length_offset: 1
 *    - type: 1028 = 0x404
 *
 *  This function is very long.
 *  1001e4b2  ^e9 c0fcffff      jmp _18.1001e177
 *  1001e4b7   8b45 14          mov eax,dword ptr ss:[ebp+0x14]
 *  1001e4ba   c745 08 08000000 mov dword ptr ss:[ebp+0x8],0x8
 *  1001e4c1   85c0             test eax,eax
 *  1001e4c3   74 3c            je short _18.1001e501
 *  1001e4c5   8378 04 00       cmp dword ptr ds:[eax+0x4],0x0
 *  1001e4c9   7f 36            jg short _18.1001e501
 *  1001e4cb   7c 05            jl short _18.1001e4d2
 *  1001e4cd   8338 00          cmp dword ptr ds:[eax],0x0
 *  1001e4d0   73 2f            jnb short _18.1001e501
 *  1001e4d2   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  1001e4d5   8b91 38a20000    mov edx,dword ptr ds:[ecx+0xa238]
 *  1001e4db   8910             mov dword ptr ds:[eax],edx
 *  1001e4dd   8b89 3ca20000    mov ecx,dword ptr ds:[ecx+0xa23c]
 *  1001e4e3   8948 04          mov dword ptr ds:[eax+0x4],ecx
 *  1001e4e6   eb 19            jmp short _18.1001e501
 *  1001e4e8   c745 08 09000000 mov dword ptr ss:[ebp+0x8],0x9
 *  1001e4ef   eb 10            jmp short _18.1001e501
 *  1001e4f1   c745 08 16000000 mov dword ptr ss:[ebp+0x8],0x16
 *  1001e4f8   eb 07            jmp short _18.1001e501
 *  1001e4fa   c745 08 1f000000 mov dword ptr ss:[ebp+0x8],0x1f
 *  1001e501   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  1001e504   8ad0             mov dl,al
 *  1001e506   80f2 20          xor dl,0x20
 *  1001e509   80c2 5f          add dl,0x5f
 *  1001e50c   80fa 3b          cmp dl,0x3b
 *  1001e50f   0f87 80010000    ja _18.1001e695
 *  1001e515   0fb60e           movzx ecx,byte ptr ds:[esi]
 *  1001e518   c1e0 08          shl eax,0x8
 *  1001e51b   0bc1             or eax,ecx
 *  1001e51d   b9 01000000      mov ecx,0x1     ; jichi: hook here
 *  1001e522   03f1             add esi,ecx
 *  1001e524   8945 08          mov dword ptr ss:[ebp+0x8],eax
 *  1001e527   8975 0c          mov dword ptr ss:[ebp+0xc],esi
 *  1001e52a   3d 79810000      cmp eax,0x8179
 *  1001e52f   0f85 9d000000    jnz _18.1001e5d2
 *  1001e535   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  1001e538   56               push esi
 *  1001e539   8d55 d0          lea edx,dword ptr ss:[ebp-0x30]
 *  1001e53c   52               push edx
 *  1001e53d   e8 0e0bffff      call _18.1000f050
 *  1001e542   8d4d d0          lea ecx,dword ptr ss:[ebp-0x30]
 *  1001e545   c745 fc 07000000 mov dword ptr ss:[ebp-0x4],0x7
 *  1001e54c   ff15 500a0e10    call dword ptr ds:[0x100e0a50]           ; _19.6a712fa9
 *  1001e552   84c0             test al,al
 *  1001e554   75 67            jnz short _18.1001e5bd
 *  1001e556   8b75 f0          mov esi,dword ptr ss:[ebp-0x10]
 *  1001e559   8d45 d0          lea eax,dword ptr ss:[ebp-0x30]
 *  1001e55c   50               push eax
 *  1001e55d   8bce             mov ecx,esi
 *  1001e55f   c745 e4 01000000 mov dword ptr ss:[ebp-0x1c],0x1
 *  1001e566   c745 e0 00000000 mov dword ptr ss:[ebp-0x20],0x0
 *  1001e56d   e8 5e80ffff      call _18.100165d0
 *  1001e572   0fb7f8           movzx edi,ax
 *  1001e575   57               push edi
 *  1001e576   8bce             mov ecx,esi
 *  1001e578   e8 c380ffff      call _18.10016640
 *  1001e57d   85c0             test eax,eax
 *  1001e57f   74 0d            je short _18.1001e58e
 *  1001e581   f640 38 02       test byte ptr ds:[eax+0x38],0x2
 *  1001e585   74 07            je short _18.1001e58e
 *  1001e587   c745 e0 01000000 mov dword ptr ss:[ebp-0x20],0x1
 *  1001e58e   837d bc 10       cmp dword ptr ss:[ebp-0x44],0x10
 *  1001e592   74 29            je short _18.1001e5bd
 *  1001e594   8b43 28          mov eax,dword ptr ds:[ebx+0x28]
 *  1001e597   85c0             test eax,eax
 */
bool InsertRUGP2Hook()
{
  DWORD low, high;
  if (!IthCheckFile(L"vm60.dll") || !SafeFillRange(L"vm60.dll", &low, &high)) {
    ConsoleOutput("vnreng:rUGP2: vm60.dll does not exist");
    return false;
  }
  const BYTE bytes[] = {
    0x0f,0xb6,0x0e,             // 1001e515   0fb60e           movzx ecx,byte ptr ds:[esi]
    0xc1,0xe0, 0x08,            // 1001e518   c1e0 08          shl eax,0x8
    0x0b,0xc1,                  // 1001e51b   0bc1             or eax,ecx
    0xb9, 0x01,0x00,0x00,0x00,  // 1001e51d   b9 01000000      mov ecx,0x1     ; jichi: hook here
    0x03,0xf1,                  // 1001e522   03f1             add esi,ecx
    0x89,0x45, 0x08,            // 1001e524   8945 08          mov dword ptr ss:[ebp+0x8],eax
    0x89,0x75, 0x0c             // 1001e527   8975 0c          mov dword ptr ss:[ebp+0xc],esi
  };
  enum { hook_offset = 0x1001e51d - 0x1001e515 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), low, high);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:rUGP2: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.length_offset = 1;
  hp.off = -8;
  hp.type = NO_CONTEXT|BIG_ENDIAN;
  ConsoleOutput("vnreng: INSERT rUGP2");
  NewHook(hp, L"rUGP2");
  return true;
}

} // unnamed namespace

bool InsertRUGPHook()
{
  return InsertRUGP1Hook() ||  InsertRUGP2Hook();
}
/********************************************************************************************
Lucifen hook:
  Game folder contains *.lpk. Used by Navel games.
  Hook is same to GetTextExtentPoint32A, use ESP to split name.
********************************************************************************************/
void InsertLucifenHook()
{
  // BOOL GetTextExtentPoint32(
  //   _In_   HDC hdc,
  //   _In_   LPCTSTR lpString,
  //   _In_   int c,
  //   _Out_  LPSIZE lpSize
  // );
  HookParam hp = {};
  hp.addr = (DWORD)::GetTextExtentPoint32A;
  hp.off = 0x8; // arg2 lpString
  hp.split = -0x18; // jichi 8/12/2014: = -4 - pusha_esp_off
  hp.length_offset = 3;
  hp.type = USING_STRING|USING_SPLIT;
  ConsoleOutput("vnreng: INSERT Lucifen");
  NewHook(hp, L"Lucifen");
  //RegisterEngineType(ENGINE_LUCIFEN);
}
/********************************************************************************************
System40 hook:
  System40 is a game engine developed by Alicesoft.
  Afaik, there are 2 very different types of System40. Each requires a particular hook.

  Pattern 1: Either SACTDX.dll or SACT2.dll exports SP_TextDraw.
  The first relative call in this function draw text to some surface.
  Text pointer is return by last absolute indirect call before that.
  Split parameter is a little tricky. The first register pushed onto stack at the begining
  usually is used as font size later. According to instruction opcode map, push
  eax -- 50, ecx -- 51, edx -- 52, ebx --53, esp -- 54, ebp -- 55, esi -- 56, edi -- 57
  Split parameter value:
  eax - -8,   ecx - -C,  edx - -10, ebx - -14, esp - -18, ebp - -1C, esi - -20, edi - -24
  Just extract the low 4 bit and shift left 2 bit, then minus by -8,
  will give us the split parameter. e.g. push ebx 53->3 *4->C, -8-C=-14.
  Sometimes if split function is enabled, ITH will split text spoke by different
  character into different thread. Just open hook dialog and uncheck split parameter.
  Then click modify hook.

  Pattern 2: *engine.dll exports SP_SetTextSprite.
  At the entry point, EAX should be a pointer to some structure, character at +0x8.
  Before calling this function, the caller put EAX onto stack, we can also find this
  value on stack. But seems parameter order varies from game release. If a future
  game breaks the EAX rule then we need to disassemble the caller code to determine
  data offset dynamically.
********************************************************************************************/

void InsertAliceHook1(DWORD addr, DWORD module, DWORD limit)
{
  if (!addr) {
    ConsoleOutput("vnreng:AliceHook1: failed");
    return;
  }
  for (DWORD i = addr, s = addr; i < s + 0x100; i++)
    if (*(BYTE *)i == 0xe8) { // Find the first relative call.
      DWORD j = i + 5 + *(DWORD *)(i + 1);
      if (j > module && j < limit) {
        while (true) { // Find the first register push onto stack.
          DWORD c = disasm((BYTE*)s);
          if (c == 1)
            break;
          s += c;
        }
        DWORD c = *(BYTE *)s;
        HookParam hp = {};
        hp.addr = j;
        hp.off = -0x8;
        hp.split = -8 -((c & 0xf) << 2);
        hp.type = USING_STRING|USING_SPLIT;
        //if (s>j) hp.type^=USING_SPLIT;
        ConsoleOutput("vnreng: INSERT AliceHook1");
        NewHook(hp, L"System40");
        //RegisterEngineType(ENGINE_SYS40);
        return;
      }
    }
  ConsoleOutput("vnreng:AliceHook1: failed");
}
void InsertAliceHook2(DWORD addr)
{
  if (!addr) {
    ConsoleOutput("vnreng:AliceHook2: failed");
    return;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x8;
  hp.ind = 0x8;
  hp.length_offset = 1;
  hp.type = DATA_INDIRECT;
  ConsoleOutput("vnreng: INSERT AliceHook2");
  NewHook(hp, L"System40");
  //RegisterEngineType(ENGINE_SYS40);
}

// jichi 8/23/2013 Move here from engine.cc
// Do not work for the latest Alice games
bool InsertAliceHook()
{
  DWORD low, high, addr;
  if (::GetFunctionAddr("SP_TextDraw", &addr, &low, &high, 0) && addr) {
    InsertAliceHook1(addr, low, low + high);
    return true;
  }
  if (::GetFunctionAddr("SP_SetTextSprite", &addr, &low, &high, 0) && addr) {
    InsertAliceHook2(addr);
    return true;
  }
  ConsoleOutput("vnreng:AliceHook: failed");
  return false;
}

/**
 *  jichi 12/26/2013: Rance hook
 *
 *  ランス01 光をもとめて: /HSN4:-14@5506A9
 *  - addr: 5572265 (0x5596a9)
 *  - off: 4
 *  - split: 4294967272 (0xffffffe8 = -0x18)
 *  - type: 1041 (0x411)
 *
 *    the above code has the same pattern except int3.
 *    005506a9  |. e8 f2fb1600    call Rance01.006c02a0 ; hook here
 *    005506ae  |. 83c4 0c        add esp,0xc
 *    005506b1  |. 5f             pop edi
 *    005506b2  |. 5e             pop esi
 *    005506b3  |. b0 01          mov al,0x1
 *    005506b5  |. 5b             pop ebx
 *    005506b6  \. c2 0400        retn 0x4
 *    005506b9     cc             int3
 *
 *  ランス・クエスト: /hsn4:-14@42e08a
 *    0042e08a  |. e8 91ed1f00    call Ranceque.0062ce20 ; hook here
 *    0042e08f  |. 83c4 0c        add esp,0xc
 *    0042e092  |. 5f             pop edi
 *    0042e093  |. 5e             pop esi
 *    0042e094  |. b0 01          mov al,0x1
 *    0042e096  |. 5b             pop ebx
 *    0042e097  \. c2 0400        retn 0x4
 *    0042e09a     cc             int3
 */
bool InsertSystem43Hook()
{
  // 9/25/2014 TODO: I should use matchBytes and replace the part after e8 with XX4
  const BYTE ins[] = {  //   005506a9  |. e8 f2fb1600    call rance01.006c02a0 ; hook here
    0x83,0xc4, 0x0c,    //   005506ae  |. 83c4 0c        add esp,0xc
    0x5f,               //   005506b1  |. 5f             pop edi
    0x5e,               //   005506b2  |. 5e             pop esi
    0xb0, 0x01,         //   005506b3  |. b0 01          mov al,0x1
    0x5b,               //   005506b5  |. 5b             pop ebx
    0xc2, 0x04,0x00,    //   005506b6  \. c2 0400        retn 0x4
    0xcc, 0xcc // patching a few int3 to make sure that this is at the end of the code block
  };
  enum { hook_offset = -5 }; // the function call before the ins
  ULONG addr = module_base_; //- sizeof(ins);
  //addr = 0x5506a9;
  enum { near_call = 0xe8 }; // intra-module function call
  do {
    //addr += sizeof(ins); // so that each time return diff address -- not needed
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(ins, sizeof(ins), addr, addr + range);
    if (!addr) {
      //ITH_MSG(L"failed");
      ConsoleOutput("vnreng:System43: pattern not found");
      return false;
    }
    addr += hook_offset;
  } while(near_call != *(BYTE *)addr); // function call
  //ITH_GROWL_DWORD(addr);

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4;
  hp.split = -0x18;
  hp.type = NO_CONTEXT|USING_SPLIT|USING_STRING;
  ConsoleOutput("vnreng: INSERT System43");
  NewHook(hp, L"System43");
  return false;
}

/********************************************************************************************
AtelierKaguya hook:
  Game folder contains message.dat. Used by AtelierKaguya games.
  Usually has font caching issue with TextOutA.
  Game engine uses EBP to set up stack frame so we can easily trace back.
  Keep step out until it's in main game module. We notice that either register or
  stack contains string pointer before call instruction. But it's not quite stable.
  In-depth analysis of the called function indicates that there's a loop traverses
  the string one character by one. We can set a hook there.
  This search process is too complex so I just make use of some characteristic
  instruction(add esi,0x40) to locate the right point.
********************************************************************************************/
bool InsertAtelierHook()
{
  //SafeFillRange(process_name_, &base, &size);
  //size=size-base;
  DWORD sig = 0x40c683; // add esi,0x40
  //i=module_base_+SearchPattern(module_base_,module_limit_-module_base_,&sig,3);
  DWORD i;
  for (i = module_base_; i < module_limit_ - 4; i++) {
    sig = *(DWORD *)i & 0xffffff;
    if (0x40c683 == sig)
      break;
  }
  if (i < module_limit_ - 4)
    for (DWORD j=i-0x200; i>j; i--)
      if (*(DWORD *)i == 0xff6acccc) { // find the function entry
        HookParam hp = {};
        hp.addr = i+2;
        hp.off = 8;
        hp.split = -0x18;
        hp.length_offset = 1;
        hp.type = USING_SPLIT;
        ConsoleOutput("vnreng: INSERT Aterlier KAGUYA");
        NewHook(hp, L"Atelier KAGUYA");
        //RegisterEngineType(ENGINE_ATELIER);
        return true;
      }

  ConsoleOutput("vnreng:Aterlier: failed");
  return false;
  //ConsoleOutput("Unknown Atelier KAGUYA engine.");
}
/********************************************************************************************
CIRCUS hook:
  Game folder contains advdata folder. Used by CIRCUS games.
  Usually has font caching issues. But trace back from GetGlyphOutline gives a hook
  which generate repetition.
  If we study circus engine follow Freaka's video, we can easily discover that
  in the game main module there is a static buffer, which is filled by new text before
  it's drawing to screen. By setting a hardware breakpoint there we can locate the
  function filling the buffer. But we don't have to set hardware breakpoint to search
  the hook address if we know some characteristic instruction(cmp al,0x24) around there.
********************************************************************************************/
bool InsertCircusHook1() // jichi 10/2/2013: Change return type to bool
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*(WORD *)i == 0xa3c)  //cmp al, 0xA; je
      for (DWORD j = i; j < i + 0x100; j++) {
        BYTE c = *(BYTE *)j;
        if (c == 0xc3)
          break;
        if (c == 0xe8) {
          DWORD k = *(DWORD *)(j+1)+j+5;
          if (k > module_base_ && k < module_limit_) {
            HookParam hp = {};
            hp.addr = k;
            hp.off = 0xc;
            hp.split = -0x18;
            hp.length_offset = 1;
            hp.type = DATA_INDIRECT|USING_SPLIT;
            ConsoleOutput("vnreng: INSERT CIRCUS#1");
            NewHook(hp, L"CIRCUS");
            //RegisterEngineType(ENGINE_CIRCUS);
            return true;
          }
        }
      }
      //break;
  //ConsoleOutput("Unknown CIRCUS engine");
  ConsoleOutput("vnreng:CIRCUS: failed");
  return false;
}

/**
 *  jichi 6/5/2014: Sample function from DC3 at 0x4201d0
 *  004201ce     cc             int3
 *  004201cf     cc             int3
 *  004201d0  /$ 8b4c24 08      mov ecx,dword ptr ss:[esp+0x8]
 *  004201d4  |. 8a01           mov al,byte ptr ds:[ecx]
 *  004201d6  |. 84c0           test al,al
 *  004201d8  |. 74 1c          je short dc3.004201f6
 *  004201da  |. 8b5424 04      mov edx,dword ptr ss:[esp+0x4]
 *  004201de  |. 8bff           mov edi,edi
 *  004201e0  |> 3c 24          /cmp al,0x24
 *  004201e2  |. 75 05          |jnz short dc3.004201e9
 *  004201e4  |. 83c1 02        |add ecx,0x2
 *  004201e7  |. eb 04          |jmp short dc3.004201ed
 *  004201e9  |> 8802           |mov byte ptr ds:[edx],al
 *  004201eb  |. 42             |inc edx
 *  004201ec  |. 41             |inc ecx
 *  004201ed  |> 8a01           |mov al,byte ptr ds:[ecx]
 *  004201ef  |. 84c0           |test al,al
 *  004201f1  |.^75 ed          \jnz short dc3.004201e0
 *  004201f3  |. 8802           mov byte ptr ds:[edx],al
 *  004201f5  |. c3             retn
 *  004201f6  |> 8b4424 04      mov eax,dword ptr ss:[esp+0x4]
 *  004201fa  |. c600 00        mov byte ptr ds:[eax],0x0
 *  004201fd  \. c3             retn
 */
bool InsertCircusHook2() // jichi 10/2/2013: Change return type to bool
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ -4; i++)
    if ((*(DWORD *)i & 0xffffff) == 0x75243c) { // cmp al, 24; je
      if (DWORD j = SafeFindEntryAligned(i, 0x80)) {
        HookParam hp = {};
        hp.addr = j;
        hp.off = 0x8;
        hp.type = USING_STRING;
        ConsoleOutput("vnreng: INSERT CIRCUS#2");
        //ITH_GROWL_DWORD(hp.addr); // jichi 6/5/2014: 0x4201d0 for DC3
        NewHook(hp, L"CIRCUS");
        //RegisterEngineType(ENGINE_CIRCUS);
        return true;
      }
      break;
    }
  //ConsoleOutput("Unknown CIRCUS engine.");
  ConsoleOutput("vnreng:CIRCUS: failed");
  return false;
}

/********************************************************************************************
ShinaRio hook:
  Game folder contains rio.ini.
  Problem of default hook GetTextExtentPoint32A is that the text repeat one time.
  But KF just can't resolve the issue. ShinaRio engine always perform integrity check.
  So it's very difficult to insert a hook into the game module. Freaka suggests to refine
  the default hook by adding split parameter on the stack. So far there is 2 different
  version of ShinaRio engine that needs different split parameter. Seems this value is
  fixed to the last stack frame. We just navigate to the entry. There should be a
  sub esp,* instruction. This value plus 4 is just the offset we need.

  New ShinaRio engine (>=2.48) uses different approach.
********************************************************************************************/
static void SpecialHookShina(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  CC_UNUSED(hp);
  DWORD ptr = *(DWORD*)(esp_base-0x20);
  *split = ptr;
  char* str = *(char**)(ptr+0x160);
  strcpy(text_buffer, str);
  int skip = 0;
  for (str = text_buffer; *str; str++)
    if (str[0] == 0x5f) {
      if (str[1] == 0x72)
        str[0] = str[1]=1;
      else if (str[1] == 0x74) {
        while (str[0] != 0x2f)
          *str++ = 1;
        *str=1;
      }
    }

  for (str = text_buffer; str[skip];)
    if (str[skip] == 1)
      skip++;
    else {
      str[0]=str[skip];
      str++;
    }

  str[0] = 0;
  if (strcmp(text_buffer, text_buffer_prev) == 0)
    *len=0;
  else {
    for (skip = 0; text_buffer[skip]; skip++)
      text_buffer_prev[skip] = text_buffer[skip];
    text_buffer_prev[skip] = 0;
    *data = (DWORD)text_buffer_prev;
    *len = skip;
  }
}

// jichi 8/27/2013
// Return ShinaRio version number
// The head of Rio.ini usually looks like:
//     [椎名里緒 v2.49]
// This function will return 49 in the above case.
//
// Games from アトリエさくら do not have Rio.ini, but $procname.ini.
int GetShinaRioVersion()
{
  int ret = 0;
  HANDLE hFile = IthCreateFile(L"RIO.INI", FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
  if (hFile == INVALID_HANDLE_VALUE)  {
    size_t len = wcslen(process_name_);
    if (len > 3) {
      wchar_t fname[MAX_PATH];
      wcscpy(fname, process_name_);
      fname[len -1] = 'i';
      fname[len -2] = 'n';
      fname[len -3] = 'i';
      hFile = IthCreateFile(fname, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
    }
  }

  if (hFile != INVALID_HANDLE_VALUE)  {
    IO_STATUS_BLOCK ios;
    //char *buffer,*version;//,*ptr;
    enum { BufferSize = 0x40 };
    char buffer[BufferSize];
    NtReadFile(hFile, 0, 0, 0, &ios, buffer, BufferSize, 0, 0);
    NtClose(hFile);
    if (buffer[0] == '[') {
      buffer[0x3f] = 0; // jichi 8/24/2013: prevent strstr from overflow
      if (char *version = strstr(buffer, "v2."))
        sscanf(version + 3, "%d", &ret); // +3 to skip "v2."
    }
  }
  return ret;
}

// jichi 8/24/2013: Rewrite ShinaRio logic.
bool InsertShinaHook()
{
  int ver = GetShinaRioVersion();
  if (ver >= 48) { // v2.48, v2.49
    HookParam hp = {};
    hp.addr = (DWORD)::GetTextExtentPoint32A;
    hp.extern_fun = SpecialHookShina;
    hp.type = EXTERN_HOOK|USING_STRING;
    ConsoleOutput("vnreng: INSERT ShinaRio > 2.47");
    NewHook(hp, L"ShinaRio");
    //RegisterEngineType(ENGINE_SHINA);
    return true;

  } else if (ver > 40) // <= v2.47. Older games like あやかしびと does not require hcode
    if (DWORD s = Util::FindCallAndEntryBoth((DWORD)GetTextExtentPoint32A, module_limit_ - module_base_, module_base_, 0xec81)) {
      HookParam hp = {};
      hp.addr = (DWORD)::GetTextExtentPoint32A;
      hp.off = 0x8;
      hp.split = *(DWORD *)(s + 2) + 4;
      hp.length_offset = 1;
      hp.type = DATA_INDIRECT|USING_SPLIT;
      ConsoleOutput("vnreng: INSERT ShinaRio <= 2.47");
      NewHook(hp, L"ShinaRio");
     //RegisterEngineType(ENGINE_SHINA);
    }
  ConsoleOutput("vnreng:ShinaRio: unknown version");
  return false;
}

bool InsertWaffleDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetTextExtentPoint32A)
    return false;

  DWORD handler;
  __asm
  {
    mov eax,fs:[0]
    mov eax,[eax]
    mov eax,[eax]
    mov eax,[eax]
    mov eax,[eax]
    mov eax,[eax]
    mov ecx, [eax + 4]
    mov handler, ecx
  }

  union {
    DWORD i;
    BYTE *ib;
    DWORD *id;
  };
  // jichi 9/30/2013: Fix the bug in ITH logic where j is unintialized
  for (i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*id == handler && *(ib - 1) == 0x68)
      if (DWORD t = SafeFindEntryAligned(i, 0x40)) {
        HookParam hp = {};
        hp.addr = t;
        hp.off = 8;
        hp.ind = 4;
        hp.length_offset = 1;
        hp.type = DATA_INDIRECT;
        ConsoleOutput("vnreng: INSERT Dynamic Waffle");
        NewHook(hp, L"Waffle");
        return true;
      }
  ConsoleOutput("vnreng:DynamicWaffle: failed");
  //ConsoleOutput("Unknown waffle engine.");
  return true; // jichi 12/25/2013: return true
}
//  DWORD retn,limit,str;
//  WORD ch;
//  NTSTATUS status;
//  MEMORY_BASIC_INFORMATION info;
//  str = *(DWORD*)(stack+0xC);
//  ch = *(WORD*)str;
//  if (ch<0x100) return false;
//  limit = (stack | 0xFFFF) + 1;
//  __asm int 3
//  for (stack += 0x10; stack < limit; stack += 4)
//  {
//    str = *(DWORD*)stack;
//    if ((str >> 16) != (stack >> 16))
//    {
//      status = NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)str,MemoryBasicInformation,&info,sizeof(info),0);
//      if (!NT_SUCCESS(status) || info.Protect & PAGE_NOACCESS) continue; //Accessible
//    }
//    if (*(WORD*)(str + 4) == ch) break;
//  }
//  if (stack < limit)
//  {
//    for (limit = stack + 0x100; stack < limit ; stack += 4)
//    if (*(DWORD*)stack == -1)
//    {
//      retn = *(DWORD*)(stack + 4);
//      if (retn > module_base_ && retn < module_limit_)
//      {
//        HookParam hp = {};
//        hp.addr = retn + *(DWORD*)(retn - 4);
//        hp.length_offset = 1;
//        hp.off = -0x20;
//        hp.ind = 4;
//        //hp.split = 0x1E8;
//        hp.type = DATA_INDIRECT;
//        NewHook(hp, L"WAFFLE");
//        //RegisterEngineType(ENGINE_WAFFLE);
//        return true;
//      }
//
//    }
//
//  }

void InsertWaffleHook()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0xac68) {
      HookParam hp = {};
      hp.addr = i;
      hp.length_offset = 1;
      hp.off = -0x20;
      hp.ind = 4;
      hp.split = 0x1e8;
      hp.type = DATA_INDIRECT|USING_SPLIT;
      ConsoleOutput("vnreng: INSERT WAFFLE");
      NewHook(hp, L"WAFFLE");
      return;
    }
  //ConsoleOutput("Probably Waffle. Wait for text.");
  trigger_fun_ = InsertWaffleDynamicHook;
  SwitchTrigger(true);
  //ConsoleOutput("vnreng:WAFFLE: failed");
}

void InsertTinkerBellHook()
{
  //DWORD s1,s2,i;
  //DWORD ch=0x8141;
  DWORD i;
  WORD count;
  count = 0;
  HookParam hp = {};
  hp.length_offset = 1;
  hp.type = BIG_ENDIAN | NO_CONTEXT;
  for (i = module_base_; i< module_limit_ - 4; i++) {
    if (*(DWORD*)i == 0x8141) {
      BYTE t = *(BYTE*)(i - 1);
      if (t == 0x3d || t == 0x2d) {
        hp.off = -0x8;
        hp.addr = i - 1;
      } else if (*(BYTE*)(i-2) == 0x81) {
        t &= 0xF8;
        if (t == 0xF8 || t == 0xE8) {
          hp.off = -8 - ((*(BYTE*)(i-1) & 7) << 2);
          hp.addr = i - 2;
        }
      }
      if (hp.addr) {
        WCHAR hook_name[0x20];
        memcpy(hook_name, L"TinkerBell", 0x14);
        hook_name[0xA] = L'0' + count;
        hook_name[0xB] = 0;
        ConsoleOutput("vnreng:INSERT TinkerBell");
        NewHook(hp, hook_name);
        count++;
        hp.addr = 0;
      }
    }
  }
  ConsoleOutput("vnreng:TinkerBell: failed");
}

//  s1=SearchPattern(module_base_,module_limit_-module_base_-4,&ch,4);
//  if (s1)
//  {
//    for (i=s1;i>s1-0x400;i--)
//    {
//      if (*(WORD*)(module_base_+i)==0xec83)
//      {
//        hp.addr=module_base_+i;
//        NewHook(hp, L"C.System");
//        break;
//      }
//    }
//  }
//  s2=s1+SearchPattern(module_base_+s1+4,module_limit_-s1-8,&ch,4);
//  if (s2)
//  {
//    for (i=s2;i>s2-0x400;i--)
//    {
//      if (*(WORD*)(module_base_+i)==0xec83)
//      {
//        hp.addr=module_base_+i;
//        NewHook(hp, L"TinkerBell");
//        break;
//      }
//    }
//  }
//  //if (count)
  //RegisterEngineType(ENGINE_TINKER);

// jichi 3/19/2014: Insert both hooks
//void InsertLuneHook()
bool InsertMBLHook()
{
  bool ret = false;
  if (DWORD c = Util::FindCallOrJmpAbs((DWORD)::ExtTextOutA, module_limit_ - module_base_, module_base_, true))
    if (DWORD addr = Util::FindCallAndEntryRel(c, module_limit_ - module_base_, module_base_, 0xec8b55)) {
      HookParam hp = {};
      hp.addr = addr;
      hp.off = 4;
      hp.type = USING_STRING;
      ConsoleOutput("vnreng:INSERT MBL-Furigana");
      NewHook(hp, L"MBL-Furigana");
      ret = true;
    }
  if (DWORD c = Util::FindCallOrJmpAbs((DWORD)::GetGlyphOutlineA, module_limit_ - module_base_, module_base_, true))
    if (DWORD addr = Util::FindCallAndEntryRel(c, module_limit_ - module_base_, module_base_, 0xec8b55)) {
      HookParam hp = {};
      hp.addr = addr;
      hp.off = 4;
      hp.split = -0x18;
      hp.length_offset = 1;
      hp.type = BIG_ENDIAN|USING_SPLIT;
      ConsoleOutput("vnreng:INSERT MBL");
      NewHook(hp, L"MBL");
      ret = true;
    }
  if (!ret)
    ConsoleOutput("vnreng:MBL: failed");
  return ret;
}

/** jichi 7/26/2014: E.A.G.L.S engine for TechArts games (SQUEEZ, May-Be Soft)
 *  Sample games: [May-Be Soft] ちぇ～んじ！
 *  Should also work for SQUEEZ's 孕ませシリーズ
 *
 *  Two functions  calls to GetGlyphOutlineA are responsible for painting.
 *  - 0x4094ef
 *  - 0x409e35
 *  However, by default, one of the thread is like: scenario namename scenario
 *  The other thread have infinite loop.
 */
bool InsertEaglsHook()
{
  // DWORD GetGlyphOutline(HDC hdc,  UINT uChar,  UINT uFormat, LPGLYPHMETRICS lpgm, DWORD cbBuffer, LPVOID lpvBuffer, const MAT2 *lpmat2);
  enum stack { // current stack
    //s_retaddr = 0x0
    arg1_hdc = 4 * 1
    , arg2_uChar = 4 * 2
    , arg3_uFormat = 4 * 3
    , arg4_lpgm = 4 * 4
    , arg5_cbBuffer = 4 * 5
    , arg6_lpvBuffer = 4 * 6
    , arg7_lpmat2 = 4 * 7
  };

  // Modify the split for GetGlyphOutlineA
  HookParam hp = {};
  hp.addr = (DWORD)::GetGlyphOutlineA;
  hp.type = BIG_ENDIAN|USING_SPLIT; // the only difference is the split value
  hp.off = arg2_uChar;
  hp.split = arg4_lpgm;
  //hp.split = arg4_lpmag2;
  hp.length_offset = 1;
  ConsoleOutput("vnreng:INSERT EAGLS");
  NewHook(hp, L"EAGLS");
  return true;
}

/********************************************************************************************
YU-RIS hook:
  Becomes common recently. I first encounter this game in Whirlpool games.
  Problem is name is repeated multiple times.
  Step out of function call to TextOuA, just before call to this function,
  there should be a piece of code to calculate the length of the name.
  This length is 2 for single character name and text,
  For a usual name this value is greater than 2.
********************************************************************************************/

bool InsertWhirlpoolHook()
{
  DWORD i,t;
  //IthBreak();
  DWORD entry = Util::FindCallAndEntryBoth((DWORD)TextOutA, module_limit_ - module_base_, module_base_, 0xec83);
  //ITH_GROWL_DWORD(entry);
  if (!entry) {
    ConsoleOutput("vnreng:YU-RIS: function entry does not exist");
    return false;
  }
  entry = Util::FindCallAndEntryRel(entry - 4, module_limit_ - module_base_, module_base_, 0xec83);
  //ITH_GROWL_DWORD(entry);
  if (!entry) {
    ConsoleOutput("vnreng:YU-RIS: function entry does not exist");
    return false;
  }
  entry = Util::FindCallOrJmpRel(entry-4,module_limit_-module_base_-0x10000,module_base_+0x10000,false);
  //ITH_GROWL_DWORD(entry);
  for (i = entry - 4; i > entry - 0x100; i--)
    if (*(WORD *)i == 0xc085) {
      t = *(WORD *)(i+2);
      if ((t&0xff) == 0x76) {
        t = 4;
        break;
      }
      if ((t&0xffff) == 0x860f) {
        t = 8;
        break;
      }
    }
  if (i == entry - 0x100) {
    ConsoleOutput("vnreng:YU-RIS: pattern not exist");
    return false;
  }
  //ITH_GROWL_DWORD2(i,t);
  HookParam hp = {};
  hp.addr = i+t;
  hp.off = -0x24;
  hp.split = -0x8;
  hp.type = USING_STRING|USING_SPLIT;
  ConsoleOutput("vnreng: INSERT YU-RIS");
  //ITH_GROWL_DWORD(hp.addr);
  NewHook(hp, L"YU-RIS");
  //RegisterEngineType(ENGINE_WHIRLPOOL);
  return true;
}

bool InsertCotophaHook()
{
  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:Cotopha: failed to get memory range");
    return false;
  }
  enum { ins = 0xec8b55 }; // mov ebp,esp, sub esp,*  ; jichi 7/12/2014
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetTextMetricsA, ins, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:Cotopha: pattern not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4;
  hp.split = -0x1c;
  hp.type = USING_UNICODE|USING_SPLIT|USING_STRING;
  ConsoleOutput("vnreng: INSERT Cotopha");
  NewHook(hp, L"Cotopha");
  //RegisterEngineType(ENGINE_COTOPHA);
  return true;
}

// jichi 5/10/2014
// See also: http://bbs.sumisora.org/read.php?tid=11044704&fpage=2
bool InsertCatSystem2Hook()
{
  //DWORD search=0x95EB60F;
  //DWORD j,i=SearchPattern(module_base_,module_limit_-module_base_,&search,4);
  //if (i==0) return;
  //i+=module_base_;
  //for (j=i-0x100;i>j;i--)
  //  if (*(DWORD*)i==0xcccccccc) break;
  //if (i==j) return;
  //hp.addr=i+4;
  //hp.off=-0x8;
  //hp.ind=4;
  //hp.split=4;
  //hp.split_ind=0x18;
  //hp.type =BIG_ENDIAN|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
  //hp.length_offset=1;

  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:CatSystem2: failed to get memory range");
    return false;
  }
  enum { beg = 0xff6acccc }; // jichi 7/12/2014: beginning of the function
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetTextMetricsA, beg, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:CatSystem2: pattern not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr + 2; // skip 1 push?
  hp.off = 8;
  hp.split = -0x10;
  hp.length_offset = 1;
  hp.type = BIG_ENDIAN|USING_SPLIT;
  ConsoleOutput("vnreng: INSERT CatSystem2");
  NewHook(hp, L"CatSystem2");
  //RegisterEngineType(ENGINE_CATSYSTEM);
  return true;
}

bool InsertNitroPlusHook()
{
  const BYTE bytes[] = {0xb0, 0x74, 0x53};
  DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:NitroPlus: pattern not exist");
    return false;
  }
  enum : WORD { sub_esp = 0xec83 }; // caller pattern: sub esp = 0x83,0xec
  BYTE b = *(BYTE *)(addr + 3) & 3;
  while (*(WORD *)addr != sub_esp)
    addr--;
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x14+ (b << 2);
  hp.length_offset = 1;
  hp.type |= BIG_ENDIAN;
  ConsoleOutput("vnreng: INSERT NitroPlus");
  NewHook(hp, L"NitroPlus");
  //RegisterEngineType(ENGINE_NITROPLUS);
  return true;
}

bool InsertRetouchHook()
{
  DWORD addr;
  if (GetFunctionAddr("?printSub@RetouchPrintManager@@AAE_NPBDAAVUxPrintData@@K@Z", &addr, nullptr, nullptr, nullptr) ||
      GetFunctionAddr("?printSub@RetouchPrintManager@@AAEXPBDKAAH1@Z", &addr, nullptr, nullptr, nullptr)) {
    HookParam hp = {};
    hp.addr = addr;
    hp.off = 4;
    hp.type = USING_STRING;
    ConsoleOutput("vnreng: INSERT RetouchSystem");
    NewHook(hp, L"RetouchSystem");
    return true;
  }
  ConsoleOutput("vnreng:RetouchSystem: failed");
  //ConsoleOutput("Unknown RetouchSystem engine.");
  return false;
}

namespace { // unnamed Malie
/********************************************************************************************
Malie hook:
  Process name is malie.exe.
  This is the most complicate code I have made. Malie engine store text string in
  linked list. We need to insert a hook to where it travels the list. At that point
  EBX should point to a structure. We can find character at -8 and font size at +10.
  Also need to enable ITH suppress function.
********************************************************************************************/
bool InsertMalieHook1()
{
  const DWORD sig1 = 0x05e3c1;
  enum { sig1_size = 3 };
  DWORD i = SearchPattern(module_base_, module_limit_ - module_base_, &sig1, sig1_size);
  if (!i) {
    ConsoleOutput("vnreng:MalieHook1: pattern i not exist");
    return false;
  }

  const WORD sig2 = 0xc383;
  enum { sig2_size = 2 };
  DWORD j = i + module_base_ + sig1_size;
  i = SearchPattern(j, module_limit_ - j, &sig2, sig2_size);
  //if (!j)
  if (!i) { // jichi 8/19/2013: Change the condition fro J to I
    ConsoleOutput("vnreng:MalieHook1: pattern j not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = j + i;
  hp.off = -0x14;
  hp.ind = -0x8;
  hp.split = -0x14;
  hp.split_ind = 0x10;
  hp.length_offset = 1;
  hp.type = USING_UNICODE|USING_SPLIT|DATA_INDIRECT|SPLIT_INDIRECT;
  ConsoleOutput("vnreng: INSERT MalieHook1");
  NewHook(hp, L"Malie");
  //RegisterEngineType(ENGINE_MALIE);
  return true;
}

DWORD malie_furi_flag_; // jichi 8/20/2013: Make it global so that it can be reset
void SpecialHookMalie(DWORD esp_base, HookParam *hp, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(hp);
  DWORD ch = *(DWORD *)(esp_base - 0x8) & 0xffff,
        ptr = *(DWORD *)(esp_base - 0x24);
  *data = ch;
  *len = 2;
  if (malie_furi_flag_) {
    DWORD index = *(DWORD *)(esp_base - 0x10);
    if (*(WORD *)(ptr + index * 2 - 2) < 0xa)
      malie_furi_flag_ = 0;
  }
  else if (ch == 0xa) {
    malie_furi_flag_ = 1;
    len = 0;
  }
  *split = malie_furi_flag_;
}

bool InsertMalieHook2() // jichi 8/20/2013: Change return type to boolean
{
  const BYTE bytes[] = {0x66,0x3d,0x1,0x0};
  DWORD start = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!start) {
    ConsoleOutput("vnreng:MalieHook2: pattern not exist");
    return false;
  }
  BYTE *ptr = (BYTE *)start;
  while (true) {
    if (*(WORD *)ptr == 0x3d66) {
      ptr += 4;
      if (ptr[0] == 0x75) {
        ptr += ptr[1]+2;
        continue;
      }
      if (*(WORD *)ptr == 0x850f) {
        ptr += *(DWORD *)(ptr + 2) + 6;
        continue;
      }
    }
    break;
  }
  malie_furi_flag_ = 0; // reset old malie flag
  HookParam hp = {};
  hp.addr = (DWORD)ptr + 4;
  hp.off = -8;
  hp.length_offset = 1;
  hp.extern_fun = SpecialHookMalie;
  hp.type = EXTERN_HOOK|USING_SPLIT|USING_UNICODE|NO_CONTEXT;
  ConsoleOutput("vnreng: INSERT MalieHook2");
  NewHook(hp, L"Malie");
  //RegisterEngineType(ENGINE_MALIE);
  return true;
}

/**
 *  jichi 12/17/2013: Added for Electro Arms
 *  Observations from Electro Arms:
 *  1. split = 0xC can handle most texts and its dwRetn is always zero
 *  2. The text containing furigana needed to split has non-zero dwRetn when split = 0
 */
void SpecialHookMalie2(DWORD esp_base, HookParam *hp, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(hp);
  CC_UNUSED(data);
  static DWORD last_split; // FIXME: This makes the special function stateful
  DWORD s1 = *(DWORD *)esp_base; // current split at 0x0
  if (!s1)
    *split = last_split;
  else {
    DWORD s2 = *(DWORD *)(esp_base + 0xc); // second split
    *split = last_split = s1 + s2; // not sure if plus is a good way
  }
  //*len = GetHookDataLength(*hp, esp_base, (DWORD)data);
  *len = 2;
}

/**
 *  jichi 8/20/2013: Add hook for sweet light BRAVA!!
 *  See: http://www.hongfire.com/forum/printthread.php?t=36807&pp=10&page=680
 *
 *  BRAVA!! /H code: "/HWN-4:C@1A3DF4:malie.exe"
 *  - addr: 1719796 = 0x1a3df4
 *  - extern_fun: 0x0
 *  - function: 0
 *  - hook_len: 0
 *  - ind: 0
 *  - length_offset: 1
 *  - module: 751199171 = 0x2cc663c3
 *  - off: 4294967288 = 0xfffffff8L = -0x8
 *  - recover_len: 0
 *  - split: 12 = 0xc
 *  - split_ind: 0
 *  - type: 1106 = 0x452
 */
bool InsertMalie2Hook()
{
  // 001a3dee    6900 70000000   imul eax,dword ptr ds:[eax],70
  // 001a3df4    0200            add al,byte ptr ds:[eax]   ; this is the place to hook
  // 001a3df6    50              push eax
  // 001a3df7    0069 00         add byte ptr ds:[ecx],ch
  // 001a3dfa    0000            add byte ptr ds:[eax],al
  const BYTE bytes1[] = {
    0x40,            // inc eax
    0x89,0x56, 0x08, // mov dword ptr ds:[esi+0x8],edx
    0x33,0xd2,       // xor edx,edx
    0x89,0x46, 0x04  // mov dword ptr ds:[esi+0x4],eax
  };
  ULONG range1 = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes1, sizeof(bytes1), module_base_, module_base_ + range1);
  //reladdr = 0x1a3df4;
  if (!addr) {
    //ITH_MSG(0, "Wrong1", "t", 0);
    //ConsoleOutput("Not malie2 engine");
    ConsoleOutput("vnreng:Malie2Hook: pattern p not exist");
    return false;
  }

  addr += sizeof(bytes1); // skip bytes1
  //const BYTE bytes2[] = { 0x85, 0xc0 }; // test eax,eax
  const WORD bytes2 = 0xc085; // test eax,eax
  enum { range2 = 0x200 };
  addr = MemDbg::findBytes(&bytes2, sizeof(bytes2), addr, addr + range2);
  if (!addr) {
    //ConsoleOutput("Not malie2 engine");
    ConsoleOutput("vnreng:Malie2Hook: pattern q not exist");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = -8; // pusha_eax_off - 4
  hp.length_offset = 1;
  //hp.split = 0xc; // jichi 12/17/2013: Subcontext removed
  //hp.split = -0xc; // jichi 12/17/2013: This could split the furigana, but will mess up the text
  //hp.type = USING_SPLIT|USING_UNICODE|NO_CONTEXT;
  // jichi 12/17/2013: Need extern func for Electro Arms
  // Though the hook parameter is quit similar to Malie, the original extern function does not work
  hp.type = EXTERN_HOOK|USING_SPLIT|USING_UNICODE|NO_CONTEXT;
  hp.extern_fun = SpecialHookMalie2;
  ConsoleOutput("vnreng: INSERT Malie2");
  NewHook(hp, L"Malie2");

  //ITH_GROWL_DWORD2(hp.addr, reladdr);
  //RegisterEngineType(ENGINE_MALIE);
  return true;
}

// jichi 2/8/3014: Return the beginning and the end of the text
// Remove the leading illegal characters
enum { _MALIE3_MAX_LENGTH = VNR_TEXT_CAPACITY };
LPCWSTR _Malie3LTrim(LPCWSTR p)
{
  if (p)
    for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
        p++)
      if (p[0] == L'v' && p[1] == L'_') { // ex. v_akr0001, v_mzk0001
        p += 9;
        return p; // must return otherwise trimming more will break the ITH repetition elimination
      } else if (p[0] > 9) // ltrim illegal characers
        return p;
  return nullptr;
}
// Remove the trailing illegal characters
LPCWSTR _Malie3RTrim(LPCWSTR p)
{
  if (p)
    for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
         p--)
      if (p[-1] > 9) {
        if (p[-1] >= L'0' && p[-1] <= L'9'&& p[-1-7] == L'_')
          p -= 9;
        else
          return p;
      }
  return nullptr;
}
// Return the end of the line
LPCWSTR _Malie3GetEOL(LPCWSTR p)
{
  if (p)
    for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
        p++)
      switch (p[0]) {
      case 0: // \0
      case 0xa: // \n // the text after 0xa is furigana
        return p;
      }
  return nullptr;
}

/**
 *  jichi 3/8/2014: Add hook for 相州戦神館學園 八命陣
 *  See: http://sakuradite.com/topic/157
 *  check 0x5b51ed for ecx+edx*2
 *  Also need to skip furigana.
 */

void SpecialHookMalie3(DWORD esp_base, HookParam *hp, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(hp);
  CC_UNUSED(split);
  DWORD ecx = regof(ecx, esp_base), // *(DWORD *)(esp_base + pusha_ecx_off - 4),
        edx = regof(edx, esp_base); // *(DWORD *)(esp_base + pusha_edx_off - 4);
  //*data = ecx + edx*2; // [ecx+edx*2];
  //*len = wcslen((LPCWSTR)data) << 2;
  // There are garbage characters
  LPCWSTR start = _Malie3LTrim((LPCWSTR)(ecx + edx*2)),
          stop = _Malie3RTrim(_Malie3GetEOL(start));
  *data = (DWORD)start;
  *len = max(0, stop - start) << 1;
  *split = FIXED_SPLIT_VALUE;
  //ITH_GROWL_DWORD5((DWORD)start, (DWORD)stop, *len, (DWORD)*start, (DWORD)_Malie3GetEOL(start));
}

/**
 *  jichi 8/20/2013: Add hook for 相州戦神館學園 八命陣
 *  See: http://sakuradite.com/topic/157
 *  Credits: @ok123
 */
bool InsertMalie3Hook()
{
  const BYTE bytes[] = {
    // 0x90 nop
    0x8b,0x44,0x24, 0x04,   // 5b51e0  mov eax,dword ptr ss:[esp+0x4]
    0x56,                   // 5b51e4  push esi
    0x57,                   // 5b51e5  push edi
    0x8b,0x50, 0x08,        // 5b51e6  mov edx,dword ptr ds:[eax+0x8]
    0x8b,0x08,              // 5b51e9  mov ecx,dword ptr ds:[eax]
    0x33,0xf6,              // 5b51eb  xor esi,esi
    0x66,0x8b,0x34,0x51,    // 5b51ed  mov si,word ptr ds:[ecx+edx*2] // jichi: hook here
    0x42                    // 5b51f1  inc edx
  };
  enum {hook_offset = 0x5b51ed - 0x5b51e0};
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:Malie3: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //ITH_GROWL(hp.addr);
  //hp.addr = 0x5b51ed;
  //hp.addr = 0x5b51f1;
  //hp.addr = 0x5b51f2;
  hp.extern_fun = SpecialHookMalie3;
  hp.type = EXTERN_HOOK|USING_UNICODE|NO_CONTEXT;
  ConsoleOutput("vnreng: INSERT Malie3");
  NewHook(hp, L"Malie3");
  return true;
}

} // unnamed Malie

bool InsertMalieHook()
{
  if (IthCheckFile(L"tools.dll"))
    return InsertMalieHook1(); // For Dies irae, etc
  else {
    // jichi 8/20/2013: Add hook for sweet light engine
    // Insert both malie and malie2 hook.
    bool ok = InsertMalieHook2();
    ok = InsertMalie2Hook() || ok; // jichi 8/20/2013 TO BE RESTORED
    ok = InsertMalie3Hook() || ok; // jichi 3/7/2014
    return ok;
  }
}

/********************************************************************************************
EMEHook hook: (Contributed by Freaka)
  EmonEngine is used by LoveJuice company and TakeOut. Earlier builds were apparently
  called Runrun engine. String parsing varies a lot depending on the font settings and
  speed setting. E.g. without antialiasing (which very early versions did not have)
  uses TextOutA, fast speed triggers different functions then slow/normal. The user can
  set his own name and some odd control characters are used (0x09 for line break, 0x0D
  for paragraph end) which is parsed and put together on-the-fly while playing so script
  can't be read directly.
********************************************************************************************/
bool InsertEMEHook()
{
  ULONG addr = MemDbg::findCallAddress((ULONG)::IsDBCSLeadByte, module_base_, module_limit_);
  // no needed as first call to IsDBCSLeadByte is correct, but sig could be used for further verification
  //WORD sig = 0x51C3;
  //while (c && (*(WORD*)(c-2)!=sig))
  //{
  //  //-0x1000 as FindCallOrJmpAbs always uses an offset of 0x1000
  //  c = Util::FindCallOrJmpAbs((DWORD)IsDBCSLeadByte,module_limit_-c-0x1000+4,c-0x1000+4,false);
  //}
  if (!addr) {
    ConsoleOutput("vnreng:EME: pattern does not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x8;
  hp.length_offset = 1;
  hp.type = NO_CONTEXT|DATA_INDIRECT;
  ConsoleOutput("vnreng: INSERT EmonEngine");
  NewHook(hp, L"EmonEngine");
  //ConsoleOutput("EmonEngine, hook will only work with text speed set to slow or normal!");
  //else ConsoleOutput("Unknown EmonEngine engine");
  return true;
}
void SpecialRunrunEngine(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  CC_UNUSED(hp);
  CC_UNUSED(split);
  DWORD eax = regof(eax, esp_base), // *(DWORD *)(esp_base - 0x8),
        edx = regof(edx, esp_base); // *(DWORD *)(esp_base - 0x10);
  DWORD addr = eax + edx; // eax + edx
  *data = *(WORD *)(addr);
  *len = 2;
}
bool InsertRREHook()
{
  ULONG addr = MemDbg::findCallAddress((ULONG)::IsDBCSLeadByte, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:RRE: function call does not exist");
    return false;
  }
  WORD sig = 0x51c3;
  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.type = NO_CONTEXT|DATA_INDIRECT;
  if ((*(WORD *)(addr-2) != sig)) {
    hp.extern_fun = SpecialRunrunEngine;
    hp.type |= EXTERN_HOOK;
    ConsoleOutput("vnreng: INSERT Runrun#1");
    NewHook(hp, L"RunrunEngine Old");
  } else {
    hp.off = -0x8;
    ConsoleOutput("vnreng: INSERT Runrun#2");
    NewHook(hp, L"RunrunEngine");
  }
  return true;
  //ConsoleOutput("RunrunEngine, hook will only work with text speed set to slow or normal!");
  //else ConsoleOutput("Unknown RunrunEngine engine");
}
bool InsertMEDHook()
{
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x8175) //cmp *, 8175
      for (DWORD j = i, k = i + 0x100; j < k; j++)
        if (*(BYTE *)j == 0xe8) {
          DWORD t = j + 5 + *(DWORD*)(j+1);
          if (t > module_base_ && t < module_limit_) {
            HookParam hp = {};
            hp.addr = t;
            hp.off = -0x8;
            hp.length_offset = 1;
            hp.type = BIG_ENDIAN;
            ConsoleOutput("vnreng: INSERT MED");
            NewHook(hp, L"MED");
            //RegisterEngineType(ENGINE_MED);
            return true;
          }
        }

  //ConsoleOutput("Unknown MED engine.");
  ConsoleOutput("vnreng:MED: failed");
  return false;
}
/********************************************************************************************
AbelSoftware hook:
  The game folder usually is made up many no extended name files(file name doesn't have '.').
  And these files have common prefix which is the game name, and 2 digit in order.


********************************************************************************************/
bool InsertAbelHook()
{
  const DWORD character[] = {0xc981d48a, 0xffffff00};
  if (DWORD j = SearchPattern(module_base_,module_limit_-module_base_, character, sizeof(character))) {
    j += module_base_;
    for (DWORD i = j - 0x100; j > i; j--)
      if (*(WORD *)j == 0xff6a) {
        HookParam hp = {};
        hp.addr = j;
        hp.off = 4;
        hp.type = USING_STRING|NO_CONTEXT;
        ConsoleOutput("vnreng: INSERT AbelSoftware");
        NewHook(hp, L"AbelSoftware");
        //RegisterEngineType(ENGINE_ABEL);
        return true;
      }
  }
  ConsoleOutput("vnreng:Abel: failed");
  return false;
}
bool InsertLiveDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetGlyphOutlineA || !frame)
    return false;
  DWORD k = *(DWORD *)frame;
  k = *(DWORD *)(k+4);
  if (*(BYTE *)(k-5)!=0xe8)
    k = *(DWORD *)(frame + 4);
  DWORD j = k + *(DWORD *)(k - 4);
  if (j > module_base_ && j < module_limit_) {
    HookParam hp = {};
    hp.addr = j;
    hp.off = -0x10;
    hp.length_offset = 1;
    hp.type |= BIG_ENDIAN;
    ConsoleOutput("vnreng: INSERT DynamicLive");
    NewHook(hp, L"Live");
    //RegisterEngineType(ENGINE_LIVE);
    return true;
  }
  ConsoleOutput("vnreng:DynamicLive: failed");
  return true; // jichi 12/25/2013: return true
}
//void InsertLiveHook()
//{
//  ConsoleOutput("Probably Live. Wait for text.");
//  trigger_fun_=InsertLiveDynamicHook;
//  SwitchTrigger(true);
//}
bool InsertLiveHook()
{
  const BYTE ins[] = {0x64,0x89,0x20,0x8b,0x45,0x0c,0x50};
  ULONG addr = MemDbg::findBytes(ins, sizeof(ins), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:Live: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x10;
  hp.length_offset = 1;
  hp.type |= BIG_ENDIAN;
  ConsoleOutput("vnreng: INSERT Live");
  NewHook(hp, L"Live");
  //RegisterEngineType(ENGINE_LIVE);
  //else ConsoleOutput("Unknown Live engine");
  return true;
}

void InsertBrunsHook()
{
  if (IthCheckFile(L"libscr.dll")) {
    HookParam hp = {};
    hp.off = 4;
    hp.length_offset = 1;
    hp.type = USING_UNICODE|MODULE_OFFSET|FUNCTION_OFFSET;
    // jichi 12/27/2013: This function does not work for the latest bruns games anymore
    hp.function = 0x8b24c7bc;
    //?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z
    if (IthCheckFile(L"msvcp90.dll"))
      hp.module = 0xc9c36a5b; // 3385027163
    else if (IthCheckFile(L"msvcp80.dll"))
      hp.module = 0xa9c36a5b; // 2848156251
    else if (IthCheckFile(L"msvcp100.dll")) // jichi 8/17/2013: MSVCRT 10.0 and 11.0
      hp.module = 0xb571d760; // 3044136800;
    else if (IthCheckFile(L"msvcp110.dll"))
      hp.module = 0xd571d760; // 3581007712;
    if (hp.module) {
      ConsoleOutput("vnreng: INSERT Brus#1");
      NewHook(hp, L"Bruns");
    }
  }
  //else
  // jichi 12/21/2013: Keep both bruns hooks
  // The first one does not work for games like 「オーク・キングダム～モン娘繁殖の豚人王～」 anymore.
  {
    union {
      DWORD i;
      DWORD *id;
      WORD *iw;
      BYTE *ib;
    };
    DWORD k = module_limit_ - 4;
    for (i = module_base_ + 0x1000; i < k; i++) {
      if (*id != 0xff) //cmp reg,0xff
        continue;
      i += 4;
      if (*iw != 0x8f0f)
        continue;//jg
      i += 2;
      i += *id + 4;
      for (DWORD j = i + 0x40; i < j; i++) {
        if (*ib != 0xe8)
          continue;
        i++;
        DWORD t = i + 4 + *id;
        if (t > module_base_ && t <module_limit_) {
          i = t;
          for (j = i + 0x80; i < j; i++) {
            if (*ib != 0xe8)
              continue;
            i++;
            t = i + 4 + *id;
            if (t > module_base_ && t <module_limit_) {

              HookParam hp = {};
              hp.addr = t;
              hp.off = 4;
              hp.length_offset = 1;
              hp.type = USING_UNICODE|DATA_INDIRECT;
              ConsoleOutput("vnreng: INSERT Brus#2");
              NewHook(hp, L"Bruns2");
              return;
            }
          }
          k = i; //Terminate outer loop.
          break; //Terminate inner loop.
        }
      }
    }
  }
  //ConsoleOutput("Unknown Bruns engine.");
  ConsoleOutput("vnreng:Brus: failed");
}

/**
 * jichi 8/18/2013:  QLIE identified by GameData/data0.pack
 *
 * The old hook cannot recognize new games.
 */

namespace { // unnamed QLIE
/**
 * jichi 8/18/2013: new QLIE hook
 * See: http://www.hongfire.com/forum/showthread.php/420362-QLIE-engine-Hcode
 *
 * Ins:
 * 55 8B EC 53 8B 5D 1C
 * - 55         push ebp    ; hook here
 * - 8bec       mov ebp, esp
 * - 53         push ebx
 * - 8B5d 1c    mov ebx, dword ptr ss:[ebp+1c]
 *
 * /HBN14*0@4CC2C4
 * - addr: 5030596  (0x4cc2c4)
 * - extern_fun: 0x0
 * - function: 0
 * - hook_len: 0
 * - ind: 0
 * - length_offset: 1
 * - module: 0
 * - off: 20    (0x14)
 * - recover_len: 0
 * - split: 0
 * - split_ind: 0
 * - type: 1032 (0x408)
 */
bool InsertQLIE2Hook()
{
  const BYTE bytes[] = { // size = 7
    0x55,           // 55       push ebp    ; hook here
    0x8b,0xec,      // 8bec     mov ebp, esp
    0x53,           // 53       push ebx
    0x8b,0x5d, 0x1c // 8b5d 1c  mov ebx, dword ptr ss:[ebp+1c]
  };
  //enum { hook_offset = 0 }; // current instruction is the first one
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) {
    ConsoleOutput("vnreng:QLIE2: pattern not found");
    //ConsoleOutput("Not QLIE2");
    return false;
  }

  HookParam hp = {};
  hp.type = DATA_INDIRECT|NO_CONTEXT; // 0x408
  hp.length_offset = 1;
  hp.off = 0x14;
  hp.addr = addr;

  ConsoleOutput("vnreng: INSERT QLIE2");
  NewHook(hp, L"QLIE2");
  //ConsoleOutput("QLIE2");
  return true;
}

// jichi: 8/18/2013: Change return type to bool
bool InsertQLIE1Hook()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x7ffe8347) { //inc edi, cmp esi,7f
      DWORD t = 0;
      for (DWORD j = i; j < i + 0x10; j++) {
        if (*(DWORD *)j == 0xa0) { //cmp esi,a0
          t = 1;
          break;
        }
      }
      if (t)
        for (DWORD j = i; j > i - 0x100; j--)
          if (*(DWORD *)j == 0x83ec8b55) { //push ebp, mov ebp,esp, sub esp,*
            HookParam hp = {};
            hp.addr = j;
            hp.off = 0x18;
            hp.split = -0x18;
            hp.length_offset = 1;
            hp.type = DATA_INDIRECT | USING_SPLIT;
            ConsoleOutput("vnreng: INSERT QLIE1");
            NewHook(hp, L"QLIE");
            //RegisterEngineType(ENGINE_FRONTWING);
            return true;
          }
    }

  ConsoleOutput("vnreng:QLIE1: failed");
  //ConsoleOutput("Unknown QLIE engine");
  return false;
}

} // unnamed QLIE

// jichi 8/18/2013: Add new hook
bool InsertQLIEHook()
{ return InsertQLIE1Hook() || InsertQLIE2Hook(); }

/********************************************************************************************
CandySoft hook:
  Game folder contains many *.fpk. Engine name is SystemC.
  I haven't seen this engine in other company/brand.

  AGTH /X3 will hook lstrlenA. One thread is the exactly result we want.
  But the function call is difficult to located programmatically.
  I find a equivalent points which is more easy to search.
  The script processing function needs to find 0x5B'[',
  so there should a instruction like cmp reg,5B
  Find this position and navigate to function entry.
  The first parameter is the string pointer.
  This approach works fine with game later than つよきす２学期.

  But the original つよきす is quite different. I handle this case separately.

********************************************************************************************/

namespace { // unnamed Candy

// jichi 8/23/2013: split into two different engines
//if (_wcsicmp(process_name_, L"systemc.exe")==0)
// Process name is "SystemC.exe"
bool InsertCandyHook1()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if ((*(DWORD *)i&0xffffff) == 0x24f980) // cmp cl,24
      for (DWORD j = i, k = i - 0x100; j > k; j--)
        if (*(DWORD *)j == 0xc0330a8a) { // mov cl,[edx]; xor eax,eax
          HookParam hp = {};
          hp.addr = j;
          hp.off = -0x10;
          hp.type = USING_STRING;
          ConsoleOutput("vnreng: INSERT SystemC#1");
          NewHook(hp, L"SystemC");
          //RegisterEngineType(ENGINE_CANDY);
          return true;
        }
  ConsoleOutput("vnreng:CandyHook1: failed");
  return false;
}

// jichi 8/23/2013: Process name is NOT "SystemC.exe"
bool InsertCandyHook2()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4 ;i++)
    if (*(WORD *)i == 0x5b3c || // cmp al,0x5b
        (*(DWORD *)i & 0xfff8fc) == 0x5bf880) // cmp reg,0x5B
      for (DWORD j = i, k = i - 0x100; j > k; j--)
        if ((*(DWORD *)j & 0xffff) == 0x8b55) { // push ebp, mov ebp,esp, sub esp,*
          HookParam hp = {};
          hp.addr = j;
          hp.off = 4;
          hp.type = USING_STRING;
          ConsoleOutput("vnreng: INSERT SystemC#2");
          NewHook(hp, L"SystemC");
          //RegisterEngineType(ENGINE_CANDY);
          return true;
        }
  ConsoleOutput("vnreng:CandyHook2: failed");
  return false;
}

/** jichi 10/2/2013: CHECKPOINT
 *
 *  [5/31/2013] 恋もHもお勉強も、おまかせ！お姉ちゃん部
 *  base = 0xf20000
 *  + シナリオ: /HSN-4@104A48:ANEBU.EXE
 *    - off: 4294967288 = 0xfffffff8 = -8
 ,    - type: 1025 = 0x401
 *  + 選択肢: /HSN-4@104FDD:ANEBU.EXE
 *    - off: 4294967288 = 0xfffffff8 = -8
 *    - type: 1089 = 0x441
 */
//bool InsertCandyHook3()
//{
//  return false; // CHECKPOINT
//  const BYTE ins[] = {
//    0x83,0xc4, 0x0c, // add esp,0xc ; hook here
//    0x0f,0xb6,0xc0,  // movzx eax,al
//    0x85,0xc0,       // test eax,eax
//    0x75, 0x0e       // jnz XXOO ; it must be 0xe, or there will be duplication
//  };
//  enum { hook_offset = 0 };
//  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
//  ULONG reladdr = SearchPattern(module_base_, range, ins, sizeof(ins));
//  reladdr = 0x104a48;
//  ITH_GROWL_DWORD(module_base_);
//  //ITH_GROWL_DWORD3(reladdr, module_base_, range);
//  if (!reladdr)
//    return false;
//
//  HookParam hp = {};
//  hp.addr = module_base_ + reladdr + hook_offset;
//  hp.off = -8;
//  hp.type = USING_STRING|NO_CONTEXT;
//  NewHook(hp, L"Candy");
//  return true;
//}

} // unnamed Candy

// jichi 10/2/2013: Add new candy hook
bool InsertCandyHook()
{
  if (0 == _wcsicmp(process_name_, L"systemc.exe"))
    return InsertCandyHook1();
  else
    return InsertCandyHook2();
    //bool b2 = InsertCandyHook2(),
    //     b3 = InsertCandyHook3();
    //return b2 || b3;
}

/********************************************************************************************
Apricot hook:
  Game folder contains arc.a*.
  This engine is heavily based on new DirectX interfaces.
  I can't find a good place where text is clean and not repeating.
  The game processes script encoded in UTF32-like format.
  I reversed the parsing algorithm of the game and implemented it partially.
  Only name and text data is needed.

********************************************************************************************/
static void SpecialHookApricoT(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  CC_UNUSED(hp);
  DWORD reg_esi = *(DWORD *)(esp_base - 0x20);
  DWORD reg_esp = *(DWORD *)(esp_base - 0x18);
  DWORD base = *(DWORD *)(reg_esi + 0x24);
  DWORD index = *(DWORD *)(reg_esi + 0x3c);
  DWORD *script = (DWORD *)(base + index*4);
  *split = reg_esp;
  if (script[0] == L'<') {
    DWORD *end;
    for (end = script; *end != L'>'; end++);
    switch (script[1]) {
    case L'N':
      if (script[2] == L'a' && script[3] == L'm' && script[4] == L'e') {
        buffer_index = 0;
        for (script += 5; script < end; script++)
          if (*script > 0x20)
            wc_buffer[buffer_index++] = *script & 0xFFFF;
        *len = buffer_index<<1;
        *data = (DWORD)wc_buffer;
        // jichi 1/4/2014: The way I save subconext is not able to distinguish the split value
        // Change to shift 16
        //*split |= 1<<31;
        *split |= 1<<16;
      } break;
    case L'T':
      if (script[2] == L'e' && script[3] == L'x' && script[4] == L't') {
        buffer_index = 0;
        for (script += 5; script < end; script++) {
          if (*script > 0x40) {
            while (*script == L'{') {
              script++;
              while (*script!=L'\\') {
                wc_buffer[buffer_index++] = *script & 0xffff;
                script++;
              }
              while (*script++!=L'}');
            }
            wc_buffer[buffer_index++] = *script & 0xffff;
          }
        }
        *len = buffer_index << 1;
        *data = (DWORD)wc_buffer;
      } break;
    }
  }

}
bool InsertApricoTHook()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if ((*(DWORD *)i & 0xfff8fc)==0x3cf880)  // cmp reg,0x3c
      for (DWORD j = i+3, k = i+0x100;j<k;j++)
        if ((*(DWORD *)j & 0xffffff) == 0x4c2) { // retn 4
          HookParam hp = {};
          hp.addr = j + 3;
          hp.extern_fun = SpecialHookApricoT;
          hp.type = EXTERN_HOOK|USING_STRING|USING_UNICODE|NO_CONTEXT;
          ConsoleOutput("vnreng: INSERT ApricoT");
          NewHook(hp, L"ApRicoT");
          //RegisterEngineType(ENGINE_APRICOT);
          return true;
        }

  ConsoleOutput("vnreng:ApricoT: failed");
  return false;
}
void InsertStuffScriptHook()
{
  // BOOL GetTextExtentPoint32(
  //   _In_   HDC hdc,
  //   _In_   LPCTSTR lpString,
  //   _In_   int c,
  //   _Out_  LPSIZE lpSize
  // );
  HookParam hp = {};
  hp.addr = (DWORD)::GetTextExtentPoint32A;
  hp.off = 0x8; // arg2 lpString
  hp.split = -0x18; // jichi 8/12/2014: = -4 - pusha_esp_off
  hp.type = USING_STRING | USING_SPLIT;
  ConsoleOutput("vnreng: INSERT StuffScriptEngine");
  NewHook(hp, L"StuffScriptEngine");
  //RegisterEngine(ENGINE_STUFFSCRIPT);
}
bool InsertTriangleHook()
{
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if ((*(DWORD*)i & 0xffffff) == 0x75403c) // cmp al,0x40; jne
      for (DWORD j = i + 4 + *(BYTE*)(i+3), k = j + 0x20; j < k; j++)
        if (*(BYTE*)j == 0xe8) {
          DWORD t = j + 5 + *(DWORD *)(j + 1);
          if (t > module_base_ && t < module_limit_) {
            HookParam hp = {};
            hp.addr = t;
            hp.off = 4;
            hp.type = USING_STRING;
            ConsoleOutput("vnreng: INSERT Triangle");
            NewHook(hp, L"Triangle");
            //RegisterEngineType(ENGINE_TRIANGLE);
            return true;
          }
        }
  //ConsoleOutput("Old/Unknown Triangle engine.");
  ConsoleOutput("vnreng:Triangle: failed");
  return false;
}
bool InsertPensilHook()
{
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x6381) // cmp *,8163
      if (DWORD j = SafeFindEntryAligned(i, 0x100)) {
        HookParam hp = {};
        hp.addr = j;
        hp.off = 8;
        hp.length_offset = 1;
        ConsoleOutput("vnreng: INSERT Pensil");
        NewHook(hp, L"Pensil");
        return true;
        //RegisterEngineType(ENGINE_PENSIL);
      }
  //ConsoleOutput("Unknown Pensil engine.");
  ConsoleOutput("vnreng:Pensil: failed");
  return false;
}
bool IsPensilSetup()
{
  HANDLE hFile = IthCreateFile(L"PSetup.exe", FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
  FILE_STANDARD_INFORMATION info;
  IO_STATUS_BLOCK ios;
  LPVOID buffer = nullptr;
  NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
  NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0,
      &info.AllocationSize.LowPart, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
  NtClose(hFile);
  BYTE *b = (BYTE *)buffer;
  DWORD len = info.EndOfFile.LowPart & ~1;
  if (len == info.AllocationSize.LowPart)
    len -= 2;
  b[len] = 0;
  b[len + 1] = 0;
  bool ret = wcsstr((LPWSTR)buffer, L"PENSIL") || wcsstr((LPWSTR)buffer, L"Pensil");
  NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
  return ret;
}
static void SpecialHookDebonosu(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  CC_UNUSED(split);
  DWORD retn = *(DWORD*)esp_base;
  if (*(WORD*)retn == 0xc483) // add esp, *
    hp->off = 4;
  else
    hp->off = -0x8;
  hp->type ^= EXTERN_HOOK;
  hp->extern_fun = 0;
  *data = *(DWORD*)(esp_base + hp->off);
  *len = strlen((char*)*data);
}
bool InsertDebonosuHook()
{
  DWORD fun;
  if (CC_UNLIKELY(!GetFunctionAddr("lstrcatA", &fun, 0, 0, 0))) {
    ConsoleOutput("vnreng:Debonosu: failed to find lstrcatA");
    return false;
  }
  DWORD addr = Util::FindImportEntry(module_base_, fun);
  if (!addr) {
    ConsoleOutput("vnreng:Debonosu: lstrcatA is not called");
    return false;
  }
  DWORD search = 0x15ff | (addr << 16);
  addr >>= 16;
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == search &&
        *(WORD *)(i + 4) == addr && // call dword ptr lstrcatA
        *(BYTE *)(i - 5) == 0x68) { // push $
      DWORD push = *(DWORD *)(i - 4);
      for (DWORD j = i + 6, k = j + 0x10; j < k; j++)
        if (*(BYTE *)j == 0xb8 &&
            *(DWORD *)(j + 1) == push)
          if (DWORD hook_addr = SafeFindEntryAligned(i, 0x200)) {
            HookParam hp = {};
            hp.addr = hook_addr;
            hp.extern_fun = SpecialHookDebonosu;
            hp.type = USING_STRING|EXTERN_HOOK;
            ConsoleOutput("vnreng: INSERT Debonosu");
            NewHook(hp, L"Debonosu");
            //RegisterEngineType(ENGINE_DEBONOSU);
            return true;
          }
      }

  ConsoleOutput("vnreng:Debonosu: failed");
  //ConsoleOutput("Unknown Debonosu engine.");
  return false;
}

/* 7/8/2014: The engine name is supposed to be: AoiGameSystem Engine
 * See: http://capita.tistory.com/m/post/205
 *
 *  BUNNYBLACK Trial2 (SystemAoi4)
 *  baseaddr: 0x01d0000
 *
 *  1002472e   cc               int3
 *  1002472f   cc               int3
 *  10024730   55               push ebp    ; jichi: hook here
 *  10024731   8bec             mov ebp,esp
 *  10024733   51               push ecx
 *  10024734   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  1002473b   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  1002473e   0fb708           movzx ecx,word ptr ds:[eax]
 *  10024741   85c9             test ecx,ecx
 *  10024743   74 34            je short _8.10024779
 *  10024745   6a 00            push 0x0
 *  10024747   6a 00            push 0x0
 *  10024749   6a 01            push 0x1
 *  1002474b   8b55 14          mov edx,dword ptr ss:[ebp+0x14]
 *  1002474e   52               push edx
 *  1002474f   0fb645 10        movzx eax,byte ptr ss:[ebp+0x10]
 *  10024753   50               push eax
 *  10024754   0fb74d 0c        movzx ecx,word ptr ss:[ebp+0xc]
 *  10024758   51               push ecx
 *  10024759   8b55 08          mov edx,dword ptr ss:[ebp+0x8]
 *  1002475c   52               push edx
 *  1002475d   e8 8eddffff      call _8.100224f0
 *  10024762   83c4 1c          add esp,0x1c
 *  10024765   8945 fc          mov dword ptr ss:[ebp-0x4],eax
 *  10024768   8b45 1c          mov eax,dword ptr ss:[ebp+0x1c]
 *  1002476b   50               push eax
 *  1002476c   8b4d 18          mov ecx,dword ptr ss:[ebp+0x18]
 *  1002476f   51               push ecx
 *  10024770   8b55 fc          mov edx,dword ptr ss:[ebp-0x4]
 *  10024773   52               push edx
 *  10024774   e8 77c6ffff      call _8.10020df0
 *  10024779   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 *  1002477c   8be5             mov esp,ebp
 *  1002477e   5d               pop ebp
 *  1002477f   c2 1800          retn 0x18
 *  10024782   cc               int3
 *  10024783   cc               int3
 *  10024784   cc               int3
 *
 *  2/12/2015 jichi: SystemAoi5
 *
 *  Note that BUNNYBLACK 3 also has SystemAoi5 version 4.1
 *
 *  Hooked to PgsvTd.dll for all SystemAoi engine, which contains GDI functions.
 *  - Old: AoiLib.dll from DrawTextExA
 *  - SystemAoi4: Aoi4.dll from DrawTextExW
 *  - SystemAoi5: Aoi5.dll from GetGlyphOutlineW
 *
 *  Logic:
 *  - Find GDI function (DrawTextExW, etc.) used to paint text in PgsvTd.dll
 *  - Then search the function call stack, to find where the exe module invoke PgsvTd
 *  - Finally insert to the call address, and text is on the top of the stack.
 *
 *  Sample hooked call in 悪魔娘の看板料理 Aoi5
 *
 *  00B6D085   56               PUSH ESI
 *  00B6D086   52               PUSH EDX
 *  00B6D087   51               PUSH ECX
 *  00B6D088   68 9E630000      PUSH 0x639E
 *  00B6D08D   50               PUSH EAX
 *  00B6D08E   FF15 54D0BC00    CALL DWORD PTR DS:[0xBCD054]             ; _12.0039E890, jichi: hook here
 *  00B6D094   8B57 20          MOV EDX,DWORD PTR DS:[EDI+0x20]
 *  00B6D097   89049A           MOV DWORD PTR DS:[EDX+EBX*4],EAX
 *  00B6D09A   8B4F 20          MOV ECX,DWORD PTR DS:[EDI+0x20]
 *  00B6D09D   8B1499           MOV EDX,DWORD PTR DS:[ECX+EBX*4]
 *  00B6D0A0   8D85 50FDFFFF    LEA EAX,DWORD PTR SS:[EBP-0x2B0]
 *  00B6D0A6   50               PUSH EAX
 *  00B6D0A7   52               PUSH EDX
 *  00B6D0A8   FF15 18D0BC00    CALL DWORD PTR DS:[0xBCD018]             ; _12.003A14A0
 *
 *  Special hook is needed, since the utf16 text is like this:
 *  [f9S30e0u]　が、それは人間相手の話だ。
 */
namespace { // unnamed
void SpecialSystemAoiHook(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  *split = 0; // 8/3/2014 jichi: split is zero, so return address is used as split
  if (hp->type & USING_UNICODE) {
    LPCWSTR wcs = (LPWSTR)argof(1, esp_base); // jichi: text on the top of the stack
    size_t size = ::wcslen(wcs);
    for (DWORD i = 0; i < size; i++)
      if (wcs[i] == L'>' || wcs[i] == L']') { // skip leading ] for scenario and > for name threads
        *data = (DWORD)(wcs + i + 1);
        size -= i + 1;
        *len = size * 2; // * 2 for wstring
        return;
      }
  } else {
    LPCSTR cs = (LPCSTR)argof(1, esp_base); // jichi: text on the top of the stack
    size_t size = ::strlen(cs);
    for (DWORD i = 0; i < size; i++)
      if (cs[i] == '>' || cs[i] == ']') {
        *data = (DWORD)(cs + i + 1);
        size -= i + 1;
        *len = size;
        return;
      }
  }
}

int GetSystemAoiVersion() // return result is cached
{
  static int ret = 0;
  if (!ret) {
    if (IthCheckFile(L"Aoi4.dll"))
      ret = 4;
    else if (IthCheckFile(L"Aoi5.dll"))
      ret = 5;
    else if (IthCheckFile(L"Aoi6.dll")) // not exist yet, for future version
      ret = 6;
    else if (IthCheckFile(L"Aoi7.dll")) // not exist yet, for future version
      ret = 7;
    else // AoiLib.dll, etc
      ret = 3;
  }
  return ret;
}

bool InsertSystemAoiDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  int version = GetSystemAoiVersion();
  bool utf16 = true;
  if (addr == ::DrawTextExA) // < 4
    utf16 = false;
  if (addr == ::DrawTextExW) // 4~5
    ; // pass
  else if (addr == ::GetGlyphOutlineW && version >= 5)
    ; // pass
  else
    return false;

  DWORD high, low;
  Util::GetCodeRange(module_base_, &low, &high);

  // jichi 2/15/2015: Traverse the stack to dynamically find the ancestor call from the main module
  const DWORD stop = (stack & 0xffff0000) + 0x10000; // range to traverse the stack
  for (DWORD i = stack; i < stop; i += 4) {
    DWORD k = *(DWORD *)i;
    if (k > low && k < high && // jichi: if the stack address falls into the code region of the main exe module
        ((*(WORD *)(k - 6) == 0x15ff) || *(BYTE *)(k - 5) == 0xe8)) { // jichi 10/20/2014: call dword ptr ds

      HookParam hp = {};
      hp.off = 0x4; // target text is on the top of the stack
      hp.extern_fun = (HookParam::extern_fun_t)SpecialSystemAoiHook; // need to remove garbage
      hp.type = utf16 ? USING_UNICODE : USING_STRING;

      i = *(DWORD *)(k - 4); // get function call address
      if (*(DWORD *)(k - 5) == 0xe8) // short jump
        hp.addr = i + k;
      else
        hp.addr = *(DWORD *)i; // jichi: long jump, this is what is happening in Aoi5
      //NewHook(hp, L"SofthouseChara");
      //ITH_GROWL_DWORD(hp.addr); // BUNNYBLACK: 0x10024730, base 0x01d0000
      if (hp.addr) {
        ConsoleOutput("vnreng: INSERT SystemAoi");
        if (addr == ::GetGlyphOutlineW)
          NewHook(hp, L"SystemAoi2"); // jichi 2/12/2015
        else
          NewHook(hp, L"SystemAoi"); // jichi 7/8/2014: renamed, see: ja.wikipedia.org/wiki/ソフトハウスキャラ
        ConsoleOutput("vnreng:SystemAoi: disable GDI hooks");
        DisableGDIHooks();
      } else
        ConsoleOutput("vnreng: failed to detect SystemAoi");
      //RegisterEngineType(ENGINE_SOFTHOUSE);
      return true;
    }
  }
  ConsoleOutput("vnreng:SystemAoi: failed");
  return true; // jichi 12/25/2013: return true
}

} // unnamed namespace

bool InsertSystemAoiHook()
{
  ConsoleOutput("vnreng: DYNAMIC SystemAoi");
  //ConsoleOutput("Probably SoftHouseChara. Wait for text.");
  trigger_fun_ = InsertSystemAoiDynamicHook;
  SwitchTrigger(true);
  return true;
}

static void SpecialHookCaramelBox(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  DWORD reg_ecx = *(DWORD*)(esp_base + hp->off);
  BYTE *ptr = (BYTE *)reg_ecx;
  buffer_index = 0;
  while (ptr[0])
    if (ptr[0] == 0x28) { // Furigana format: (Kanji,Furi)
      ptr++;
      while (ptr[0]!=0x2c) //Copy Kanji
        text_buffer[buffer_index++] = *ptr++;
      while (ptr[0]!=0x29) // Skip Furi
        ptr++;
      ptr++;
    } else if (ptr[0] == 0x5c)
      ptr +=2;
    else {
      text_buffer[buffer_index++] = ptr[0];
      if (LeadByteTable[ptr[0]] == 2) {
        ptr++;
        text_buffer[buffer_index++] = ptr[0];
      }
      ptr++;
    }

  *len = buffer_index;
  *data = (DWORD)text_buffer;
  *split = 0; // 8/3/2014 jichi: use return address as split
}
// jichi 10/1/2013: Change return type to bool
bool InsertCaramelBoxHook()
{
  union { DWORD i; BYTE* pb; WORD* pw; DWORD* pd; };
  DWORD reg = -1;
  for (i = module_base_ + 0x1000; i < module_limit_ - 4; i++) {
    if (*pd == 0x7ff3d) // cmp eax, 7ff
      reg = 0;
    else if ((*pd & 0xfffff8fc) == 0x07fff880) // cmp reg, 7ff
      reg = pb[1] & 0x7;

    if (reg == -1)
      continue;

    DWORD flag = 0;
    if (*(pb - 6) == 3) { //add reg, [ebp+$disp_32]
      if (*(pb - 5) == (0x85 | (reg << 3)))
        flag = 1;
    } else if (*(pb - 3) == 3) { // add reg, [ebp+$disp_8]
      if (*(pb - 2) == (0x45 | (reg << 3)))
        flag = 1;
    } else if (*(pb - 2) == 3) { // add reg, reg
      if (((*(pb - 1) >> 3) & 7)== reg)
        flag = 1;
    }
    reg = -1;
    if (flag) {
      for (DWORD j = i, k = i - 0x100; j > k; j--) {
        if ((*(DWORD *)j & 0xffff00ff) == 0x1000b8) { // mov eax,10??
          HookParam hp = {};
          hp.addr = j & ~0xf;
          hp.extern_fun = SpecialHookCaramelBox;
          hp.type = USING_STRING | EXTERN_HOOK;
          for (i &= ~0xffff; i < module_limit_ - 4; i++)
            if (pb[0] == 0xe8) {
              pb++;
              if (pd[0] + i + 4 == hp.addr) {
                pb += 4;
                if ((pd[0] & 0xffffff) == 0x04c483)
                  hp.off = 4;
                else hp.off = -0xc;
                break;
              }
            }

          if (hp.off == 0) {
            ConsoleOutput("vnreng:CaramelBox: failed, zero off");
            return false;
          }
          ConsoleOutput("vnreng: INSERT CaramelBox");
          NewHook(hp, L"CaramelBox");
          //RegisterEngineType(ENGINE_CARAMEL);
          return true;
        }
      }
    }
  }
  ConsoleOutput("vnreng:CaramelBox: failed");
  return false;
//_unknown_engine:
  //ConsoleOutput("Unknown CarmelBox engine.");
}

/**
 *  jichi 10/12/2014
 *  P.S.: Another approach
 *  See: http://tieba.baidu.com/p/2425786155
 *  Quote:
 *  I guess this post should go in here. I got sick of AGTH throwing a fit when entering the menus in Wolf RPG games, so I did some debugging. This is tested and working properly with lots of games. If you find one that isn't covered then please PM me and I'll look into it.
 *
 *  Wolf RPG H-code - Use whichever closest matches your Game.exe
 *  /HBN*0@454C6C (2010/10/09 : 2,344KB : v1.31)
 *  /HBN*0@46BA03 (2011/11/22 : 2,700KB : v2.01)
 *  /HBN*0@470CEA (2012/05/07 : 3,020KB : v2.02)
 *  /HBN*0@470D5A (2012/06/10 : 3,020KB : v2.02a)
 *
 *  ith_p.cc:Ith::parseHookCode: enter: code = "/HBN*0@470CEA"
 *  - addr: 4656362 ,
 *  - length_offset: 1
 *  - type: 1032 = 0x408
 *
 *  Use /HB instead of /HBN if you want to split dialogue text and menu text into separate threads.
 *  Also set the repetition trace parameters in AGTH higher or it won't work properly with text-heavy menus. 64 x 16 seems to work fine.
 *
 *  Issues:
 *  AGTH still causes a bit of lag when translating menus if you have a lot of skills or items.
 *  Using ITH avoids this problem, but it sometimes has issues with repetition detection which can be fixed by quickly deselecting and reselecting the game window; Personally I find this preferable to menu and battle slowdown that AGTH sometimes causes, but then my PC is pretty slow so you might not have that problem.
 *
 *  Minimising the AGTH/ITH window generally makes the game run a bit smoother as windows doesn't need to keep scrolling the text box as new text is added.
 *
 *  RPG Maker VX H-code:
 *  Most games are detected automatically and if not then by using the AGTH /X or /X2 or /X3 parameters.
 *
 *  Games that use TRGSSX.dll may have issues with detection (especially with ITH).
 *  If TRGSSX.dll is included with the game then this code should work:
 *  /HQN@D3CF:TRGSSX.dll
 *
 *  With this code, using AGTH to start the process will not work. You must start the game normally and then hook the process afterwards.
 *  ITH has this functionality built into the interface. AGTH requires the /PN command line argument, for example:
 *  agth /PNGame.exe /HQN@D3CF:TRGSSX.dll /C
 *
 *  Again, drop the N to split dialogue and menu text into separate threads.
 */
// jichi 10/13/2013: restored
bool InsertWolfHook()
{
  //__asm int 3   // debug
  // jichi 10/12/2013:
  // Step 1: find the address of GetTextMetricsA
  // Step 2: find where this function is called
  // Step 3: search "sub esp, XX" after where it is called
  if (DWORD c1 = Util::FindCallAndEntryAbs((DWORD)GetTextMetricsA, module_limit_ - module_base_, module_base_, 0xec81))
    if (DWORD c2 = Util::FindCallOrJmpRel(c1, module_limit_ - module_base_, module_base_, 0)) {
      union {
        DWORD i;
        WORD *k;
      };
      DWORD j;
      for (i = c2 - 0x100, j = c2 - 0x400; i > j; i--)
        if (*k == 0xec83) { // jichi 10/12/2013: 83 EC XX   sub esp, XX  See: http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20120312.txt
          HookParam hp = {};
          hp.addr = i;
          hp.off = -0xc;
          hp.split = -0x18;
          hp.type = DATA_INDIRECT|USING_SPLIT;
          hp.length_offset = 1;
          //ITH_GROWL_DWORD(hp.addr); // jichi 6/5/2014: 淫乱勇者セフィのRPG = 0x50a400
          ConsoleOutput("vnreng: INSERT WolfRPG");
          NewHook(hp, L"WolfRPG");
          return true;
        }
    }

  //ConsoleOutput("Unknown WolfRPG engine.");
  ConsoleOutput("vnreng:WolfRPG: failed");
  return false;
}

bool InsertIGSDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != GetGlyphOutlineW)
    return false;
  DWORD i;
  i = *(DWORD *)frame;
  i = *(DWORD *)(i+4);
  DWORD j, k;
  if (SafeFillRange(L"mscorlib.ni.dll", &j, &k)) {
    while (*(BYTE *)i != 0xe8)
      i++;
    DWORD t = *(DWORD *)(i + 1) + i + 5;
    if (t>j && t<k) {
      HookParam hp = {};
      hp.addr = t;
      hp.off = -0x10;
      hp.split = -0x18;
      hp.length_offset = 1;
      hp.type = USING_UNICODE|USING_SPLIT;
      ConsoleOutput("vnreng: INSERT IronGameSystem");
      NewHook(hp, L"IronGameSystem");
      //ConsoleOutput("IGS - Please set text(テキスト) display speed(表示速度) to fastest(瞬間)");
      //RegisterEngineType(ENGINE_IGS);
      return true;
    }
  }
  ConsoleOutput("vnreng:IGS: failed");
  return true; // jichi 12/25/2013: return true
}
void InsertIronGameSystemHook()
{
  //ConsoleOutput("Probably IronGameSystem. Wait for text.");
  trigger_fun_ = InsertIGSDynamicHook;
  SwitchTrigger(true);
  ConsoleOutput("vnreng: TRIGGER IronGameSystem");
}

/********************************************************************************************
AkabeiSoft2Try hook:
  Game folder contains YaneSDK.dll. Maybe we should call the engine Yane(屋根 = roof)?
  This engine is based on .NET framework. This really makes it troublesome to locate a
  valid hook address. The problem is that the engine file merely contains bytecode for
  the CLR. Real meaningful object code is generated dynamically and the address is randomized.
  Therefore the easiest method is to brute force search whole address space. While it's not necessary
  to completely search the whole address space, since non-executable pages can be excluded first.
  The generated code sections do not belong to any module(exe/dll), hence they do not have
  a section name. So we can also exclude executable pages from all modules. At last, the code
  section should be long(>0x2000). The remain address space should be several MBs in size and
  can be examined in reasonable time(less than 0.1s for P8400 Win7x64).
  Characteristic sequence is 0F B7 44 50 0C, stands for movzx eax, word ptr [edx*2 + eax + C].
  Obviously this instruction extracts one unicode character from a string.
  A main shortcoming is that the code is not generated if it hasn't been used yet.
  So if you are in title screen this approach will fail.

********************************************************************************************/
namespace { // unnamed
MEMORY_WORKING_SET_LIST *GetWorkingSet()
{
  DWORD len,retl;
  NTSTATUS status;
  LPVOID buffer = 0;
  len = 0x4000;
  status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  if (!NT_SUCCESS(status)) return 0;
  status = NtQueryVirtualMemory(NtCurrentProcess(), 0, MemoryWorkingSetList, buffer, len, &retl);
  if (status == STATUS_INFO_LENGTH_MISMATCH) {
    len = *(DWORD*)buffer;
    len = ((len << 2) & 0xfffff000) + 0x4000;
    retl = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &retl, MEM_RELEASE);
    buffer = 0;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), 0, MemoryWorkingSetList, buffer, len, &retl);
    if (!NT_SUCCESS(status)) return 0;
    return (MEMORY_WORKING_SET_LIST*)buffer;
  } else {
    retl = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &retl, MEM_RELEASE);
    return 0;
  }

}
typedef struct _NSTRING
{
  PVOID vfTable;
  DWORD lenWithNull;
  DWORD lenWithoutNull;
  WCHAR str[1];
} NSTRING;

// qsort correctly identifies overflow.
int cmp(const void * a, const void * b)
{ return *(int*)a - *(int*)b; }

void SpecialHookAB2Try(DWORD esp_base, HookParam *hp, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(hp);
  //DWORD test = *(DWORD*)(esp_base - 0x10);
  DWORD edx = regof(edx, esp_base);
  if (edx != 0)
    return;

  //NSTRING *s = *(NSTRING **)(esp_base - 8);
  if (const NSTRING *s = (NSTRING *)regof(eax, esp_base)) {
    *len = s->lenWithoutNull << 1;
    *data = (DWORD)s->str;
    //*split = 0;
    *split = FIXED_SPLIT_VALUE; // 8/3/2014 jichi: change to single threads
  }
}

BOOL FindCharacteristInstruction(MEMORY_WORKING_SET_LIST *list)
{
  DWORD base, size;
  DWORD i, j, k, addr, retl;
  NTSTATUS status;
  ::qsort(&list->WorkingSetList, list->NumberOfPages, 4, cmp);
  base = list->WorkingSetList[0];
  size = 0x1000;
  for (i = 1; i < list->NumberOfPages; i++) {
    if ((list->WorkingSetList[i] & 2) == 0)
      continue;
    if (list->WorkingSetList[i] >> 31)
      break;
    if (base + size == list->WorkingSetList[i])
      size += 0x1000;
    else {
      if (size > 0x2000) {
        addr = base & ~0xfff;
        status = NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)addr,
          MemorySectionName,text_buffer_prev,0x1000,&retl);
        if (!NT_SUCCESS(status)) {
          k = addr + size - 4;
          for (j = addr; j < k; j++) {
            if (*(DWORD*)j == 0x5044b70f) {
              if (*(WORD*)(j + 4) == 0x890c) { // movzx eax, word ptr [edx*2 + eax + 0xC]; wchar = string[i];
                HookParam hp = {};
                hp.addr = j;
                hp.extern_fun = SpecialHookAB2Try;
                hp.type = USING_STRING|USING_UNICODE|EXTERN_HOOK|NO_CONTEXT;
                ConsoleOutput("vnreng: INSERT AB2Try");
                NewHook(hp, L"AB2Try");
                //ConsoleOutput("Please adjust text speed to fastest/immediate.");
                //RegisterEngineType(ENGINE_AB2T);
                return TRUE;
              }
            }
          }
        }
      }
      size = 0x1000;
      base = list->WorkingSetList[i];
    }
  }
  return FALSE;
}
} // unnamed namespace
bool InsertAB2TryHook()
{
  MEMORY_WORKING_SET_LIST *list = GetWorkingSet();
  if (!list) {
    ConsoleOutput("vnreng:AB2Try: cannot find working list");
    return false;
  }
  bool ret = FindCharacteristInstruction(list);
  if (ret)
    ConsoleOutput("vnreng:AB2Try: found characteristic sequence");
  else
    ConsoleOutput("vnreng:AB2Try: cannot find characteristic sequence");
  //L"Make sure you have start the game and have seen some text on the screen.");
  DWORD size = 0;
  NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&list, &size, MEM_RELEASE);
  return ret;
}

/********************************************************************************************
C4 hook: (Contributed by Stomp)
  Game folder contains C4.EXE or XEX.EXE.
********************************************************************************************/
bool InsertC4Hook()
{
  const BYTE bytes[] = { 0x8a, 0x10, 0x40, 0x80, 0xfa, 0x5f, 0x88, 0x15 };
  //enum { hook_offset = 0 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:C4: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x8;
  hp.type |= DATA_INDIRECT|NO_CONTEXT;
  hp.length_offset = 1;
  ConsoleOutput("vnreng: INSERT C4");
  NewHook(hp, L"C4");
  //RegisterEngineType(ENGINE_C4);
  return true;
}
static void SpecialHookWillPlus(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  static DWORD detect_offset;
  if (detect_offset) return;
  DWORD i,l;
  union{
    DWORD retn;
    WORD *pw;
    BYTE *pb;
  };
  retn = *(DWORD*)esp_base;
  i = 0;
  while (*pw != 0xc483) { //add esp, $
    l = ::disasm(pb);
    if (++i == 5)
      //ConsoleOutput("Fail to detect offset.");
      break;
    retn += l;
  }
  if (*pw == 0xc483) {
    hp->off = *(pb + 2) - 8;
    hp->type ^= EXTERN_HOOK;
    hp->extern_fun = 0;
    char* str = *(char**)(esp_base + hp->off);
    *data = (DWORD)str;
    *len = strlen(str);
    *split = 0; // 8/3/2014 jichi: use return address as split
  }
  detect_offset = 1;
}

bool InsertWillPlusHook()
{
  //__debugbreak();
  enum { sub_esp = 0xec81 }; // caller pattern: sub esp = 0x81,0xec byte
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:WillPlus: function call not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.extern_fun = SpecialHookWillPlus;
  hp.type = USING_STRING|EXTERN_HOOK;
  ConsoleOutput("vnreng: INSERT WillPlus");
  NewHook(hp, L"WillPlus");
  //RegisterEngineType(ENGINE_WILLPLUS);
  return true;
}

/** jichi 9/14/2013
 *  TanukiSoft (*.tac)
 *
 *  Seems to be broken for new games in 2012 such like となりの
 *
 *  微少女: /HSN4@004983E0
 *  This is the same hook as ITH
 *  - addr: 4817888 (0x4983e0)
 *  - extern_fun: 0x0
 *  - off: 4
 *  - type: 1025 (0x401)
 *
 *  隣りのぷ～さん: /HSN-8@200FE7:TONARINO.EXE
 *  - addr: 2101223 (0x200fe7)
 *  - module: 2343491905 (0x8baed941)
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - type: 1089 (0x441)
 */
bool InsertTanukiHook()
{
  ConsoleOutput("vnreng: trying TanukiSoft");
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x8140)
      if (DWORD j = SafeFindEntryAligned(i, 0x400)) { // jichi 9/14/2013: might crash the game without admin priv
        //ITH_GROWL_DWORD2(i, j);
        HookParam hp = {};
        hp.addr = j;
        hp.off = 4;
        hp.type = USING_STRING | NO_CONTEXT;
        ConsoleOutput("vnreng: INSERT TanukiSoft");
        NewHook(hp, L"TanukiSoft");
        return true;
      }

  //ConsoleOutput("Unknown TanukiSoft engine.");
  ConsoleOutput("vnreng:TanukiSoft: failed");
  return false;
}
static void SpecialHookRyokucha(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  CC_UNUSED(split);
  const DWORD *base = (const DWORD *)esp_base;
  for (DWORD i = 1; i < 5; i++) {
    DWORD j = base[i];
    if ((j >> 16) == 0 && (j >> 8)) {
      hp->off = i << 2;
      *data = j;
      *len = 2;
      hp->type &= ~EXTERN_HOOK;
      hp->extern_fun = 0;
      return;
    }
  }
  *len = 0;
}
bool InsertRyokuchaDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetGlyphOutlineA)
    return false;
  bool flag;
  DWORD insert_addr;
  __asm
  {
    mov eax,fs:[0]
    mov eax,[eax]
    mov eax,[eax] //Step up SEH chain for 2 nodes.
    mov ecx,[eax + 0xC]
    mov eax,[eax + 4]
    add ecx,[ecx - 4]
    mov insert_addr,ecx
    cmp eax,[ecx + 3]
    sete al
    mov flag,al
  }
  if (flag) {
    HookParam hp = {};
    hp.addr = insert_addr;
    hp.length_offset = 1;
    hp.extern_fun = SpecialHookRyokucha;
    hp.type = BIG_ENDIAN|EXTERN_HOOK;
    ConsoleOutput("vnreng: INSERT StudioRyokucha");
    NewHook(hp, L"StudioRyokucha");
    return true;
  }
  //else ConsoleOutput("Unknown Ryokucha engine.");
  ConsoleOutput("vnreng:StudioRyokucha: failed");
  return true;
}
void InsertRyokuchaHook()
{
  //ConsoleOutput("Probably Ryokucha. Wait for text.");
  trigger_fun_ = InsertRyokuchaDynamicHook;
  SwitchTrigger(true);
  ConsoleOutput("vnreng: TRIGGER Ryokucha");
}

/**
 *  jichi 5/11/2014: Hook to the beginning of a function
 *
 *  Here's an example of Demonion II (reladdr = 0x18c540):
 *  The text is displayed character by character.
 *  sub_58C540 proc near
 *  arg_0 = dword ptr  8 // LPCSTR with 1 character
 *
 *  It's weird that I cannot find the caller of this function using OllyDbg.
 *
 *  0138C540  /$ 55             PUSH EBP
 *  0138C541  |. 8BEC           MOV EBP,ESP
 *  0138C543  |. 83E4 F8        AND ESP,0xFFFFFFF8
 *  0138C546  |. 8B43 0C        MOV EAX,DWORD PTR DS:[EBX+0xC]
 *  0138C549  |. 83EC 08        SUB ESP,0x8
 *  0138C54C  |. 56             PUSH ESI
 *  0138C54D  |. 57             PUSH EDI
 *  0138C54E  |. 85C0           TEST EAX,EAX
 *  0138C550  |. 75 04          JNZ SHORT demonion.0138C556
 *  0138C552  |. 33F6           XOR ESI,ESI
 *  0138C554  |. EB 18          JMP SHORT demonion.0138C56E
 *  0138C556  |> 8B4B 14        MOV ECX,DWORD PTR DS:[EBX+0x14]
 *  0138C559  |. 2BC8           SUB ECX,EAX
 *  0138C55B  |. B8 93244992    MOV EAX,0x92492493
 *  0138C560  |. F7E9           IMUL ECX
 *  0138C562  |. 03D1           ADD EDX,ECX
 *  0138C564  |. C1FA 04        SAR EDX,0x4
 *  0138C567  |. 8BF2           MOV ESI,EDX
 *  0138C569  |. C1EE 1F        SHR ESI,0x1F
 *  0138C56C  |. 03F2           ADD ESI,EDX
 *  0138C56E  |> 8B7B 10        MOV EDI,DWORD PTR DS:[EBX+0x10]
 *  0138C571  |. 8BCF           MOV ECX,EDI
 *  0138C573  |. 2B4B 0C        SUB ECX,DWORD PTR DS:[EBX+0xC]
 *  0138C576  |. B8 93244992    MOV EAX,0x92492493
 *  0138C57B  |. F7E9           IMUL ECX
 *  0138C57D  |. 03D1           ADD EDX,ECX
 *  0138C57F  |. C1FA 04        SAR EDX,0x4
 *  0138C582  |. 8BC2           MOV EAX,EDX
 *  0138C584  |. C1E8 1F        SHR EAX,0x1F
 *  0138C587  |. 03C2           ADD EAX,EDX
 *  0138C589  |. 3BC6           CMP EAX,ESI
 *  0138C58B  |. 73 2F          JNB SHORT demonion.0138C5BC
 *  0138C58D  |. C64424 08 00   MOV BYTE PTR SS:[ESP+0x8],0x0
 *  0138C592  |. 8B4C24 08      MOV ECX,DWORD PTR SS:[ESP+0x8]
 *  0138C596  |. 8B5424 08      MOV EDX,DWORD PTR SS:[ESP+0x8]
 *  0138C59A  |. 51             PUSH ECX
 *  0138C59B  |. 8B4D 08        MOV ECX,DWORD PTR SS:[EBP+0x8]
 *  0138C59E  |. 52             PUSH EDX
 *  0138C59F  |. B8 01000000    MOV EAX,0x1
 *  0138C5A4  |. 8BD7           MOV EDX,EDI
 *  0138C5A6  |. E8 F50E0000    CALL demonion.0138D4A0
 *  0138C5AB  |. 83C4 08        ADD ESP,0x8
 *  0138C5AE  |. 83C7 1C        ADD EDI,0x1C
 *  0138C5B1  |. 897B 10        MOV DWORD PTR DS:[EBX+0x10],EDI
 *  0138C5B4  |. 5F             POP EDI
 *  0138C5B5  |. 5E             POP ESI
 *  0138C5B6  |. 8BE5           MOV ESP,EBP
 *  0138C5B8  |. 5D             POP EBP
 *  0138C5B9  |. C2 0400        RETN 0x4
 *  0138C5BC  |> 397B 0C        CMP DWORD PTR DS:[EBX+0xC],EDI
 *  0138C5BF  |. 76 05          JBE SHORT demonion.0138C5C6
 *  0138C5C1  |. E8 1B060D00    CALL demonion.0145CBE1
 *  0138C5C6  |> 8B03           MOV EAX,DWORD PTR DS:[EBX]
 *  0138C5C8  |. 57             PUSH EDI                                 ; /Arg4
 *  0138C5C9  |. 50             PUSH EAX                                 ; |Arg3
 *  0138C5CA  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+0x8]           ; |
 *  0138C5CD  |. 50             PUSH EAX                                 ; |Arg2
 *  0138C5CE  |. 8D4C24 14      LEA ECX,DWORD PTR SS:[ESP+0x14]          ; |
 *  0138C5D2  |. 51             PUSH ECX                                 ; |Arg1
 *  0138C5D3  |. 8BC3           MOV EAX,EBX                              ; |
 *  0138C5D5  |. E8 D6010000    CALL demonion.0138C7B0                   ; \demonion.0138C7B0
 *  0138C5DA  |. 5F             POP EDI
 *  0138C5DB  |. 5E             POP ESI
 *  0138C5DC  |. 8BE5           MOV ESP,EBP
 *  0138C5DE  |. 5D             POP EBP
 *  0138C5DF  \. C2 0400        RETN 0x4
 */
bool InsertGXPHook()
{
  union {
    DWORD i;
    DWORD *id;
    BYTE *ib;
  };
  //__asm int 3
  for (i = module_base_ + 0x1000; i < module_limit_ - 4; i++) {
    //find cmp word ptr [esi*2+eax],0
    if (*id != 0x703c8366)
      continue;
    i += 4;
    if (*ib != 0)
      continue;
    i++;
    DWORD j = i + 0x200;
    j = j < (module_limit_ - 8) ? j : (module_limit_ - 8);

    DWORD flag = false;
    while (i < j) {
      DWORD k = disasm(ib);
      if (k == 0)
        break;
      if (k == 1 && (*ib & 0xf8) == 0x50) { // push reg
        flag = true;
        break;
      }
      i += k;
    }
    if (flag)
      while (i < j) {
        if (*ib == 0xe8) {
          i++;
          DWORD addr = *id + i + 4;
          if (addr > module_base_ && addr < module_limit_) {
            HookParam hp = {};
            hp.addr = addr;
            hp.type = USING_UNICODE | DATA_INDIRECT;
            hp.length_offset = 1;
            hp.off = 4;

            //ITH_GROWL_DWORD3(hp.addr, module_base_, hp.addr - module_base_);
            //DWORD call = Util::FindCallAndEntryAbs(hp.addr, module_limit_ - module_base_, module_base_, 0xec81); // zero
            //DWORD call = Util::FindCallAndEntryAbs(hp.addr, module_limit_ - module_base_, module_base_, 0xec83); // zero
            //DWORD call = Util::FindCallAndEntryAbs(hp.addr, module_limit_ - module_base_, module_base_, 0xec8b55); // zero
            //ITH_GROWL_DWORD3(call, module_base_, call - module_base_);

            ConsoleOutput("vnreng: INSERT GXP");
            NewHook(hp, L"GXP");
            return true;
          }
        }
        i++;
      }
  }
  //ConsoleOutput("Unknown GXP engine.");
  ConsoleOutput("vnreng:GXP: failed");
  return false;
}

namespace { // unnamed, for Anex86
BYTE JIS_tableH[0x80] = {
  0x00,0x81,0x81,0x82,0x82,0x83,0x83,0x84,
  0x84,0x85,0x85,0x86,0x86,0x87,0x87,0x88,
  0x88,0x89,0x89,0x8a,0x8a,0x8b,0x8b,0x8c,
  0x8c,0x8d,0x8d,0x8e,0x8e,0x8f,0x8f,0x90,
  0x90,0x91,0x91,0x92,0x92,0x93,0x93,0x94,
  0x94,0x95,0x95,0x96,0x96,0x97,0x97,0x98,
  0x98,0x99,0x99,0x9a,0x9a,0x9b,0x9b,0x9c,
  0x9c,0x9d,0x9d,0x9e,0x9e,0xdf,0xdf,0xe0,
  0xe0,0xe1,0xe1,0xe2,0xe2,0xe3,0xe3,0xe4,
  0xe4,0xe5,0xe5,0xe6,0xe6,0xe7,0xe7,0xe8,
  0xe8,0xe9,0xe9,0xea,0xea,0xeb,0xeb,0xec,
  0xec,0xed,0xed,0xee,0xee,0xef,0xef,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

BYTE JIS_tableL[0x80] = {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,
  0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,
  0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,
  0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,
  0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,
  0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
  0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,
  0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,
  0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
  0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
  0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
  0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x00,
};

void SpecialHookAnex86(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  __asm
  {
    mov eax, esp_base
    mov ecx, [eax - 0xC]
    cmp byte ptr [ecx + 0xE], 0
    jnz _fin
    movzx ebx, byte ptr [ecx + 0xC] ; Low byte
    movzx edx, byte ptr [ecx + 0xD] ; High byte
    test edx,edx
    jnz _jis_char
    mov eax,data
    mov [eax],ebx
    mov eax, len
    mov [eax], 1
    jmp _fin
_jis_char:
    cmp ebx,0x7E
    ja _fin
    cmp edx,0x7E
    ja _fin
    test dl,1
    lea eax, [ebx + 0x7E]
    movzx ecx, byte ptr [JIS_tableL + ebx]
    cmovnz eax, ecx
    mov ah, byte ptr [JIS_tableH + edx]
    ror ax,8
    mov ecx, data
    mov [ecx], eax
    mov ecx, len
    mov [ecx], 2
_fin:
  }

}
} // unnamed namespace
bool InsertAnex86Hook()
{
  const DWORD dwords[] = {0x618ac033,0x0d418a0c}; // jichi 12/25/2013: Remove static keyword
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 8; i++)
    if (*(DWORD *)i == dwords[0])
      if (*(DWORD *)(i + 4) == dwords[1]) {
        HookParam hp = {};
        hp.addr = i;
        hp.extern_fun = SpecialHookAnex86;
        hp.type = EXTERN_HOOK;
        hp.length_offset = 1;
        ConsoleOutput("vnreng: INSERT Anex86");
        NewHook(hp, L"Anex86");
        return true;
      }
  ConsoleOutput("vnreng:Anex86: failed");
  return false;
}
//static char* ShinyDaysQueueString[0x10];
//static int ShinyDaysQueueStringLen[0x10];
//static int ShinyDaysQueueIndex, ShinyDaysQueueNext;
static void SpecialHookShinyDays(DWORD esp_base, HookParam* hp, DWORD* data, DWORD* split, DWORD* len)
{
  static int ShinyDaysQueueStringLen;
  LPWSTR fun_str;
  char *text_str;
  DWORD l = 0;
  __asm
  {
    mov eax,esp_base
    mov ecx,[eax+0x4C]
    mov fun_str,ecx
    mov esi,[eax+0x70]
    mov edi,[eax+0x74]
    add esi,0x3C
    cmp esi,edi
    jae _no_text
    mov edx,[esi+0x10]
    mov ecx,esi
    cmp edx,8
    cmovae ecx,[ecx]
    add edx,edx
    mov text_str,ecx
    mov l,edx
_no_text:
  }
  if (::memcmp(fun_str, L"[PlayVoice]",0x18) == 0) {
    *data = (DWORD)text_buffer;
    *len = ShinyDaysQueueStringLen;
  }
  else if (::memcmp(fun_str, L"[PrintText]",0x18) == 0) {
    memcpy(text_buffer, text_str, l);
    ShinyDaysQueueStringLen = l;
  }
}
bool InsertShinyDaysHook()
{
  const BYTE bytes[] = {
    0xff,0x83,0x70,0x03,0x00,0x00,0x33,0xf6,
    0xc6,0x84,0x24,0x90,0x02,0x00,0x00,0x02
  };
  LPVOID addr = (LPVOID)0x42ad94;
  if (::memcmp(addr, bytes, sizeof(bytes)) != 0) {
    ConsoleOutput("vnreng:ShinyDays: only work for 1.00");
    return false;
  }

  HookParam hp = {};
  hp.addr = 0x42ad9c;
  hp.extern_fun = SpecialHookShinyDays;
  hp.type = USING_UNICODE | USING_STRING| EXTERN_HOOK | NO_CONTEXT;
  ConsoleOutput("vnreng: INSERT ShinyDays");
  NewHook(hp, L"ShinyDays 1.00");
  return true;
}

/**
 *  jichi 9/5/2013: NEXTON games with aInfo.db
 *  Sample games:
 *  - /HA-C@4D69E:InnocentBullet.exe (イノセントバレット)
 *  - /HA-C@40414C:ImoutoBancho.exe (妹番長)
 *
 *  See: http://ja.wikipedia.org/wiki/ネクストン
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2576241908
 *
 *  Old:
 *  md5 = 85ac031f2539e1827d9a1d9fbde4023d
 *  hcode = /HA-C@40414C:ImoutoBancho.exe
 *  - addr: 4211020 (0x40414c)
 *  - module: 1051997988 (0x3eb43724)
 *  - length_offset: 1
 *  - off: 4294967280 (0xfffffff0) = -0x10
 *  - split: 0
 *  - type: 68 (0x44)
 *
 *  New (11/7/2013):
 *  /HA-20:4@583DE:MN2.EXE (NEW)
 *  - addr: 361438 (0x583de)
 *  - module: 3436540819
 *  - length_offset: 1
 *  - off: 4294967260 (0xffffffdc) = -0x24
 *  - split: 4
 *  - type: 84 (0x54)
 */

bool InsertNextonHook()
{
  // 0x8944241885c00f84
  const BYTE bytes[] = {
    //0xe8 //??,??,??,??,      00804147   e8 24d90100      call imoutoba.00821a70
    0x89,0x44,0x24, 0x18,   // 0080414c   894424 18        mov dword ptr ss:[esp+0x18],eax; hook here
    0x85,0xc0,              // 00804150   85c0             test eax,eax
    0x0f,0x84               // 00804152  ^0f84 c0feffff    je imoutoba.00804018
  };
  //enum { hook_offset = 0 };
  ULONG addr = module_base_; //- sizeof(bytes);
  do {
    addr += sizeof(bytes); // ++ so that each time return diff address
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(bytes, sizeof(bytes), addr, addr + range);
    if (!addr) {
      ConsoleOutput("vnreng:NEXTON: pattern not exist");
      return false;
    }

    //const BYTE hook_ins[] = {
    //  0x57,       // 00804144   57               push edi
    //  0x8b,0xc3,  // 00804145   8bc3             mov eax,ebx
    //  0xe8 //??,??,??,??,      00804147   e8 24d90100      call imoutoba.00821a70
    //};
  } while(0xe8c38b57 != *(DWORD *)(addr - 8));

  //ITH_GROWL_DWORD3(module_base_, addr, *(DWORD *)(addr-8));

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  //hp.off = -0x10;
  //hp.type = BIG_ENDIAN; // 4

  // 魔王のくせに生イキだっ！2 ～今度は性戦だ！～
  // CheatEngine search for byte array: 8944241885C00F84
  //addr = 0x4583de; // wrong
  //addr = 0x5460ba;
  //addr = 0x5f3d8a;
  //addr = 0x768776;
  //addr = 0x7a5319;

  hp.off = -0x24;
  hp.split = 4;
  hp.type = BIG_ENDIAN|USING_SPLIT; // 0x54

  // Indirect is needed for new games,
  // Such as: /HA-C*0@4583DE for 「魔王のくせに生イキだっ！２」
  //hp.type = BIG_ENDIAN|DATA_INDIRECT; // 12
  //hp.type = USING_UNICODE;
  //ITH_GROWL_DWORD3(addr, -hp.off, hp.type);

  ConsoleOutput("vnreng: INSERT NEXTON");
  NewHook(hp, L"NEXTON");

  //ConsoleOutput("NEXTON");
  return true;
}

/** jichi 8/17/2014 Nexton1
 *  Sample games:
 *  - [Nomad][071026] 淫烙の巫女 Trial
 *
 *  Debug method: text are prefetched into memory. Add break point to it.
 *
 *  GetGlyphOutlineA is called, but no correct text.
 *
 *  There are so many good hooks. The shortest function was picked,as follows:
 *  0041974e   cc               int3
 *  0041974f   cc               int3
 *  00419750   56               push esi    ; jichi: hook here, text in arg1
 *  00419751   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
 *  00419755   8bc6             mov eax,esi
 *  00419757   57               push edi
 *  00419758   8d78 01          lea edi,dword ptr ds:[eax+0x1]
 *  0041975b   eb 03            jmp short inrakutr.00419760
 *  0041975d   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  00419760   8a10             mov dl,byte ptr ds:[eax]	; jichi: eax is the text
 *  00419762   83c0 01          add eax,0x1
 *  00419765   84d2             test dl,dl
 *  00419767  ^75 f7            jnz short inrakutr.00419760
 *  00419769   2bc7             sub eax,edi
 *  0041976b   50               push eax
 *  0041976c   56               push esi
 *  0041976d   83c1 04          add ecx,0x4
 *  00419770   e8 eb85feff      call inrakutr.00401d60
 *  00419775   5f               pop edi
 *  00419776   5e               pop esi
 *  00419777   c2 0400          retn 0x4
 *  0041977a   cc               int3
 *  0041977b   cc               int3
 *  0041977c   cc               int3
 *
 *  Runtime stack: this function takes two arguments. Text address is in arg1.
 *
 *  Other possible hooks are as follows:
 *  00460caf   53               push ebx
 *  00460cb0   c700 16000000    mov dword ptr ds:[eax],0x16
 *  00460cb6   e8 39feffff      call inrakutr.00460af4
 *  00460cbb   83c4 14          add esp,0x14
 *  00460cbe   385d fc          cmp byte ptr ss:[ebp-0x4],bl
 *  00460cc1   74 07            je short inrakutr.00460cca
 *  00460cc3   8b45 f8          mov eax,dword ptr ss:[ebp-0x8]
 *  00460cc6   8360 70 fd       and dword ptr ds:[eax+0x70],0xfffffffd
 *  00460cca   33c0             xor eax,eax
 *  00460ccc   eb 2c            jmp short inrakutr.00460cfa
 *  00460cce   0fb601           movzx eax,byte ptr ds:[ecx]	; jichi: here, ecx
 *  00460cd1   8b55 f4          mov edx,dword ptr ss:[ebp-0xc]
 *  00460cd4   f64410 1d 04     test byte ptr ds:[eax+edx+0x1d],0x4
 *  00460cd9   74 0e            je short inrakutr.00460ce9
 *  00460cdb   8d51 01          lea edx,dword ptr ds:[ecx+0x1]
 *  00460cde   381a             cmp byte ptr ds:[edx],bl
 *  00460ce0   74 07            je short inrakutr.00460ce9
 *  00460ce2   c1e0 08          shl eax,0x8
 *  00460ce5   8bf0             mov esi,eax
 *  00460ce7   8bca             mov ecx,edx
 *  00460ce9   0fb601           movzx eax,byte ptr ds:[ecx]
 *  00460cec   03c6             add eax,esi
 *  00460cee   385d fc          cmp byte ptr ss:[ebp-0x4],bl
 *  00460cf1   74 07            je short inrakutr.00460cfa
 *  00460cf3   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
 *  00460cf6   8361 70 fd       and dword ptr ds:[ecx+0x70],0xfffffffd
 *  00460cfa   5e               pop esi
 *  00460cfb   5b               pop ebx
 *  00460cfc   c9               leave
 *  00460cfd   c3               retn
 *
 *  00460d41   74 05            je short inrakutr.00460d48
 *  00460d43   381e             cmp byte ptr ds:[esi],bl
 *  00460d45   74 01            je short inrakutr.00460d48
 *  00460d47   46               inc esi
 *  00460d48   8bc6             mov eax,esi
 *  00460d4a   5e               pop esi
 *  00460d4b   5b               pop ebx
 *  00460d4c   c3               retn
 *  00460d4d   56               push esi
 *  00460d4e   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
 *  00460d52   0fb606           movzx eax,byte ptr ds:[esi]	; jichi: esi & ebp
 *  00460d55   50               push eax
 *  00460d56   e8 80fcffff      call inrakutr.004609db
 *  00460d5b   85c0             test eax,eax
 *  00460d5d   59               pop ecx
 *  00460d5e   74 0b            je short inrakutr.00460d6b
 *  00460d60   807e 01 00       cmp byte ptr ds:[esi+0x1],0x0
 *  00460d64   74 05            je short inrakutr.00460d6b
 *  00460d66   6a 02            push 0x2
 *  00460d68   58               pop eax
 *  00460d69   5e               pop esi
 *  00460d6a   c3               retn
 *
 *  00460d1d   53               push ebx
 *  00460d1e   53               push ebx
 *  00460d1f   53               push ebx
 *  00460d20   53               push ebx
 *  00460d21   53               push ebx
 *  00460d22   c700 16000000    mov dword ptr ds:[eax],0x16
 *  00460d28   e8 c7fdffff      call inrakutr.00460af4
 *  00460d2d   83c4 14          add esp,0x14
 *  00460d30   33c0             xor eax,eax
 *  00460d32   eb 16            jmp short inrakutr.00460d4a
 *  00460d34   0fb606           movzx eax,byte ptr ds:[esi]	; jichi: esi, ebp
 *  00460d37   50               push eax
 *  00460d38   e8 9efcffff      call inrakutr.004609db
 *  00460d3d   46               inc esi
 *  00460d3e   85c0             test eax,eax
 *  00460d40   59               pop ecx
 *  00460d41   74 05            je short inrakutr.00460d48
 *  00460d43   381e             cmp byte ptr ds:[esi],bl
 *  00460d45   74 01            je short inrakutr.00460d48
 *  00460d47   46               inc esi
 *
 *  0042c59f   cc               int3
 *  0042c5a0   56               push esi
 *  0042c5a1   8bf1             mov esi,ecx
 *  0042c5a3   8b86 cc650000    mov eax,dword ptr ds:[esi+0x65cc]
 *  0042c5a9   8b50 1c          mov edx,dword ptr ds:[eax+0x1c]
 *  0042c5ac   57               push edi
 *  0042c5ad   8b7c24 0c        mov edi,dword ptr ss:[esp+0xc]
 *  0042c5b1   8d8e cc650000    lea ecx,dword ptr ds:[esi+0x65cc]
 *  0042c5b7   57               push edi
 *  0042c5b8   ffd2             call edx
 *  0042c5ba   8bc7             mov eax,edi
 *  0042c5bc   8d50 01          lea edx,dword ptr ds:[eax+0x1]
 *  0042c5bf   90               nop
 *  0042c5c0   8a08             mov cl,byte ptr ds:[eax]	; jichi: here eax
 *  0042c5c2   83c0 01          add eax,0x1
 *  0042c5c5   84c9             test cl,cl
 *  0042c5c7  ^75 f7            jnz short inrakutr.0042c5c0
 *  0042c5c9   2bc2             sub eax,edx
 *  0042c5cb   50               push eax
 *  0042c5cc   57               push edi
 *  0042c5cd   8d8e 24660000    lea ecx,dword ptr ds:[esi+0x6624]
 *  0042c5d3   e8 8857fdff      call inrakutr.00401d60
 *  0042c5d8   8b86 b4660000    mov eax,dword ptr ds:[esi+0x66b4]
 *  0042c5de   85c0             test eax,eax
 *  0042c5e0   74 0d            je short inrakutr.0042c5ef
 *  0042c5e2   8b8e b8660000    mov ecx,dword ptr ds:[esi+0x66b8]
 *  0042c5e8   2bc8             sub ecx,eax
 *  0042c5ea   c1f9 02          sar ecx,0x2
 *  0042c5ed   75 05            jnz short inrakutr.0042c5f4
 *  0042c5ef   e8 24450300      call inrakutr.00460b18
 *  0042c5f4   8b96 b4660000    mov edx,dword ptr ds:[esi+0x66b4]
 *  0042c5fa   8b0a             mov ecx,dword ptr ds:[edx]
 *  0042c5fc   8b01             mov eax,dword ptr ds:[ecx]
 *  0042c5fe   8b50 30          mov edx,dword ptr ds:[eax+0x30]
 *  0042c601   ffd2             call edx
 *  0042c603   8b06             mov eax,dword ptr ds:[esi]
 *  0042c605   8b90 f8000000    mov edx,dword ptr ds:[eax+0xf8]
 *  0042c60b   6a 00            push 0x0
 *  0042c60d   68 c3164a00      push inrakutr.004a16c3
 *  0042c612   57               push edi
 *  0042c613   8bce             mov ecx,esi
 *  0042c615   ffd2             call edx
 *  0042c617   5f               pop edi
 *  0042c618   5e               pop esi
 *  0042c619   c2 0400          retn 0x4
 *  0042c61c   cc               int3
 *
 *  0041974e   cc               int3
 *  0041974f   cc               int3
 *  00419750   56               push esi
 *  00419751   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
 *  00419755   8bc6             mov eax,esi
 *  00419757   57               push edi
 *  00419758   8d78 01          lea edi,dword ptr ds:[eax+0x1]
 *  0041975b   eb 03            jmp short inrakutr.00419760
 *  0041975d   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  00419760   8a10             mov dl,byte ptr ds:[eax]	; jichi: eax
 *  00419762   83c0 01          add eax,0x1
 *  00419765   84d2             test dl,dl
 *  00419767  ^75 f7            jnz short inrakutr.00419760
 *  00419769   2bc7             sub eax,edi
 *  0041976b   50               push eax
 *  0041976c   56               push esi
 *  0041976d   83c1 04          add ecx,0x4
 *  00419770   e8 eb85feff      call inrakutr.00401d60
 *  00419775   5f               pop edi
 *  00419776   5e               pop esi
 *  00419777   c2 0400          retn 0x4
 *  0041977a   cc               int3
 *  0041977b   cc               int3
 *  0041977c   cc               int3
 *
 *  0042c731   57               push edi
 *  0042c732   ffd0             call eax
 *  0042c734   8bc7             mov eax,edi
 *  0042c736   8d50 01          lea edx,dword ptr ds:[eax+0x1]
 *  0042c739   8da424 00000000  lea esp,dword ptr ss:[esp]
 *  0042c740   8a08             mov cl,byte ptr ds:[eax]	; jichi: eax
 *  0042c742   83c0 01          add eax,0x1
 *  0042c745   84c9             test cl,cl
 *  0042c747  ^75 f7            jnz short inrakutr.0042c740
 *  0042c749   2bc2             sub eax,edx
 *  0042c74b   8bf8             mov edi,eax
 *  0042c74d   e8 fe1d0100      call inrakutr.0043e550
 *  0042c752   8b0d 187f4c00    mov ecx,dword ptr ds:[0x4c7f18]
 *  0042c758   8b11             mov edx,dword ptr ds:[ecx]
 *  0042c75a   8b42 70          mov eax,dword ptr ds:[edx+0x70]
 *  0042c75d   ffd0             call eax
 *  0042c75f   83c0 0a          add eax,0xa
 *  0042c762   0fafc7           imul eax,edi
 *  0042c765   5f               pop edi
 *  0042c766   8986 60660000    mov dword ptr ds:[esi+0x6660],eax
 */
bool InsertNexton1Hook()
{
  // Use accurate stopAddress in case of running out of memory
  // Since the file pattern for Nexton1 is not accurate.
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) {
    ConsoleOutput("vnreng:NEXTON1: failed to get memory range");
    return false;
  }
  const BYTE bytes[] = {
    0x56,                  // 00419750   56               push esi    ; jichi: hook here, text in arg1
    0x8b,0x74,0x24, 0x08,  // 00419751   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
    0x8b,0xc6,             // 00419755   8bc6             mov eax,esi
    0x57,                  // 00419757   57               push edi
    0x8d,0x78, 0x01,       // 00419758   8d78 01          lea edi,dword ptr ds:[eax+0x1]
    0xeb, 0x03,            // 0041975b   eb 03            jmp short inrakutr.00419760
    0x8d,0x49, 0x00,       // 0041975d   8d49 00          lea ecx,dword ptr ds:[ecx]
    0x8a,0x10,             // 00419760   8a10             mov dl,byte ptr ds:[eax]	; jichi: eax is the text
    0x83,0xc0, 0x01,       // 00419762   83c0 01          add eax,0x1
    0x84,0xd2,             // 00419765   84d2             test dl,dl
    0x75, 0xf7,            // 00419767  ^75 f7            jnz short inrakutr.00419760
    0x2b,0xc7,             // 00419769   2bc7             sub eax,edi
    0x50,                  // 0041976b   50               push eax
    0x56,                  // 0041976c   56               push esi
    0x83,0xc1, 0x04        // 0041976d   83c1 04          add ecx,0x4
    //0xe8, XX4,           // 00419770   e8 eb85feff      call inrakutr.00401d60
    //0x5f,                // 00419775   5f               pop edi
    //0x5e,                // 00419776   5e               pop esi
    //0xc2, 0x04,0x00      // 00419777   c2 0400          retn 0x4
  };
  enum { hook_offset = 0 }; // distance to the beginning of the function
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), startAddress, stopAddress);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:NEXTON1: pattern not found");
    return false;
  }
  //ITH_GROWL_DWORD(addr);

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.length_offset = 1;
  hp.off = 4; // [esp+4] == arg0
  hp.type = USING_STRING;
  ConsoleOutput("vnreng: INSERT NEXTON1");
  NewHook(hp, L"NEXTON1");
  return true;
}

/**
 *  jichi 9/16/2013: a-unicorn / gesen18
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2586681823
 *  Pattern: 2bce8bf8
 *      2bce      sub ecx,esi ; hook here
 *      8bf8      mov eds,eax
 *      8bd1      mov edx,ecx
 *
 *  /HBN-20*0@xxoo
 *  - length_offset: 1
 *  - off: 4294967260 (0xffffffdc)
 *  - type: 1032 (0x408)
 */
bool InsertGesen18Hook()
{
  const BYTE bytes[] = {
    0x2b,0xce,  // sub ecx,esi ; hook here
    0x8b,0xf8   // mov eds,eax
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) {
    ConsoleOutput("vnreng:Gesen18: pattern not exist");
    return false;
  }

  HookParam hp = {};
  hp.type = NO_CONTEXT | DATA_INDIRECT;
  hp.length_offset = 1;
  hp.off = -0x24;
  hp.addr = addr;

  //index = SearchPattern(module_base_, size,ins, sizeof(ins));
  //ITH_GROWL_DWORD2(base, index);

  ConsoleOutput("vnreng: INSERT Gesen18");
  NewHook(hp, L"Gesen18");
  //ConsoleOutput("Gesen18");
  return true;
}

/**
 *  jichi 10/1/2013: Artemis Engine
 *  See: http://www.ies-net.com/
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2625537737
 *  Pattern:
 *     650a2f 83c4 0c   add esp,0xc ; hook here
 *     650a32 0fb6c0    movzx eax,al
 *     650a35 85c0      test eax,eax
 *     0fb6c0 75 0e     jnz short tsugokaz.0065a47
 *
 *  Wrong: 0x400000 + 0x7c574
 *
 *  //Example: [130927]妹スパイラル /HBN-8*0:14@65589F
 *  Example: ツゴウノイイ家族 Trial /HBN-8*0:14@650A2F
 *  Note: 0x650a2f > 40000(base) + 20000(limit)
 *  - addr: 0x650a2f
 *  - extern_fun: 0x0
 *  - function: 0
 *  - hook_len: 0
 *  - ind: 0
 *  - length_offset: 1
 *  - module: 0
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - recover_len: 0
 *  - split: 20 = 0x14
 *  - split_ind: 0
 *  - type: 1048 = 0x418
 *
 *  @CaoNiMaGeBi:
 *  RECENT GAMES:
 *    [130927]妹スパイラル /HBN-8*0:14@65589F
 *    [130927]サムライホルモン
 *    [131025]ツゴウノイイ家族 /HBN-8*0:14@650A2F (for trial version)
 *    CLIENT ORGANIZAIONS:
 *    CROWD
 *    D:drive.
 *    Hands-Aid Corporation
 *    iMel株式会社
 *    SHANNON
 *    SkyFish
 *    SNACK-FACTORY
 *    team flap
 *    Zodiac
 *    くらむちゃうだ～
 *    まかろんソフト
 *    アイディアファクトリー株式会社
 *    カラクリズム
 *    合资会社ファーストリーム
 *    有限会社ウルクスへブン
 *    有限会社ロータス
 *    株式会社CUCURI
 *    株式会社アバン
 *    株式会社インタラクティブブレインズ
 *    株式会社ウィンディール
 *    株式会社エヴァンジェ
 *    株式会社ポニーキャニオン
 *    株式会社大福エンターテインメント
 */
bool InsertArtemisHook()
{
  const BYTE bytes[] = {
    0x83,0xc4, 0x0c, // add esp,0xc ; hook here
    0x0f,0xb6,0xc0,  // movzx eax,al
    0x85,0xc0,       // test eax,eax
    0x75, 0x0e       // jnz XXOO ; it must be 0xe, or there will be duplication
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD3(reladdr, module_base_, range);
  if (!addr) {
    ConsoleOutput("vnreng:Artemis: pattern not exist");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.off = -0xc;
  hp.split = 0x14;
  hp.type = NO_CONTEXT|DATA_INDIRECT|USING_SPLIT; // 0x418

  //hp.addr = 0x650a2f;
  //ITH_GROWL_DWORD(hp.addr);

  ConsoleOutput("vnreng: INSERT Artemis");
  NewHook(hp, L"Artemis");
  //ConsoleOutput("Artemis");
  return true;
}

/**
 *  jichi 1/2/2014: Taskforce2 Engine
 *
 *  Examples:
 *  神様(仮)-カミサマカッコカリ- 路地裏繚乱編 (1.1)
 *  /HS-8@178872:Taskforce2.exe
 *
 *  00578819   . 50             push eax                                 ; |arg1
 *  0057881a   . c745 f4 cc636b>mov dword ptr ss:[ebp-0xc],taskforc.006b>; |
 *  00578821   . e8 31870000    call taskforc.00580f57                   ; \taskforc.00580f57
 *  00578826   . cc             int3
 *  00578827  /$ 8b4c24 04      mov ecx,dword ptr ss:[esp+0x4]
 *  0057882b  |. 53             push ebx
 *  0057882c  |. 33db           xor ebx,ebx
 *  0057882e  |. 3bcb           cmp ecx,ebx
 *  00578830  |. 56             push esi
 *  00578831  |. 57             push edi
 *  00578832  |. 74 08          je short taskforc.0057883c
 *  00578834  |. 8b7c24 14      mov edi,dword ptr ss:[esp+0x14]
 *  00578838  |. 3bfb           cmp edi,ebx
 *  0057883a  |. 77 1b          ja short taskforc.00578857
 *  0057883c  |> e8 28360000    call taskforc.0057be69
 *  00578841  |. 6a 16          push 0x16
 *  00578843  |. 5e             pop esi
 *  00578844  |. 8930           mov dword ptr ds:[eax],esi
 *  00578846  |> 53             push ebx
 *  00578847  |. 53             push ebx
 *  00578848  |. 53             push ebx
 *  00578849  |. 53             push ebx
 *  0057884a  |. 53             push ebx
 *  0057884b  |. e8 6a050000    call taskforc.00578dba
 *  00578850  |. 83c4 14        add esp,0x14
 *  00578853  |. 8bc6           mov eax,esi
 *  00578855  |. eb 31          jmp short taskforc.00578888
 *  00578857  |> 8b7424 18      mov esi,dword ptr ss:[esp+0x18]
 *  0057885b  |. 3bf3           cmp esi,ebx
 *  0057885d  |. 75 04          jnz short taskforc.00578863
 *  0057885f  |. 8819           mov byte ptr ds:[ecx],bl
 *  00578861  |.^eb d9          jmp short taskforc.0057883c
 *  00578863  |> 8bd1           mov edx,ecx
 *  00578865  |> 8a06           /mov al,byte ptr ds:[esi]
 *  00578867  |. 8802           |mov byte ptr ds:[edx],al
 *  00578869  |. 42             |inc edx
 *  0057886a  |. 46             |inc esi
 *  0057886b  |. 3ac3           |cmp al,bl
 *  0057886d  |. 74 03          |je short taskforc.00578872
 *  0057886f  |. 4f             |dec edi
 *  00578870  |.^75 f3          \jnz short taskforc.00578865
 *  00578872  |> 3bfb           cmp edi,ebx ; jichi: hook here
 *  00578874  |. 75 10          jnz short taskforc.00578886
 *  00578876  |. 8819           mov byte ptr ds:[ecx],bl
 *  00578878  |. e8 ec350000    call taskforc.0057be69
 *  0057887d  |. 6a 22          push 0x22
 *  0057887f  |. 59             pop ecx
 *  00578880  |. 8908           mov dword ptr ds:[eax],ecx
 *  00578882  |. 8bf1           mov esi,ecx
 *  00578884  |.^eb c0          jmp short taskforc.00578846
 *  00578886  |> 33c0           xor eax,eax
 *  00578888  |> 5f             pop edi
 *  00578889  |. 5e             pop esi
 *  0057888a  |. 5b             pop ebx
 *  0057888b  \. c3             retn
 *
 *  [131129] [Digital Cute] オトメスイッチ -OtomeSwitch- ～彼が持ってる彼女のリモコン～ (1.1)
 *  /HS-8@1948E9:Taskforce2.exe
 *  - addr: 0x1948e9
 *  - off: 4294967284 (0xfffffff4 = -0xc)
 *  - type: 65  (0x41)
 *
 *  00594890   . 50             push eax                                 ; |arg1
 *  00594891   . c745 f4 64c56d>mov dword ptr ss:[ebp-0xc],taskforc.006d>; |
 *  00594898   . e8 88880000    call taskforc.0059d125                   ; \taskforc.0059d125
 *  0059489d   . cc             int3
 *  0059489e  /$ 8b4c24 04      mov ecx,dword ptr ss:[esp+0x4]
 *  005948a2  |. 53             push ebx
 *  005948a3  |. 33db           xor ebx,ebx
 *  005948a5  |. 3bcb           cmp ecx,ebx
 *  005948a7  |. 56             push esi
 *  005948a8  |. 57             push edi
 *  005948a9  |. 74 08          je short taskforc.005948b3
 *  005948ab  |. 8b7c24 14      mov edi,dword ptr ss:[esp+0x14]
 *  005948af  |. 3bfb           cmp edi,ebx
 *  005948b1  |. 77 1b          ja short taskforc.005948ce
 *  005948b3  |> e8 91350000    call taskforc.00597e49
 *  005948b8  |. 6a 16          push 0x16
 *  005948ba  |. 5e             pop esi
 *  005948bb  |. 8930           mov dword ptr ds:[eax],esi
 *  005948bd  |> 53             push ebx
 *  005948be  |. 53             push ebx
 *  005948bf  |. 53             push ebx
 *  005948c0  |. 53             push ebx
 *  005948c1  |. 53             push ebx
 *  005948c2  |. e8 7e010000    call taskforc.00594a45
 *  005948c7  |. 83c4 14        add esp,0x14
 *  005948ca  |. 8bc6           mov eax,esi
 *  005948cc  |. eb 31          jmp short taskforc.005948ff
 *  005948ce  |> 8b7424 18      mov esi,dword ptr ss:[esp+0x18]
 *  005948d2  |. 3bf3           cmp esi,ebx
 *  005948d4  |. 75 04          jnz short taskforc.005948da
 *  005948d6  |. 8819           mov byte ptr ds:[ecx],bl
 *  005948d8  |.^eb d9          jmp short taskforc.005948b3
 *  005948da  |> 8bd1           mov edx,ecx
 *  005948dc  |> 8a06           /mov al,byte ptr ds:[esi]
 *  005948de  |. 8802           |mov byte ptr ds:[edx],al
 *  005948e0  |. 42             |inc edx
 *  005948e1  |. 46             |inc esi
 *  005948e2  |. 3ac3           |cmp al,bl
 *  005948e4  |. 74 03          |je short taskforc.005948e9
 *  005948e6  |. 4f             |dec edi
 *  005948e7  |.^75 f3          \jnz short taskforc.005948dc
 *  005948e9  |> 3bfb           cmp edi,ebx ; jichi: hook here
 *  005948eb  |. 75 10          jnz short taskforc.005948fd
 *  005948ed  |. 8819           mov byte ptr ds:[ecx],bl
 *  005948ef  |. e8 55350000    call taskforc.00597e49
 *  005948f4  |. 6a 22          push 0x22
 *  005948f6  |. 59             pop ecx
 *  005948f7  |. 8908           mov dword ptr ds:[eax],ecx
 *  005948f9  |. 8bf1           mov esi,ecx
 *  005948fb  |.^eb c0          jmp short taskforc.005948bd
 *  005948fd  |> 33c0           xor eax,eax
 *  005948ff  |> 5f             pop edi
 *  00594900  |. 5e             pop esi
 *  00594901  |. 5b             pop ebx
 *  00594902  \. c3             retn
 *
 *  Use this if that hook fails, try this one for future engines:
 *  /HS0@44CADA
 */
bool InsertTaskforce2Hook()
{
  const BYTE bytes[] = {
    0x88,0x02,  // 005948de  |. 8802           |mov byte ptr ds:[edx],al
    0x42,       // 005948e0  |. 42             |inc edx
    0x46,       // 005948e1  |. 46             |inc esi
    0x3a,0xc3,  // 005948e2  |. 3ac3           |cmp al,bl
    0x74, 0x03, // 005948e4  |. 74 03          |je short taskforc.005948e9
    0x4f,       // 005948e6  |. 4f             |dec edi
    0x75, 0xf3, // 005948e7  |.^75 f3          \jnz short taskforc.005948dc
    0x3b,0xfb   // 005948e9  |> 3bfb           cmp edi,ebx ; jichi: hook here
  };
  enum { hook_offset = sizeof(bytes) - 2 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD3(reladdr, module_base_, range);
  if (!addr) {
    ConsoleOutput("vnreng:Taskforce2: pattern not exist");
    //return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = -0xc;
  hp.type = BIG_ENDIAN|USING_STRING; // 0x41

  //ITH_GROWL_DWORD(hp.addr);
  //hp.addr = 0x1948e9 + module_base_;

  ConsoleOutput("vnreng: INSERT Taskforce2");
  NewHook(hp, L"Taskforce2");
  return true;
}

namespace { // unnamed Rejet
/**
 *  jichi 12/22/2013: Rejet
 *  See (CaoNiMaGeBi): http://www.hongfire.com/forum/printthread.php?t=36807&pp=40&page=172
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2506179113
 *  Pattern: 2bce8bf8
 *      2bce      sub ecx,esi ; hook here
 *      8bf8      mov eds,eax
 *      8bd1      mov edx,ecx
 *
 *  Examples:
 *  - Type1: ドットカレシ-We're 8bit Lovers!: /HBN-4*0@A5332:DotKareshi.exe
 *    length_offset: 1
 *    off: 0xfffffff8 (-0x8)
 *    type: 1096 (0x448)
 *
 *    module_base_ = 10e0000 (variant)
 *    hook_addr = module_base_ + reladdr = 0xe55332
 *    01185311   . FFF0           PUSH EAX  ; beginning of a new function
 *    01185313   . 0FC111         XADD DWORD PTR DS:[ECX],EDX
 *    01185316   . 4A             DEC EDX
 *    01185317   . 85D2           TEST EDX,EDX
 *    01185319   . 0F8F 45020000  JG DotKares.01185564
 *    0118531F   . 8B08           MOV ECX,DWORD PTR DS:[EAX]
 *    01185321   . 8B11           MOV EDX,DWORD PTR DS:[ECX]
 *    01185323   . 50             PUSH EAX
 *    01185324   . 8B42 04        MOV EAX,DWORD PTR DS:[EDX+0x4]
 *    01185327   . FFD0           CALL EAX
 *    01185329   . E9 36020000    JMP DotKares.01185564
 *    0118532E   . 8B7424 20      MOV ESI,DWORD PTR SS:[ESP+0x20]
 *    01185332   . E8 99A9FBFF    CALL DotKares.0113FCD0    ; hook here
 *    01185337   . 8BF0           MOV ESI,EAX
 *    01185339   . 8D4C24 14      LEA ECX,DWORD PTR SS:[ESP+0x14]
 *    0118533D   . 3BF7           CMP ESI,EDI
 *    0118533F   . 0F84 1A020000  JE DotKares.0118555F
 *    01185345   . 51             PUSH ECX                                 ; /Arg2
 *    01185346   . 68 E4FE5501    PUSH DotKares.0155FEE4                   ; |Arg1 = 0155FEE4
 *    0118534B   . E8 1023F9FF    CALL DotKares.01117660                   ; \DotKares.00377660
 *    01185350   . 83C4 08        ADD ESP,0x8
 *    01185353   . 84C0           TEST AL,AL
 *
 *  - Type2: ドットカレシ-We're 8bit Lovers! II: /HBN-8*0@A7AF9:dotkareshi.exe
 *    off: 4294967284 (0xfffffff4 = -0xc)
 *    length_offset: 1
 *    type: 1096 (0x448)
 *
 *    module_base_: 0x12b0000
 *
 *    01357ad2   . fff0           push eax ; beginning of a new function
 *    01357ad4   . 0fc111         xadd dword ptr ds:[ecx],edx
 *    01357ad7   . 4a             dec edx
 *    01357ad8   . 85d2           test edx,edx
 *    01357ada   . 7f 0a          jg short dotkares.01357ae6
 *    01357adc   . 8b08           mov ecx,dword ptr ds:[eax]
 *    01357ade   . 8b11           mov edx,dword ptr ds:[ecx]
 *    01357ae0   . 50             push eax
 *    01357ae1   . 8b42 04        mov eax,dword ptr ds:[edx+0x4]
 *    01357ae4   . ffd0           call eax
 *    01357ae6   > 8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
 *    01357aea   . 33ff           xor edi,edi
 *    01357aec   . 3979 f4        cmp dword ptr ds:[ecx-0xc],edi
 *    01357aef   . 0f84 1e020000  je dotkares.01357d13
 *    01357af5   . 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *    01357af9   . e8 7283fbff    call dotkares.0130fe70    ; jichi: hook here
 *    01357afe   . 8bf0           mov esi,eax
 *    01357b00   . 3bf7           cmp esi,edi
 *    01357b02   . 0f84 0b020000  je dotkares.01357d13
 *    01357b08   . 8d5424 14      lea edx,dword ptr ss:[esp+0x14]
 *    01357b0c   . 52             push edx                                 ; /arg2
 *    01357b0d   . 68 cc9f7501    push dotkares.01759fcc                   ; |arg1 = 01759fcc
 *    01357b12   . e8 e9f9f8ff    call dotkares.012e7500                   ; \dotkares.012c7500
 *    01357b17   . 83c4 08        add esp,0x8
 *    01357b1a   . 84c0           test al,al
 *    01357b1c   . 74 1d          je short dotkares.01357b3b
 *    01357b1e   . 8d46 64        lea eax,dword ptr ds:[esi+0x64]
 *    01357b21   . e8 bad0f8ff    call dotkares.012e4be0
 *    01357b26   . 68 28a17501    push dotkares.0175a128                   ; /arg1 = 0175a128 ascii "<br>"
 *
 *  - Type2: Tiny×MACHINEGUN: /HBN-8*0@4CEB8:TinyMachinegun.exe
 *    module_base_: 0x12f0000
 *    There are two possible places to hook
 *
 *    0133cea0   . fff0           push eax ; beginning of a new function
 *    0133cea2   . 0fc111         xadd dword ptr ds:[ecx],edx
 *    0133cea5   . 4a             dec edx
 *    0133cea6   . 85d2           test edx,edx
 *    0133cea8   . 7f 0a          jg short tinymach.0133ceb4
 *    0133ceaa   . 8b08           mov ecx,dword ptr ds:[eax]
 *    0133ceac   . 8b11           mov edx,dword ptr ds:[ecx]
 *    0133ceae   . 50             push eax
 *    0133ceaf   . 8b42 04        mov eax,dword ptr ds:[edx+0x4]
 *    0133ceb2   . ffd0           call eax
 *    0133ceb4   > 8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
 *    0133ceb8   . 33db           xor ebx,ebx               ; jichi: hook here
 *    0133ceba   . 3959 f4        cmp dword ptr ds:[ecx-0xc],ebx
 *    0133cebd   . 0f84 d4010000  je tinymach.0133d097
 *    0133cec3   . 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *    0133cec7   . e8 f4f90100    call tinymach.0135c8c0     ; jichi: or hook here
 *    0133cecc   . 8bf0           mov esi,eax
 *    0133cece   . 3bf3           cmp esi,ebx
 *    0133ced0   . 0f84 c1010000  je tinymach.0133d097
 *    0133ced6   . 8d5424 14      lea edx,dword ptr ss:[esp+0x14]
 *    0133ceda   . 52             push edx                                 ; /arg2
 *    0133cedb   . 68 44847d01    push tinymach.017d8444                   ; |arg1 = 017d8444
 *    0133cee0   . e8 eb5bfdff    call tinymach.01312ad0                   ; \tinymach.011b2ad0
 *
 *  - Type 3: 剣が君: /HBN-8*0@B357D:KenGaKimi.exe
 *
 *    01113550   . fff0           push eax
 *    01113552   . 0fc111         xadd dword ptr ds:[ecx],edx
 *    01113555   . 4a             dec edx
 *    01113556   . 85d2           test edx,edx
 *    01113558   . 7f 0a          jg short kengakim.01113564
 *    0111355a   . 8b08           mov ecx,dword ptr ds:[eax]
 *    0111355c   . 8b11           mov edx,dword ptr ds:[ecx]
 *    0111355e   . 50             push eax
 *    0111355f   . 8b42 04        mov eax,dword ptr ds:[edx+0x4]
 *    01113562   . ffd0           call eax
 *    01113564     8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
 *    01113568     33ff           xor edi,edi
 *    0111356a     3979 f4        cmp dword ptr ds:[ecx-0xc],edi
 *    0111356d     0f84 09020000  je kengakim.0111377c
 *    01113573     8d5424 14      lea edx,dword ptr ss:[esp+0x14]
 *    01113577     52             push edx
 *    01113578     68 dc6a5401    push kengakim.01546adc
 *    0111357d     e8 3eaff6ff    call kengakim.0107e4c0    ; hook here
 */
bool FindRejetHook(LPCVOID pattern, DWORD pattern_size, DWORD hook_off, DWORD hp_off, LPCWSTR hp_name = L"Rejet")
{
  // Offset to the function call from the beginning of the function
  //enum { hook_offset = 0x21 }; // Type1: hex(0x01185332-0x01185311)
  //const BYTE pattern[] = {    // Type1: Function start
  //  0xff,0xf0,      // 01185311   . fff0           push eax  ; beginning of a new function
  //  0x0f,0xc1,0x11, // 01185313   . 0fc111         xadd dword ptr ds:[ecx],edx
  //  0x4a,           // 01185316   . 4a             dec edx
  //  0x85,0xd2,      // 01185317   . 85d2           test edx,edx
  //  0x0f,0x8f       // 01185319   . 0f8f 45020000  jg DotKares.01185564
  //};
  //ITH_GROWL_DWORD(module_base_);
  ULONG addr = module_base_; //- sizeof(pattern);
  do {
    //addr += sizeof(pattern); // ++ so that each time return diff address
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(pattern, pattern_size, addr, addr + range);
    if (!addr) {
      //ITH_MSG(L"failed");
      ConsoleOutput("vnreng:Rejet: pattern not found");
      return false;
    }

    addr += hook_off;
    //ITH_GROWL_DWORD(addr);
    //ITH_GROWL_DWORD(*(DWORD *)(addr-3));
    //const BYTE hook_ins[] = {
    //  /*0x8b,*/0x74,0x24, 0x20,  //    mov esi,dword ptr ss:[esp+0x20]
    //  0xe8 //??,??,??,??, 01357af9  e8 7283fbff call DotKares.0130fe70 ; jichi: hook here
    //};
  } while(0xe8202474 != *(DWORD *)(addr - 3));

  ConsoleOutput("vnreng: INSERT Rejet");
  HookParam hp = {};
  hp.addr = addr; //- 0xf;
  hp.type = NO_CONTEXT|DATA_INDIRECT|FIXING_SPLIT;
  hp.length_offset = 1;
  hp.off = hp_off;
  //hp.off = -0x8; // Type1
  //hp.off = -0xc; // Type2

  NewHook(hp, hp_name);
  return true;
}
bool InsertRejetHook1() // This type of hook has varied hook address
{
  const BYTE bytes[] = {  // Type1: Function start
    0xff,0xf0,          // 01185311   . fff0           push eax  ; beginning of a new function
    0x0f,0xc1,0x11,     // 01185313   . 0fc111         xadd dword ptr ds:[ecx],edx
    0x4a,               // 01185316   . 4a             dec edx
    0x85,0xd2,          // 01185317   . 85d2           test edx,edx
    0x0f,0x8f           // 01185319   . 0f8f 45020000  jg DotKares.01185564
  };
  // Offset to the function call from the beginning of the function
  enum { hook_offset = 0x21 }; // Type1: hex(0x01185332-0x01185311)
  enum { hp_off = -0x8 }; // hook parameter
  return FindRejetHook(bytes, sizeof(bytes), hook_offset, hp_off);
}
bool InsertRejetHook2() // This type of hook has static hook address
{
  const BYTE bytes[] = {   // Type2 Function start
    0xff,0xf0,           //   01357ad2   fff0           push eax
    0x0f,0xc1,0x11,      //   01357ad4   0fc111         xadd dword ptr ds:[ecx],edx
    0x4a,                //   01357ad7   4a             dec edx
    0x85,0xd2,           //   01357ad8   85d2           test edx,edx
    0x7f, 0x0a,          //   01357ada   7f 0a          jg short DotKares.01357ae6
    0x8b,0x08,           //   01357adc   8b08           mov ecx,dword ptr ds:[eax]
    0x8b,0x11,           //   01357ade   8b11           mov edx,dword ptr ds:[ecx]
    0x50,                //   01357ae0   50             push eax
    0x8b,0x42, 0x04,     //   01357ae1   8b42 04        mov eax,dword ptr ds:[edx+0x4]
    0xff,0xd0,           //   01357ae4   ffd0           call eax
    0x8b,0x4c,0x24, 0x14 //   01357ae6   8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
  };
  // Offset to the function call from the beginning of the function
  enum { hook_offset = 0x27 }; // Type2: hex(0x0133CEC7-0x0133CEA0) = hex(0x01357af9-0x1357ad2)
  enum { hp_off = -0xc }; // hook parameter
  return FindRejetHook(bytes, sizeof(bytes), hook_offset, hp_off);
}
bool InsertRejetHook3() // jichi 12/28/2013: add for 剣が君
{
  // The following pattern is the same as type2
  const BYTE bytes[] = {   // Type2 Function start
    0xff,0xf0,           //   01357ad2   fff0           push eax
    0x0f,0xc1,0x11,      //   01357ad4   0fc111         xadd dword ptr ds:[ecx],edx
    0x4a,                //   01357ad7   4a             dec edx
    0x85,0xd2,           //   01357ad8   85d2           test edx,edx
    0x7f, 0x0a,          //   01357ada   7f 0a          jg short DotKares.01357ae6
    0x8b,0x08,           //   01357adc   8b08           mov ecx,dword ptr ds:[eax]
    0x8b,0x11,           //   01357ade   8b11           mov edx,dword ptr ds:[ecx]
    0x50,                //   01357ae0   50             push eax
    0x8b,0x42, 0x04,     //   01357ae1   8b42 04        mov eax,dword ptr ds:[edx+0x4]
    0xff,0xd0,           //   01357ae4   ffd0           call eax
    0x8b,0x4c,0x24, 0x14 //   01357ae6   8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
  };
  // Offset to the function call from the beginning of the function
  //enum { hook_offset = 0x27 }; // Type2: hex(0x0133CEC7-0x0133CEA0) = hex(0x01357af9-0x1357ad2)
  enum { hp_off = -0xc }; // hook parameter
  ULONG addr = module_base_; //- sizeof(bytes);
  while (true) {
    //addr += sizeof(bytes); // ++ so that each time return diff address
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(bytes, sizeof(bytes), addr, addr + range);
    if (!addr) {
      //ITH_MSG(L"failed");
      ConsoleOutput("vnreng:Rejet: pattern not found");
      return false;
    }
    addr += sizeof(bytes);
    // Push and call at once, i.e. push (0x68) and call (0xe8)
    // 01185345     52             push edx
    // 01185346   . 68 e4fe5501    push dotkares.0155fee4                   ; |arg1 = 0155fee4
    // 0118534b   . e8 1023f9ff    call dotkares.01117660                   ; \dotkares.00377660
    enum { start = 0x10, stop = 0x50 };
    // Different from FindRejetHook
    DWORD i;
    for (i = start; i < stop; i++)
      if (*(WORD *)(addr + i - 1) == 0x6852 && *(BYTE *)(addr + i + 5) == 0xe8) // 0118534B-01185346
        break;
    if (i < stop) {
      addr += i;
      break;
    }
  } //while(0xe8202474 != *(DWORD *)(addr - 3));

  //ITH_GROWL_DWORD(addr - module_base_); // = 0xb3578 for 剣が君

  ConsoleOutput("vnreng: INSERT Rejet");
  // The same as type2
  HookParam hp = {};
  hp.addr = addr; //- 0xf;
  hp.type = NO_CONTEXT|DATA_INDIRECT|FIXING_SPLIT;
  hp.length_offset = 1;
  hp.off = hp_off;
  //hp.off = -0x8; // Type1
  //hp.off = -0xc; // Type2

  NewHook(hp, L"Rejet");
  return true;
}
} // unnamed Rejet

bool InsertRejetHook()
{ return InsertRejetHook2() || InsertRejetHook1() || InsertRejetHook3(); } // insert hook2 first, since 2's pattern seems to be more unique

/**
 *  jichi 4/1/2014: Insert AU hook
 *  Sample games:
 *  英雄＊戦姫: /HBN-8*4@4AD807
 *  英雄＊戦姫GOLD: /HB-8*4@4ADB50 (alternative)
 *
 *  /HBN-8*4@4AD807
 *  - addr: 4904967 = 0x4ad807
 *  - ind: 4
 *  - length_offset: 1
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - type: 1032 = 0x408
 *
 *  004ad76a  |. ff50 04        |call dword ptr ds:[eax+0x4]
 *  004ad76d  |. 48             |dec eax                                 ;  switch (cases 1..a)
 *  004ad76e  |. 83f8 09        |cmp eax,0x9
 *  004ad771  |. 0f87 37020000  |ja 英雄＊戦.004ad9ae
 *  004ad777  |. ff2485 2cda4a0>|jmp dword ptr ds:[eax*4+0x4ada2c]
 *  004ad77e  |> 83bf c4000000 >|cmp dword ptr ds:[edi+0xc4],0x1         ;  case 1 of switch 004ad76d
 *  004ad785  |. 75 35          |jnz short 英雄＊戦.004ad7bc
 *  004ad787  |. 39af c8000000  |cmp dword ptr ds:[edi+0xc8],ebp
 *  004ad78d  |. 72 08          |jb short 英雄＊戦.004ad797
 *  004ad78f  |. 8b87 b4000000  |mov eax,dword ptr ds:[edi+0xb4]
 *  004ad795  |. eb 06          |jmp short 英雄＊戦.004ad79d
 *  004ad797  |> 8d87 b4000000  |lea eax,dword ptr ds:[edi+0xb4]
 *  004ad79d  |> 0fb608         |movzx ecx,byte ptr ds:[eax]
 *  004ad7a0  |. 51             |push ecx
 *  004ad7a1  |. e8 d15b2a00    |call 英雄＊戦.00753377
 *  004ad7a6  |. 83c4 04        |add esp,0x4
 *  004ad7a9  |. 85c0           |test eax,eax
 *  004ad7ab  |. 74 0f          |je short 英雄＊戦.004ad7bc
 *  004ad7ad  |. 8d5424 20      |lea edx,dword ptr ss:[esp+0x20]
 *  004ad7b1  |. 52             |push edx
 *  004ad7b2  |. b9 88567a00    |mov ecx,英雄＊戦.007a5688
 *  004ad7b7  |. e8 a40cf6ff    |call 英雄＊戦.0040e460
 *  004ad7bc  |> 8b8424 e400000>|mov eax,dword ptr ss:[esp+0xe4]
 *  004ad7c3  |. 8a48 01        |mov cl,byte ptr ds:[eax+0x1]
 *  004ad7c6  |. 84c9           |test cl,cl
 *  004ad7c8  |. 75 2e          |jnz short 英雄＊戦.004ad7f8
 *  004ad7ca  |. 8d9f b0000000  |lea ebx,dword ptr ds:[edi+0xb0]
 *  004ad7d0  |. be ac6e7a00    |mov esi,英雄＊戦.007a6eac
 *  004ad7d5  |. 8bcb           |mov ecx,ebx
 *  004ad7d7  |. e8 e40af6ff    |call 英雄＊戦.0040e2c0
 *  004ad7dc  |. 84c0           |test al,al
 *  004ad7de  |. 0f84 ca010000  |je 英雄＊戦.004ad9ae
 *  004ad7e4  |. be a86e7a00    |mov esi,英雄＊戦.007a6ea8
 *  004ad7e9  |. 8bcb           |mov ecx,ebx
 *  004ad7eb  |. e8 d00af6ff    |call 英雄＊戦.0040e2c0
 *  004ad7f0  |. 84c0           |test al,al
 *  004ad7f2  |. 0f84 b6010000  |je 英雄＊戦.004ad9ae
 *  004ad7f8  |> 6a 00          |push 0x0
 *  004ad7fa  |. 8d8f b0000000  |lea ecx,dword ptr ds:[edi+0xb0]
 *  004ad800  |. 83c8 ff        |or eax,0xffffffff
 *  004ad803  |. 8d5c24 24      |lea ebx,dword ptr ss:[esp+0x24]
 *  004ad807  |. e8 740cf6ff    |call 英雄＊戦.0040e480     ; jichi: hook here
 *  004ad80c  |. e9 9d010000    |jmp 英雄＊戦.004ad9ae
 *  004ad811  |> 8b8c24 e400000>|mov ecx,dword ptr ss:[esp+0xe4]         ;  case 4 of switch 004ad76d
 *  004ad818  |. 8039 00        |cmp byte ptr ds:[ecx],0x0
 *  004ad81b  |. 0f84 8d010000  |je 英雄＊戦.004ad9ae
 *  004ad821  |. b8 04000000    |mov eax,0x4
 *  004ad826  |. b9 c86e7a00    |mov ecx,英雄＊戦.007a6ec8                   ;  ascii "<br>"
 *  004ad82b  |. 8d5424 20      |lea edx,dword ptr ss:[esp+0x20]
 *  004ad82f  |. e8 3c0df6ff    |call 英雄＊戦.0040e570
 *  004ad834  |. e9 75010000    |jmp 英雄＊戦.004ad9ae
 *  004ad839  |> 8bbf b4000000  |mov edi,dword ptr ds:[edi+0xb4]         ;  case 5 of switch 004ad76d
 */
bool InsertTencoHook()
{
  const BYTE bytes[] = {
    0x6a, 0x00,                     // 004ad7f8  |> 6a 00          |push 0x0
    0x8d,0x8f, 0xb0,0x00,0x00,0x00, // 004ad7fa  |. 8d8f b0000000  |lea ecx,dword ptr ds:[edi+0xb0]
    0x83,0xc8, 0xff,                // 004ad800  |. 83c8 ff        |or eax,0xffffffff
    0x8d,0x5c,0x24, 0x24,           // 004ad803  |. 8d5c24 24      |lea ebx,dword ptr ss:[esp+0x24]
    0xe8 //740cf6ff                 // 004ad807  |. e8 740cf6ff    |call 英雄＊戦.0040e480     ; jichi: hook here
  };
  enum { hook_offset = sizeof(bytes) - 1 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //reladdr = 0x4ad807;
  if (!addr) {
    ConsoleOutput("vnreng:Tenco: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.length_offset = 1;
  hp.ind = 4;
  hp.off = -0xc;
  hp.type = NO_CONTEXT|DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT Tenco");
  NewHook(hp, L"Tenco");
  return true;
}

/**
 *  jichi 4/1/2014: Insert AOS hook
 *  About 彩文館: http://erogetrailers.com/brand/165
 *  About AOS: http://asmodean.reverse.net/pages/exaos.html
 *
 *  Sample games:
 *
 *  [140228] [Sugar Pot] 恋する少女と想いのキセキ V1.00 H-CODE by 소쿠릿
 *  - /HB8*0@3C2F0:恋する少女と想いのキセキ.exe
 *  - /HBC*0@3C190:恋する少女と想いのキセキ.exe
 *
 *  [120224] [Sugar Pot]  ツクモノツキ
 *
 *  LiLiM games
 *
 *  /HB8*0@3C2F0:恋する少女と想いのキセ
 *  - addr: 246512 = 0x3c2f0
 *  - length_offset: 1
 *  - module: 1814017450
 *  - off: 8
 *  - type: 72 = 0x48
 *
 *  00e3c2ed     cc                         int3
 *  00e3c2ee     cc                         int3
 *  00e3c2ef     cc                         int3
 *  00e3c2f0  /$ 51                         push ecx    ; jichi: hook here, function starts
 *  00e3c2f1  |. a1 0c64eb00                mov eax,dword ptr ds:[0xeb640c]
 *  00e3c2f6  |. 8b0d 7846eb00              mov ecx,dword ptr ds:[0xeb4678]
 *  00e3c2fc  |. 53                         push ebx
 *  00e3c2fd  |. 55                         push ebp
 *  00e3c2fe  |. 8b6c24 10                  mov ebp,dword ptr ss:[esp+0x10]
 *  00e3c302  |. 56                         push esi
 *  00e3c303  |. 8b35 c446eb00              mov esi,dword ptr ds:[0xeb46c4]
 *  00e3c309  |. 57                         push edi
 *  00e3c30a  |. 0fb63d c746eb00            movzx edi,byte ptr ds:[0xeb46c7]
 *  00e3c311  |. 81e6 ffffff00              and esi,0xffffff
 *  00e3c317  |. 894424 18                  mov dword ptr ss:[esp+0x18],eax
 *  00e3c31b  |. 85ff                       test edi,edi
 *  00e3c31d  |. 74 6b                      je short 恋する少.00e3c38a
 *  00e3c31f  |. 8bd9                       mov ebx,ecx
 *  00e3c321  |. 85db                       test ebx,ebx
 *  00e3c323  |. 74 17                      je short 恋する少.00e3c33c
 *  00e3c325  |. 8b4b 28                    mov ecx,dword ptr ds:[ebx+0x28]
 *  00e3c328  |. 56                         push esi                                 ; /color
 *  00e3c329  |. 51                         push ecx                                 ; |hdc
 *  00e3c32a  |. ff15 3c40e800              call dword ptr ds:[<&gdi32.SetTextColor>>; \settextcolor
 *  00e3c330  |. 89b3 c8000000              mov dword ptr ds:[ebx+0xc8],esi
 *  00e3c336  |. 8b0d 7846eb00              mov ecx,dword ptr ds:[0xeb4678]
 *  00e3c33c  |> 0fbf55 1c                  movsx edx,word ptr ss:[ebp+0x1c]
 *  00e3c340  |. 0fbf45 0a                  movsx eax,word ptr ss:[ebp+0xa]
 *  00e3c344  |. 0fbf75 1a                  movsx esi,word ptr ss:[ebp+0x1a]
 *  00e3c348  |. 03d7                       add edx,edi
 *  00e3c34a  |. 03c2                       add eax,edx
 *  00e3c34c  |. 0fbf55 08                  movsx edx,word ptr ss:[ebp+0x8]
 *  00e3c350  |. 03f7                       add esi,edi
 *  00e3c352  |. 03d6                       add edx,esi
 *  00e3c354  |. 85c9                       test ecx,ecx
 *  00e3c356  |. 74 32                      je short 恋する少.00e3c38a
 */
bool InsertAOSHook()
{
  // jichi 4/2/2014: The starting of this function is different from ツクモノツキ
  // So, use a pattern in the middle of the function instead.
  //
  //const BYTE bytes[] = {
  //  0x51,                                 // 00e3c2f0  /$ 51              push ecx    ; jichi: hook here, function begins
  //  0xa1, 0x0c,0x64,0xeb,0x00,            // 00e3c2f1  |. a1 0c64eb00     mov eax,dword ptr ds:[0xeb640c]
  //  0x8b,0x0d, 0x78,0x46,0xeb,0x00,       // 00e3c2f6  |. 8b0d 7846eb00   mov ecx,dword ptr ds:[0xeb4678]
  //  0x53,                                 // 00e3c2fc  |. 53              push ebx
  //  0x55,                                 // 00e3c2fd  |. 55              push ebp
  //  0x8b,0x6c,0x24, 0x10,                 // 00e3c2fe  |. 8b6c24 10       mov ebp,dword ptr ss:[esp+0x10]
  //  0x56,                                 // 00e3c302  |. 56              push esi
  //  0x8b,0x35, 0xc4,0x46,0xeb,0x00,       // 00e3c303  |. 8b35 c446eb00   mov esi,dword ptr ds:[0xeb46c4]
  //  0x57,                                 // 00e3c309  |. 57              push edi
  //  0x0f,0xb6,0x3d, 0xc7,0x46,0xeb,0x00,  // 00e3c30a  |. 0fb63d c746eb00 movzx edi,byte ptr ds:[0xeb46c7]
  //  0x81,0xe6, 0xff,0xff,0xff,0x00        // 00e3c311  |. 81e6 ffffff00   and esi,0xffffff
  //};
  //enum { hook_offset = 0 };

  const BYTE bytes[] = {
    0x0f,0xbf,0x55, 0x1c,   // 00e3c33c  |> 0fbf55 1c                  movsx edx,word ptr ss:[ebp+0x1c]
    0x0f,0xbf,0x45, 0x0a,   // 00e3c340  |. 0fbf45 0a                  movsx eax,word ptr ss:[ebp+0xa]
    0x0f,0xbf,0x75, 0x1a,   // 00e3c344  |. 0fbf75 1a                  movsx esi,word ptr ss:[ebp+0x1a]
    0x03,0xd7,              // 00e3c348  |. 03d7                       add edx,edi
    0x03,0xc2,              // 00e3c34a  |. 03c2                       add eax,edx
    0x0f,0xbf,0x55, 0x08,   // 00e3c34c  |. 0fbf55 08                  movsx edx,word ptr ss:[ebp+0x8]
    0x03,0xf7,              // 00e3c350  |. 03f7                       add esi,edi
    0x03,0xd6,              // 00e3c352  |. 03d6                       add edx,esi
    0x85,0xc9               // 00e3c354  |. 85c9                       test ecx,ecx
  };
  enum { hook_offset = 0x00e3c2f0 - 0x00e3c33c }; // distance to the beginning of the function, which is 0x51 (push ecx)
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:AOS: pattern not found");
    return false;
  }
  addr += hook_offset;
  //ITH_GROWL(addr);
  enum { push_ecx = 0x51 }; // beginning of the function
  if (*(BYTE *)addr != push_ecx) {
    ConsoleOutput("vnreng:AOS: beginning of the function not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.off = 8;
  hp.type = DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT AOS");
  NewHook(hp, L"AOS");
  return true;
}

/**
 *  jichi 4/15/2014: Insert Adobe AIR hook
 *  Sample games:
 *  華アワセ 蛟編: /HW-C*0:D8@4D04B5:Adobe AIR.dll
 *  華アワセ 姫空木編: /HW-C*0:d8@4E69A7:Adobe AIR.dll
 *
 *  Issue: The game will hang if the hook is injected before loading
 *
 *  /HW-C*0:D8@4D04B5:ADOBE AIR.DLL
 *  - addr: 5047477 = 0x4d04b5
 *  -length_offset: 1
 *  - module: 3506957663 = 0xd107ed5f
 *  - off: 4294967280 = 0xfffffff0 = -0x10
 *  - split: 216 = 0xd8
 *  - type: 90 = 0x5a
 *
 *  0f8f0497  |. eb 69         jmp short adobe_ai.0f8f0502
 *  0f8f0499  |> 83c8 ff       or eax,0xffffffff
 *  0f8f049c  |. eb 67         jmp short adobe_ai.0f8f0505
 *  0f8f049e  |> 8b7d 0c       mov edi,dword ptr ss:[ebp+0xc]
 *  0f8f04a1  |. 85ff          test edi,edi
 *  0f8f04a3  |. 7e 5d         jle short adobe_ai.0f8f0502
 *  0f8f04a5  |. 8b55 08       mov edx,dword ptr ss:[ebp+0x8]
 *  0f8f04a8  |. b8 80000000   mov eax,0x80
 *  0f8f04ad  |. be ff030000   mov esi,0x3ff
 *  0f8f04b2  |> 0fb70a        /movzx ecx,word ptr ds:[edx]
 *  0f8f04b5  |. 8bd8          |mov ebx,eax ; jichi: hook here
 *  0f8f04b7  |. 4f            |dec edi
 *  0f8f04b8  |. 66:3bcb       |cmp cx,bx
 *  0f8f04bb  |. 73 05         |jnb short adobe_ai.0f8f04c2
 *  0f8f04bd  |. ff45 fc       |inc dword ptr ss:[ebp-0x4]
 *  0f8f04c0  |. eb 3a         |jmp short adobe_ai.0f8f04fc
 *  0f8f04c2  |> bb 00080000   |mov ebx,0x800
 *  0f8f04c7  |. 66:3bcb       |cmp cx,bx
 *  0f8f04ca  |. 73 06         |jnb short adobe_ai.0f8f04d2
 *  0f8f04cc  |. 8345 fc 02    |add dword ptr ss:[ebp-0x4],0x2
 *  0f8f04d0  |. eb 2a         |jmp short adobe_ai.0f8f04fc
 *  0f8f04d2  |> 81c1 00280000 |add ecx,0x2800
 *  0f8f04d8  |. 8bde          |mov ebx,esi
 *  0f8f04da  |. 66:3bcb       |cmp cx,bx
 *  0f8f04dd  |. 77 19         |ja short adobe_ai.0f8f04f8
 *  0f8f04df  |. 4f            |dec edi
 *  0f8f04e0  |.^78 b7         |js short adobe_ai.0f8f0499
 *  0f8f04e2  |. 42            |inc edx
 *  0f8f04e3  |. 42            |inc edx
 *  0f8f04e4  |. 0fb70a        |movzx ecx,word ptr ds:[edx]
 *  0f8f04e7  |. 81c1 00240000 |add ecx,0x2400
 *  0f8f04ed  |. 66:3bcb       |cmp cx,bx
 *  0f8f04f0  |. 77 06         |ja short adobe_ai.0f8f04f8
 *  0f8f04f2  |. 8345 fc 04    |add dword ptr ss:[ebp-0x4],0x4
 *  0f8f04f6  |. eb 04         |jmp short adobe_ai.0f8f04fc
 *  0f8f04f8  |> 8345 fc 03    |add dword ptr ss:[ebp-0x4],0x3
 *  0f8f04fc  |> 42            |inc edx
 *  0f8f04fd  |. 42            |inc edx
 *  0f8f04fe  |. 85ff          |test edi,edi
 *  0f8f0500  |.^7f b0         \jg short adobe_ai.0f8f04b2
 *  0f8f0502  |> 8b45 fc       mov eax,dword ptr ss:[ebp-0x4]
 *  0f8f0505  |> 5f            pop edi
 *  0f8f0506  |. 5e            pop esi
 *  0f8f0507  |. 5b            pop ebx
 *  0f8f0508  |. c9            leave
 *  0f8f0509  \. c3            retn
 */
bool InsertAdobeAirHook()
{
  enum { module = 0xd107ed5f }; // hash of "Adobe AIR.dll"
  DWORD base = Util::FindModuleBase(module);
  if (!base) {
    ConsoleOutput("vnreng:Adobe AIR: module not found");
    return false;
  }

  const BYTE bytes[] = {
    0x0f,0xb7,0x0a,  // 0f8f04b2  |> 0fb70a        /movzx ecx,word ptr ds:[edx]
    0x8b,0xd8,       // 0f8f04b5  |. 8bd8          |mov ebx,eax ; jichi: hook here
    0x4f,            // 0f8f04b7  |. 4f            |dec edi
    0x66,0x3b,0xcb,  // 0f8f04b8  |. 66:3bcb       |cmp cx,bx
    0x73, 0x05,      // 0f8f04bb  |. 73 05         |jnb short adobe_ai.0f8f04c2
    0xff,0x45, 0xfc, // 0f8f04bd  |. ff45 fc       |inc dword ptr ss:[ebp-0x4]
    0xeb, 0x3a       // 0f8f04c0  |. eb 3a         |jmp short adobe_ai.0f8f04fc
  };
  enum { hook_offset = 0x0f8f04b5 - 0x0f8f04b2 }; // = 3. 0 also works.
  enum { range = 0x600000 }; // larger than relative addresses
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), base, base + range);
  //ITH_GROWL(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:Adobe AIR: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.module = module;
  hp.length_offset = 1;
  hp.off = -0x10;
  hp.split = 0xd8;
  //hp.type = USING_SPLIT|MODULE_OFFSET|USING_UNICODE|DATA_INDIRECT; // 0x5a;
  hp.type = USING_SPLIT|USING_UNICODE|DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT Adobe AIR");
  NewHook(hp, L"Adobe AIR");
  return true;
}

/**
 *  jichi 1/10/2014: Rai7 puk
 *  See: http://www.hongfire.com/forum/showthread.php/421909-%E3%80%90Space-Warfare-Sim%E3%80%91Rai-7-PUK/page10
 *  See: www.hongfire.com/forum/showthread.php/421909-%E3%80%90Space-Warfare-Sim%E3%80%91Rai-7-PUK/page19
 *
 *  Version: R7P3-13v2(131220).rar, pass: sstm http://pan.baidu.com/share/home?uk=3727185265#category/type=0
 *  /HS0@409524
 */
//bool InsertRai7Hook()
//{
//}

/**
 *  jichi 10/1/2013: sol-fa-soft
 *  See (tryguy): http://www.hongfire.com/forum/printthread.php?t=36807&pp=10&page=639
 *
 *  @tryguy
 *  [sol-fa-soft]
 *  17 スク水不要論: /HA4@4AD140
 *  18 ななちゃんといっしょ: /HA4@5104A0
 *  19 発情てんこうせい: /HA4@51D720
 *  20 わたしのたまごさん: /HA4@4968E0
 *  21 修学旅行夜更かし組: /HA4@49DC00
 *  22 おぼえたてキッズ: /HA4@49DDB0
 *  23 ちっさい巫女さんSOS: /HA4@4B4AA0
 *  24 はじめてのおふろやさん: /HA4@4B5600
 *  25 はきわすれ愛好会: /HA4@57E360
 *  26 朝っぱらから発情家族: /HA4@57E360
 *  27 となりのヴァンパイア: /HA4@5593B0
 *  28 麦わら帽子と水辺の妖精: /HA4@5593B0
 *  29 海と温泉と夏休み: /HA4@6DE8E0
 *  30 駄菓子屋さん繁盛記: /HA4@6DEC90
 *  31 浴衣の下は… ～神社で発見！ ノーパン少女～: /HA4@6DEC90
 *  32 プールのじかん スク水不要論2: /HA4@62AE10
 *  33 妹のお泊まり会: /HA4@6087A0
 *  34 薄着少女: /HA4@6087A0
 *  35 あやめ Princess Intermezzo: /HA4@609BF0
 *
 *  SG01 男湯Ｒ: /HA4@6087A0
 *
 *  c71 真冬の大晦日CD: /HA4@516b50
 *  c78 sol-fa-soft真夏のお気楽CD: /HA4@6DEC90
 *
 *  Example: 35 あやめ Princess Intermezzo: /HA4@609BF0
 *  - addr: 6331376 = 0x609bf0
 *  - length_offset: 1
 *  - off: 4
 *  - type: 4
 *
 *  ASCII: あやめ, hook_offset = -50
 *  Function starts
 *  00609bef  /> cc             int3
 *  00609bf0  /> 55             push ebp
 *  00609bf1  |. 8bec           mov ebp,esp
 *  00609bf3  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  00609bf9  |. 6a ff          push -0x1
 *  00609bfb  |. 68 e1266300    push あやめ.006326e1
 *  00609c00  |. 50             push eax
 *  00609c01  |. 64:8925 000000>mov dword ptr fs:[0],esp
 *  00609c08  |. 81ec 80000000  sub esp,0x80
 *  00609c0e  |. 53             push ebx
 *  00609c0f  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
 *  00609c12  |. 57             push edi
 *  00609c13  |. 8bf9           mov edi,ecx
 *  00609c15  |. 8b07           mov eax,dword ptr ds:[edi]
 *  00609c17  |. 83f8 02        cmp eax,0x2
 *  00609c1a  |. 75 1f          jnz short あやめ.00609c3b
 *  00609c1c  |. 3b5f 40        cmp ebx,dword ptr ds:[edi+0x40]
 *  00609c1f  |. 75 1a          jnz short あやめ.00609c3b
 *  00609c21  |. 837f 44 00     cmp dword ptr ds:[edi+0x44],0x0
 *  00609c25  |. 74 14          je short あやめ.00609c3b
 *  00609c27  |. 5f             pop edi
 *  00609c28  |. b0 01          mov al,0x1
 *  00609c2a  |. 5b             pop ebx
 *  00609c2b  |. 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
 *  00609c2e  |. 64:890d 000000>mov dword ptr fs:[0],ecx
 *  00609c35  |. 8be5           mov esp,ebp
 *  00609c37  |. 5d             pop ebp
 *  00609c38  |. c2 0400        retn 0x4
 *  Function stops
 *
 *  WideChar: こいなか-小田舎で初恋x中出しセクシャルライフ-, hook_offset = -53
 *  0040653a     cc             int3
 *  0040653b     cc             int3
 *  0040653c     cc             int3
 *  0040653d     cc             int3
 *  0040653e     cc             int3
 *  0040653f     cc             int3
 *  00406540   > 55             push ebp
 *  00406541   . 8bec           mov ebp,esp
 *  00406543   . 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  00406549   . 6a ff          push -0x1
 *  0040654b   . 68 f1584300    push erondo01.004358f1
 *  00406550   . 50             push eax
 *  00406551   . 64:8925 000000>mov dword ptr fs:[0],esp
 *  00406558   . 83ec 6c        sub esp,0x6c
 *  0040655b   . 53             push ebx
 *  0040655c   . 8bd9           mov ebx,ecx
 *  0040655e   . 57             push edi
 *  0040655f   . 8b03           mov eax,dword ptr ds:[ebx]
 *  00406561   . 8b7d 08        mov edi,dword ptr ss:[ebp+0x8]
 *  00406564   . 83f8 02        cmp eax,0x2
 *  00406567   . 75 1f          jnz short erondo01.00406588
 *  00406569   . 3b7b 3c        cmp edi,dword ptr ds:[ebx+0x3c]
 *  0040656c   . 75 1a          jnz short erondo01.00406588
 *  0040656e   . 837b 40 00     cmp dword ptr ds:[ebx+0x40],0x0
 *  00406572   . 74 14          je short erondo01.00406588
 *  00406574   . 5f             pop edi
 *  00406575   . b0 01          mov al,0x1
 *  00406577   . 5b             pop ebx
 *  00406578   . 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
 *  0040657b   . 64:890d 000000>mov dword ptr fs:[0],ecx
 *  00406582   . 8be5           mov esp,ebp
 *  00406584   . 5d             pop ebp
 *  00406585   . c2 0400        retn 0x4
 *
 *  WideChar: 祝福の鐘の音は、桜色の風と共に, hook_offset = -50,
 *  FIXME: how to know if it is UTF16? This game has /H code, though:
 *
 *      /HA-4@94D62:shukufuku_main.exe
 *
 *  011d619e   cc               int3
 *  011d619f   cc               int3
 *  011d61a0   55               push ebp
 *  011d61a1   8bec             mov ebp,esp
 *  011d61a3   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  011d61a9   6a ff            push -0x1
 *  011d61ab   68 d1811f01      push .011f81d1
 *  011d61b0   50               push eax
 *  011d61b1   64:8925 00000000 mov dword ptr fs:[0],esp
 *  011d61b8   81ec 80000000    sub esp,0x80
 *  011d61be   53               push ebx
 *  011d61bf   8b5d 08          mov ebx,dword ptr ss:[ebp+0x8]
 *  011d61c2   57               push edi
 *  011d61c3   8bf9             mov edi,ecx
 *  011d61c5   8b07             mov eax,dword ptr ds:[edi]
 *  011d61c7   83f8 02          cmp eax,0x2
 *  011d61ca   75 1f            jnz short .011d61eb
 *  011d61cc   3b5f 40          cmp ebx,dword ptr ds:[edi+0x40]
 *  011d61cf   75 1a            jnz short .011d61eb
 *  011d61d1   837f 44 00       cmp dword ptr ds:[edi+0x44],0x0
 *  011d61d5   74 14            je short .011d61eb
 *  011d61d7   5f               pop edi
 *  011d61d8   b0 01            mov al,0x1
 *  011d61da   5b               pop ebx
 *  011d61db   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  011d61de   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  011d61e5   8be5             mov esp,ebp
 *  011d61e7   5d               pop ebp
 *  011d61e8   c2 0400          retn 0x4
 */
bool InsertScenarioPlayerHook()
{
  //const BYTE bytes[] = {
  //  0x53,                    // 00609c0e  |. 53             push ebx
  //  0x8b,0x5d,0x08,          // 00609c0f  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
  //  0x57,                    // 00609c12  |. 57             push edi
  //  0x8b,0xf9,               // 00609c13  |. 8bf9           mov edi,ecx
  //  0x8b,0x07,               // 00609c15  |. 8b07           mov eax,dword ptr ds:[edi]
  //  0x83,0xf8, 0x02,         // 00609c17  |. 83f8 02        cmp eax,0x2
  //  0x75, 0x1f,              // 00609c1a  |. 75 1f          jnz short あやめ.00609c3b
  //  0x3b,0x5f, 0x40,         // 00609c1c  |. 3b5f 40        cmp ebx,dword ptr ds:[edi+0x40]
  //  0x75, 0x1a,              // 00609c1f  |. 75 1a          jnz short あやめ.00609c3b
  //  0x83,0x7f, 0x44, 0x00,   // 00609c21  |. 837f 44 00     cmp dword ptr ds:[edi+0x44],0x0
  //  0x74, 0x14,              // 00609c25  |. 74 14          je short あやめ.00609c3b
  //};
  //enum { hook_offset = 0x00609bf0 - 0x00609c0e }; // distance to the beginning of the function

  const BYTE bytes[] = {
    0x74, 0x14,     // 00609c25  |. 74 14          je short あやめ.00609c3b
    0x5f,           // 00609c27  |. 5f             pop edi
    0xb0, 0x01,     // 00609c28  |. b0 01          mov al,0x1
    0x5b,           // 00609c2a  |. 5b             pop ebx
    0x8b,0x4d, 0xf4 // 00609c2b  |. 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
  };
  enum { // distance to the beginning of the function
    hook_offset_A = 0x00609bf0 - 0x00609c25   // -53
    , hook_offset_W = 0x00406540 - 0x00406572 // -50
  };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG start = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!start) {
    ConsoleOutput("vnreng:ScenarioPlayer: pattern not found");
    return false;
  }

  DWORD addr = MemDbg::findEnclosingAlignedFunction(start, 80); // range is around 50, use 80

  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (!addr || *(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:ScenarioPlayer: pattern found but the function offset is invalid");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.off = 4;
  if (addr - start == hook_offset_W) {
    hp.type = USING_UNICODE;
    ConsoleOutput("vnreng: INSERT ScenarioPlayerW");
    NewHook(hp, L"ScenarioPlayerW");
  } else {
    hp.type = BIG_ENDIAN; // 4
    ConsoleOutput("vnreng: INSERT ScenarioPlayerA");
    NewHook(hp, L"ScenarioPlayerA");
  }
  return true;
}

/**
 *  jichi 4/19/2014: Marine Heart
 *  See: http://blgames.proboards.com/post/1984
 *       http://www.yaoiotaku.com/forums/threads/11440-huge-bl-game-torrent
 *
 *  Issue: The extracted text someitems has limited repetition
 *  TODO: It might be better to use FindCallAndEntryAbs for gdi32.CreateFontA?
 *        See how FindCallAndEntryAbs is used in Majiro.
 *
 *  妖恋愛奇譚 ～神サマの堕し方～ /HS4*0@40D160
 *  - addr: 4247904 = 0x40d160
 *  - off: 4
 *  - type: 9
 *
 *  Function starts
 *  0040d160  /$ 55                 push ebp    ; jichi: hook here
 *  0040d161  |. 8bec               mov ebp,esp
 *  0040d163  |. 83c4 90            add esp,-0x70
 *  0040d166  |. 33c0               xor eax,eax
 *  0040d168  |. 53                 push ebx
 *  0040d169  |. 56                 push esi
 *  0040d16a  |. 57                 push edi
 *  0040d16b  |. 8b75 08            mov esi,dword ptr ss:[ebp+0x8]
 *  0040d16e  |. c745 cc 281e4800   mov dword ptr ss:[ebp-0x34],saisys.00481>
 *  0040d175  |. 8965 d0            mov dword ptr ss:[ebp-0x30],esp
 *  0040d178  |. c745 c8 d0d14700   mov dword ptr ss:[ebp-0x38],<jmp.&cp3245>
 *  0040d17f  |. 66:c745 d4 0000    mov word ptr ss:[ebp-0x2c],0x0
 *  0040d185  |. 8945 e0            mov dword ptr ss:[ebp-0x20],eax
 *  0040d188  |. 64:8b15 00000000   mov edx,dword ptr fs:[0]
 *  0040d18f  |. 8955 c4            mov dword ptr ss:[ebp-0x3c],edx
 *  0040d192  |. 8d4d c4            lea ecx,dword ptr ss:[ebp-0x3c]
 *  0040d195  |. 64:890d 00000000   mov dword ptr fs:[0],ecx
 *  0040d19c  |. 8b05 741c4800      mov eax,dword ptr ds:[0x481c74]
 *  0040d1a2  |. 8945 bc            mov dword ptr ss:[ebp-0x44],eax
 *  0040d1a5  |. 8b05 781c4800      mov eax,dword ptr ds:[0x481c78]
 *  0040d1ab  |. 8945 c0            mov dword ptr ss:[ebp-0x40],eax
 *  0040d1ae  |. 8d46 24            lea eax,dword ptr ds:[esi+0x24]
 *  0040d1b1  |. 8b56 14            mov edx,dword ptr ds:[esi+0x14]
 *  0040d1b4  |. 8955 bc            mov dword ptr ss:[ebp-0x44],edx
 *  0040d1b7  |. 8b10               mov edx,dword ptr ds:[eax]
 *  0040d1b9  |. 85d2               test edx,edx
 *  0040d1bb  |. 74 04              je short saisys.0040d1c1
 *  0040d1bd  |. 8b08               mov ecx,dword ptr ds:[eax]
 *  0040d1bf  |. eb 05              jmp short saisys.0040d1c6
 *  0040d1c1  |> b9 9b1c4800        mov ecx,saisys.00481c9b
 *  0040d1c6  |> 51                 push ecx                                 ; /facename
 *  0040d1c7  |. 6a 01              push 0x1                                 ; |pitchandfamily = fixed_pitch|ff_dontcare
 *  0040d1c9  |. 6a 03              push 0x3                                 ; |quality = 3.
 *  0040d1cb  |. 6a 00              push 0x0                                 ; |clipprecision = clip_default_precis
 *  0040d1cd  |. 6a 00              push 0x0                                 ; |outputprecision = out_default_precis
 *  0040d1cf  |. 68 80000000        push 0x80                                ; |charset = 128.
 *  0040d1d4  |. 6a 00              push 0x0                                 ; |strikeout = false
 *  0040d1d6  |. 6a 00              push 0x0                                 ; |underline = false
 *  0040d1d8  |. 6a 00              push 0x0                                 ; |italic = false
 *  0040d1da  |. 68 90010000        push 0x190                               ; |weight = fw_normal
 *  0040d1df  |. 6a 00              push 0x0                                 ; |orientation = 0x0
 *  0040d1e1  |. 6a 00              push 0x0                                 ; |escapement = 0x0
 *  0040d1e3  |. 6a 00              push 0x0                                 ; |width = 0x0
 *  0040d1e5  |. 8b46 04            mov eax,dword ptr ds:[esi+0x4]           ; |
 *  0040d1e8  |. 50                 push eax                                 ; |height
 *  0040d1e9  |. e8 00fa0600        call <jmp.&gdi32.CreateFontA>            ; \createfonta
 *  0040d1ee  |. 8945 b8            mov dword ptr ss:[ebp-0x48],eax
 *  0040d1f1  |. 8b55 b8            mov edx,dword ptr ss:[ebp-0x48]
 *  0040d1f4  |. 85d2               test edx,edx
 *  0040d1f6  |. 75 14              jnz short saisys.0040d20c
 */
bool InsertMarineHeartHook()
{
  // FIXME: Why this does not work?!
  // jichi 6/3/2014: CreateFontA is only called once in this function
  //  0040d160  /$ 55                 push ebp    ; jichi: hook here
  //  0040d161  |. 8bec               mov ebp,esp
  //ULONG addr = Util::FindCallAndEntryAbs((DWORD)CreateFontA, module_limit_ - module_base_, module_base_, 0xec8b);

  const BYTE bytes[] = {
    0x51,                       // 0040d1c6  |> 51                 push ecx                        ; /facename
    0x6a, 0x01,                 // 0040d1c7  |. 6a 01              push 0x1                        ; |pitchandfamily = fixed_pitch|ff_dontcare
    0x6a, 0x03,                 // 0040d1c9  |. 6a 03              push 0x3                        ; |quality = 3.
    0x6a, 0x00,                 // 0040d1cb  |. 6a 00              push 0x0                        ; |clipprecision = clip_default_precis
    0x6a, 0x00,                 // 0040d1cd  |. 6a 00              push 0x0                        ; |outputprecision = out_default_precis
    0x68, 0x80,0x00,0x00,0x00,  // 0040d1cf  |. 68 80000000        push 0x80                       ; |charset = 128.
    0x6a, 0x00,                 // 0040d1d4  |. 6a 00              push 0x0                        ; |strikeout = false
    0x6a, 0x00,                 // 0040d1d6  |. 6a 00              push 0x0                        ; |underline = false
    0x6a, 0x00,                 // 0040d1d8  |. 6a 00              push 0x0                        ; |italic = false
    0x68, 0x90,0x01,0x00,0x00,  // 0040d1da  |. 68 90010000        push 0x190                      ; |weight = fw_normal
    0x6a, 0x00,                 // 0040d1df  |. 6a 00              push 0x0                        ; |orientation = 0x0
    0x6a, 0x00,                 // 0040d1e1  |. 6a 00              push 0x0                        ; |escapement = 0x0
    0x6a, 0x00,                 // 0040d1e3  |. 6a 00              push 0x0                        ; |width = 0x0 0x8b,0x46, 0x04,
    0x8b,0x46, 0x04,            // 0040d1e5  |. 8b46 04            mov eax,dword ptr ds:[esi+0x4]  ; |
    0x50,                       // 0040d1e8  |. 50                 push eax                        ; |height
    0xe8, 0x00,0xfa,0x06,0x00   // 0040d1e9  |. e8 00fa0600        call <jmp.&gdi32.CreateFontA>   ; \createfonta
  };
  enum { hook_offset = 0x0040d160 - 0x0040d1c6 }; // distance to the beginning of the function
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:MarineHeart: pattern not found");
    return false;
  }

  addr += hook_offset;
  //addr = 0x40d160;
  //ITH_GROWL_DWORD(addr);
  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (*(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:MarineHeart: pattern found but the function offset is invalid");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4;
  hp.type = USING_STRING|DATA_INDIRECT; // = 9

  ConsoleOutput("vnreng: INSERT MarineHeart");
  NewHook(hp, L"MarineHeart");
  return true;
}

/**
 *  jichi 6/1/2014:
 *  Observations from 愛姉妹4
 *  - Scenario: arg1 + 4*5 is 0, arg1+0xc is address of the text
 *  - Character: arg1 + 4*10 is 0, arg1+0xc is text
 */
static inline size_t _elf_strlen(LPCSTR p) // limit search address which might be bad
{
  //CC_ASSERT(p);
  for (size_t i = 0; i < VNR_TEXT_CAPACITY; i++)
    if (!*p++)
      return i;
  return 0; // when len >= VNR_TEXT_CAPACITY
}

static void SpecialHookElf(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //DWORD arg1 = *(DWORD *)(esp_base + 0x4);
  DWORD arg1 = argof(1, esp_base);
  DWORD arg2_scene = arg1 + 4*5,
        arg2_chara = arg1 + 4*10;
  DWORD text; //= 0; // This variable will be killed
  if (*(DWORD *)arg2_scene == 0) {
    text = *(DWORD *)(arg2_scene + 0xc);
    if (!text || ::IsBadReadPtr((LPCVOID)text, 1)) // Text from scenario could be bad when open backlog while the character is speaking
      return;
    *split = 1;
  } else if (*(DWORD *)arg2_chara == 0) {
    text = arg2_chara + 0xc;
    *split = 2;
  } else
    return;
  //if (text && text < MemDbg::UserMemoryStopAddress) {
  *len = _elf_strlen((LPCSTR)text); // in case the text is bad but still readable
  //*len = ::strlen((LPCSTR)text);
  *data = text;
}

/**
 *  jichi 5/31/2014: elf's
 *  Type1: SEXティーチャー剛史 trial, reladdr = 0x2f0f0, 2 parameters
 *  Type2: 愛姉妹4, reladdr = 0x2f9b0, 3 parameters
 *
 *  IDA: sub_42F9B0 proc near ; bp-based frame
 *    var_8 = dword ptr -8
 *    var_4 = byte ptr -4
 *    var_3 = word ptr -3
 *    arg_0 = dword ptr  8
 *    arg_4 = dword ptr  0Ch
 *    arg_8 = dword ptr  10h
 *
 *  Call graph (Type2):
 *  0x2f9b0 ;  hook here
 *  > 0x666a0 ; called multiple time
 *  > TextOutA ; there are two TextOutA, the second is the right one
 *
 *  Function starts (Type1), pattern offset: 0xc
 *  - 012ef0f0  /$ 55             push ebp ; jichi: hook
 *  - 012ef0f1  |. 8bec           mov ebp,esp
 *  - 012ef0f3  |. 83ec 10        sub esp,0x10
 *  - 012ef0f6  |. 837d 0c 00     cmp dword ptr ss:[ebp+0xc],0x0
 *  - 012ef0fa  |. 53             push ebx
 *  - 012ef0fb  |. 56             push esi
 *  - 012ef0fc  |. 75 0f          jnz short stt_tria.012ef10d ; jicchi: pattern starts
 *  - 012ef0fe  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  - 012ef101  |. 8b48 04        mov ecx,dword ptr ds:[eax+0x4]
 *  - 012ef104  |. 8b91 90000000  mov edx,dword ptr ds:[ecx+0x90] ; jichi: pattern stops
 *  - 012ef10a  |. 8955 0c        mov dword ptr ss:[ebp+0xc],edx
 *  - 012ef10d  |> 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  - 012ef110  |. 8b51 04        mov edx,dword ptr ds:[ecx+0x4]
 *  - 012ef113  |. 33c0           xor eax,eax
 *  - 012ef115  |. c645 f8 00     mov byte ptr ss:[ebp-0x8],0x0
 *  - 012ef119  |. 66:8945 f9     mov word ptr ss:[ebp-0x7],ax
 *  - 012ef11d  |. 8b82 b0000000  mov eax,dword ptr ds:[edx+0xb0]
 *  - 012ef123  |. 8945 f4        mov dword ptr ss:[ebp-0xc],eax
 *  - 012ef126  |. 33db           xor ebx,ebx
 *  - 012ef128  |> 8b4f 20        /mov ecx,dword ptr ds:[edi+0x20]
 *  - 012ef12b  |. 83f9 10        |cmp ecx,0x10
 *
 *  Function starts (Type2), pattern offset: 0x10
 *  - 0093f9b0  /$ 55             push ebp  ; jichi: hook here
 *  - 0093f9b1  |. 8bec           mov ebp,esp
 *  - 0093f9b3  |. 83ec 08        sub esp,0x8
 *  - 0093f9b6  |. 837d 10 00     cmp dword ptr ss:[ebp+0x10],0x0
 *  - 0093f9ba  |. 53             push ebx
 *  - 0093f9bb  |. 8b5d 0c        mov ebx,dword ptr ss:[ebp+0xc]
 *  - 0093f9be  |. 56             push esi
 *  - 0093f9bf  |. 57             push edi
 *  - 0093f9c0  |. 75 0f          jnz short silkys.0093f9d1 ; jichi: pattern starts
 *  - 0093f9c2  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  - 0093f9c5  |. 8b48 04        mov ecx,dword ptr ds:[eax+0x4]
 *  - 0093f9c8  |. 8b91 90000000  mov edx,dword ptr ds:[ecx+0x90] ; jichi: pattern stops
 *  - 0093f9ce  |. 8955 10        mov dword ptr ss:[ebp+0x10],edx
 *  - 0093f9d1  |> 33c0           xor eax,eax
 *  - 0093f9d3  |. c645 fc 00     mov byte ptr ss:[ebp-0x4],0x0
 *  - 0093f9d7  |. 66:8945 fd     mov word ptr ss:[ebp-0x3],ax
 *  - 0093f9db  |. 33ff           xor edi,edi
 *  - 0093f9dd  |> 8b53 20        /mov edx,dword ptr ds:[ebx+0x20]
 *  - 0093f9e0  |. 8d4b 0c        |lea ecx,dword ptr ds:[ebx+0xc]
 *  - 0093f9e3  |. 83fa 10        |cmp edx,0x10
 */
bool InsertElfHook()
{
  const BYTE bytes[] = {
      //0x55,                             // 0093f9b0  /$ 55             push ebp  ; jichi: hook here
      //0x8b,0xec,                        // 0093f9b1  |. 8bec           mov ebp,esp
      //0x83,0xec, 0x08,                  // 0093f9b3  |. 83ec 08        sub esp,0x8
      //0x83,0x7d, 0x10, 0x00,            // 0093f9b6  |. 837d 10 00     cmp dword ptr ss:[ebp+0x10],0x0
      //0x53,                             // 0093f9ba  |. 53             push ebx
      //0x8b,0x5d, 0x0c,                  // 0093f9bb  |. 8b5d 0c        mov ebx,dword ptr ss:[ebp+0xc]
      //0x56,                             // 0093f9be  |. 56             push esi
      //0x57,                             // 0093f9bf  |. 57             push edi
      0x75, 0x0f,                       // 0093f9c0  |. 75 0f          jnz short silkys.0093f9d1
      0x8b,0x45, 0x08,                  // 0093f9c2  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
      0x8b,0x48, 0x04,                  // 0093f9c5  |. 8b48 04        mov ecx,dword ptr ds:[eax+0x4]
      0x8b,0x91, 0x90,0x00,0x00,0x00    // 0093f9c8  |. 8b91 90000000  mov edx,dword ptr ds:[ecx+0x90]
  };
  //enum { hook_offset = 0xc };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr);
  //addr = 0x42f170; // 愛姉妹4 Trial
  //reladdr = 0x2f9b0; // 愛姉妹4
  //reladdr = 0x2f0f0; // SEXティーチャー剛史 trial
  if (!addr) {
    ConsoleOutput("vnreng:Elf: pattern not found");
    return false;
  }

  enum : BYTE { push_ebp = 0x55 };
  for (int i = 0; i < 0x20; i++, addr--) // value of i is supposed to be 0xc or 0x10
    if (*(BYTE *)addr == push_ebp) { // beginning of the function

      HookParam hp = {};
      hp.addr = addr;
      hp.extern_fun = (HookParam::extern_fun_t)SpecialHookElf;
      hp.type = EXTERN_HOOK|USING_STRING|NO_CONTEXT; // = 9

      ConsoleOutput("vnreng: INSERT Elf");
      NewHook(hp, L"Elf");
      return true;
    }
  ConsoleOutput("vnreng:Elf: function not found");
  return false;
}

/** jichi 6/1/2014 Eushully
 *  Insert to the last GetTextExtentPoint32A
 */
bool InsertEushullyHook()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:Eushully: failed to get memory range");
    return false;
  }
  ULONG addr = MemDbg::findLastCallerAddressAfterInt3((DWORD)::GetTextExtentPoint32A, startAddress, stopAddress);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:Eushully: failed");
    return false;
  }

  // BOOL GetTextExtentPoint32(
  //   _In_   HDC hdc,
  //   _In_   LPCTSTR lpString,
  //   _In_   int c,
  //   _Out_  LPSIZE lpSize
  // );
  enum stack { // current stack
    //retaddr = 0 // esp[0] is the return address since this is the beginning of the function
    arg1_hdc = 4 * 1 // 0x4
    , arg2_lpString = 4 * 2 // 0x8
    , arg3_lc = 4 * 3 // 0xc
    , arg4_lpSize = 4 * 4 // 0x10
  };

  HookParam hp = {};
  hp.addr = addr;
  hp.type = USING_STRING|FIXING_SPLIT; // merging all threads
  hp.off = arg2_lpString; // arg2 = 0x4 * 2
  ConsoleOutput("vnreng: INSERT Eushully");
  NewHook(hp, L"Eushully");
  return true;
}

/** jichi 6/1/2014 AMUSE CRAFT
 *  Related brands: http://erogetrailers.com/brand/2047
 *  Sample game: 魔女こいにっき
 *  See:  http://sakuradite.com/topic/223
 *  Sample H-code: /HBN-4*0:18@26159:MAJOKOI_try.exe (need remove context, though)
 *
 *  Sample games:
 *  - 時計仕掛けのレイライン
 *  - きみと僕との騎士の日々
 *
 *  /HBN-4*0:18@26159:MAJOKOI_TRY.EXE
 *  - addr: 155993
 *  - length_offset: 1
 *  - module: 104464j455
 *  - off: 4294967288 = 0xfffffff8
 *  - split: 24 = 0x18
 *  - type: 1112 = 0x458
 *
 *  Call graph:
 *  - hook reladdr:  0x26159, fun reladdr: 26150
 *  - scene fun reladdr: 0x26fd0
 *    - arg1 and arg3 are pointers
 *    - arg2 is the text
 *  - scneairo only reladdr: 0x26670
 *  Issue for implementing embeded engine: two functions are needed to be hijacked
 *
 *  013c614e     cc             int3
 *  013c614f     cc             int3
 *  013c6150  /$ 55             push ebp ; jichi: function starts
 *  013c6151  |. 8bec           mov ebp,esp
 *  013c6153  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  013c6156  |. 0fb608         movzx ecx,byte ptr ds:[eax]
 *  013c6159  |. 81f9 81000000  cmp ecx,0x81 ; jichi: hook here
 *  013c615f  |. 7c 0d          jl short majokoi_.013c616e
 *  013c6161  |. 8b55 08        mov edx,dword ptr ss:[ebp+0x8]
 *  013c6164  |. 0fb602         movzx eax,byte ptr ds:[edx]
 *  013c6167  |. 3d 9f000000    cmp eax,0x9f
 *  013c616c  |. 7e 1c          jle short majokoi_.013c618a
 *  013c616e  |> 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  013c6171  |. 0fb611         movzx edx,byte ptr ds:[ecx]
 *  013c6174  |. 81fa e0000000  cmp edx,0xe0
 *  013c617a  |. 7c 30          jl short majokoi_.013c61ac
 *  013c617c  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  013c617f  |. 0fb608         movzx ecx,byte ptr ds:[eax]
 *  013c6182  |. 81f9 fc000000  cmp ecx,0xfc
 *  013c6188  |. 7f 22          jg short majokoi_.013c61ac
 *  013c618a  |> 8b55 08        mov edx,dword ptr ss:[ebp+0x8]
 *  013c618d  |. 0fb642 01      movzx eax,byte ptr ds:[edx+0x1]
 *  013c6191  |. 83f8 40        cmp eax,0x40
 *  013c6194  |. 7c 16          jl short majokoi_.013c61ac
 *  013c6196  |. 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  013c6199  |. 0fb651 01      movzx edx,byte ptr ds:[ecx+0x1]
 *  013c619d  |. 81fa fc000000  cmp edx,0xfc
 *  013c61a3  |. 7f 07          jg short majokoi_.013c61ac
 *  013c61a5  |. b8 01000000    mov eax,0x1
 *  013c61aa  |. eb 02          jmp short majokoi_.013c61ae
 *  013c61ac  |> 33c0           xor eax,eax
 *  013c61ae  |> 5d             pop ebp
 *  013c61af  \. c3             retn
 */
bool InsertAmuseCraftHook()
{
  const BYTE bytes[] = {
    0x55,                 // 013c6150  /$ 55             push ebp ; jichi: function starts
    0x8b,0xec,            // 013c6151  |. 8bec           mov ebp,esp
    0x8b,0x45, 0x08,      // 013c6153  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
    0x0f,0xb6,0x08,       // 013c6156  |. 0fb608         movzx ecx,byte ptr ds:[eax]
    0x81,0xf9 //81000000  // 013c6159  |. 81f9 81000000  cmp ecx,0x81 ; jichi: hook here
  };
  enum { hook_offset = sizeof(bytes) - 2 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(reladdr); // supposed to be 0x21650
  //ITH_GROWL_DWORD(reladdr  + hook_offset);
  //reladdr = 0x26159; // 魔女こいにっき trial
  if (!addr) {
    ConsoleOutput("vnreng:AMUSE CRAFT: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.type = NO_CONTEXT|USING_SPLIT|DATA_INDIRECT; // 0x418
  //hp.type = NO_CONTEXT|USING_SPLIT|DATA_INDIRECT|RELATIVE_SPLIT;  // Use relative address to prevent floating issue
  hp.type = NO_CONTEXT|USING_SPLIT|DATA_INDIRECT;
  hp.off = -0x8; // eax
  //hp.split = 0x18;
  //hp.split = 0x4; // This is supposed to be the return address
  hp.split = 0x20; // arg6
  hp.length_offset = 1;
  ConsoleOutput("vnreng: INSERT AMUSE CRAFT");
  NewHook(hp, L"AMUSE CRAFT");
  return true;
}

/** jichi 7/6/2014 NeXAS
 *  Sample game: BALDRSKYZERO EXTREME
 *
 *  Call graph:
 *  - GetGlyphOutlineA x 2 functions
 *  - Caller 503620: char = [arg1 + 0x1a8]
 *  - Caller: 500039, 4ffff0
 *    edi = [esi+0x1a0] # stack size 4x3
 *    arg1 = eax = [edi]
 *
 *  0050361f     cc             int3
 *  00503620  /$ 55             push ebp
 *  00503621  |. 8bec           mov ebp,esp
 *  00503623  |. 83e4 f8        and esp,0xfffffff8
 *  00503626  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  0050362c  |. 6a ff          push -0x1
 *  0050362e  |. 68 15815900    push bszex.00598115
 *  00503633  |. 50             push eax
 *  00503634  |. 64:8925 000000>mov dword ptr fs:[0],esp
 *  0050363b  |. 81ec 78010000  sub esp,0x178
 *  00503641  |. 53             push ebx
 *  00503642  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
 *  00503645  |. 80bb ed010000 >cmp byte ptr ds:[ebx+0x1ed],0x0
 *  0050364c  |. 56             push esi
 *  0050364d  |. 57             push edi
 *  0050364e  |. 0f85 6e0b0000  jnz bszex.005041c2
 *  00503654  |. 8db3 a8010000  lea esi,dword ptr ds:[ebx+0x1a8]
 *  0050365a  |. c683 ed010000 >mov byte ptr ds:[ebx+0x1ed],0x1
 *  00503661  |. 837e 14 10     cmp dword ptr ds:[esi+0x14],0x10
 *  00503665  |. 72 04          jb short bszex.0050366b
 *  00503667  |. 8b06           mov eax,dword ptr ds:[esi]
 *  00503669  |. eb 02          jmp short bszex.0050366d
 *  0050366b  |> 8bc6           mov eax,esi
 *  0050366d  |> 8038 20        cmp byte ptr ds:[eax],0x20
 *  00503670  |. 0f84 ef0a0000  je bszex.00504165
 *  00503676  |. b9 fcc97400    mov ecx,bszex.0074c9fc
 *  0050367b  |. 8bfe           mov edi,esi
 *  0050367d  |. e8 2e20f1ff    call bszex.004156b0
 *  00503682  |. 84c0           test al,al
 *  00503684  |. 0f85 db0a0000  jnz bszex.00504165
 *  0050368a  |. 8b93 38010000  mov edx,dword ptr ds:[ebx+0x138]
 *  00503690  |. 33c0           xor eax,eax
 *  00503692  |. 3bd0           cmp edx,eax
 *  00503694  |. 0f84 8d0a0000  je bszex.00504127
 *  0050369a  |. 8b8b 3c010000  mov ecx,dword ptr ds:[ebx+0x13c]
 *  005036a0  |. 3bc8           cmp ecx,eax
 *  005036a2  |. 0f84 7f0a0000  je bszex.00504127
 *  005036a8  |. 894424 40      mov dword ptr ss:[esp+0x40],eax
 *  005036ac  |. 894424 44      mov dword ptr ss:[esp+0x44],eax
 *  005036b0  |. 894424 48      mov dword ptr ss:[esp+0x48],eax
 *  005036b4  |. 898424 8c01000>mov dword ptr ss:[esp+0x18c],eax
 *  005036bb  |. 33ff           xor edi,edi
 *  005036bd  |. 66:897c24 60   mov word ptr ss:[esp+0x60],di
 *  005036c2  |. bf 01000000    mov edi,0x1
 *  005036c7  |. 66:897c24 62   mov word ptr ss:[esp+0x62],di
 *  005036cc  |. 33ff           xor edi,edi
 *  005036ce  |. 66:897c24 64   mov word ptr ss:[esp+0x64],di
 *  005036d3  |. 66:897c24 66   mov word ptr ss:[esp+0x66],di
 *  005036d8  |. 66:897c24 68   mov word ptr ss:[esp+0x68],di
 *  005036dd  |. 66:897c24 6a   mov word ptr ss:[esp+0x6a],di
 *  005036e2  |. 66:897c24 6c   mov word ptr ss:[esp+0x6c],di
 *  005036e7  |. bf 01000000    mov edi,0x1
 *  005036ec  |. 66:897c24 6e   mov word ptr ss:[esp+0x6e],di
 *  005036f1  |. 894424 0c      mov dword ptr ss:[esp+0xc],eax
 *  005036f5  |. 894424 10      mov dword ptr ss:[esp+0x10],eax
 *  005036f9  |. 3883 ec010000  cmp byte ptr ds:[ebx+0x1ec],al
 *  005036ff  |. 0f84 39010000  je bszex.0050383e
 *  00503705  |. c78424 f000000>mov dword ptr ss:[esp+0xf0],bszex.00780e>
 *  00503710  |. 898424 3001000>mov dword ptr ss:[esp+0x130],eax
 *  00503717  |. 898424 1001000>mov dword ptr ss:[esp+0x110],eax
 *  0050371e  |. 898424 1401000>mov dword ptr ss:[esp+0x114],eax
 *  00503725  |. c68424 8c01000>mov byte ptr ss:[esp+0x18c],0x1
 *  0050372d  |. 837e 14 10     cmp dword ptr ds:[esi+0x14],0x10
 *  00503731  |. 72 02          jb short bszex.00503735
 *  00503733  |. 8b36           mov esi,dword ptr ds:[esi]
 *  00503735  |> 51             push ecx
 *  00503736  |. 52             push edx
 *  00503737  |. 56             push esi
 *  00503738  |. 8d8424 ec00000>lea eax,dword ptr ss:[esp+0xec]
 *  0050373f  |. 68 00ca7400    push bszex.0074ca00                      ;  ascii "gaiji%s%02d%02d.fil"
 *  00503744  |. 50             push eax
 *  00503745  |. e8 cec6f7ff    call bszex.0047fe18
 *  0050374a  |. 83c4 14        add esp,0x14
 *  0050374d  |. 8d8c24 e000000>lea ecx,dword ptr ss:[esp+0xe0]
 *  00503754  |. 51             push ecx                                 ; /arg1
 *  00503755  |. 8d8c24 9400000>lea ecx,dword ptr ss:[esp+0x94]          ; |
 *  0050375c  |. e8 dfeaefff    call bszex.00402240                      ; \bszex.00402240
 *  00503761  |. 6a 00          push 0x0                                 ; /arg4 = 00000000
 *  00503763  |. 8d9424 9400000>lea edx,dword ptr ss:[esp+0x94]          ; |
 *  0050376a  |. c68424 9001000>mov byte ptr ss:[esp+0x190],0x2          ; |
 *  00503772  |. a1 a8a78200    mov eax,dword ptr ds:[0x82a7a8]          ; |
 *  00503777  |. 52             push edx                                 ; |arg3
 *  00503778  |. 50             push eax                                 ; |arg2 => 00000000
 *  00503779  |. 8d8c24 fc00000>lea ecx,dword ptr ss:[esp+0xfc]          ; |
 *  00503780  |. 51             push ecx                                 ; |arg1
 *  00503781  |. e8 2a0dfeff    call bszex.004e44b0                      ; \bszex.004e44b0
 *  00503786  |. 84c0           test al,al
 *  00503788  |. 8d8c24 9000000>lea ecx,dword ptr ss:[esp+0x90]
 *  0050378f  |. 0f95c3         setne bl
 *  00503792  |. c68424 8c01000>mov byte ptr ss:[esp+0x18c],0x1
 *  0050379a  |. e8 a1baf1ff    call bszex.0041f240
 *  0050379f  |. 84db           test bl,bl
 *  005037a1  |. 74 40          je short bszex.005037e3
 *  005037a3  |. 8db424 f000000>lea esi,dword ptr ss:[esp+0xf0]
 *  005037aa  |. e8 6106feff    call bszex.004e3e10
 *  005037af  |. 8bd8           mov ebx,eax
 *  005037b1  |. 895c24 0c      mov dword ptr ss:[esp+0xc],ebx
 *  005037b5  |. e8 5606feff    call bszex.004e3e10
 *  005037ba  |. 8bf8           mov edi,eax
 *  005037bc  |. 0faffb         imul edi,ebx
 *  005037bf  |. 894424 10      mov dword ptr ss:[esp+0x10],eax
 *  005037c3  |. 8bc7           mov eax,edi
 *  005037c5  |. 8d7424 40      lea esi,dword ptr ss:[esp+0x40]
 *  005037c9  |. e8 e219f1ff    call bszex.004151b0
 *  005037ce  |. 8b5424 40      mov edx,dword ptr ss:[esp+0x40]
 *  005037d2  |. 52             push edx                                 ; /arg1
 *  005037d3  |. 8bc7           mov eax,edi                              ; |
 *  005037d5  |. 8db424 f400000>lea esi,dword ptr ss:[esp+0xf4]          ; |
 *  005037dc  |. e8 8f03feff    call bszex.004e3b70                      ; \bszex.004e3b70
 *  005037e1  |. eb 10          jmp short bszex.005037f3
 *  005037e3  |> 8d8424 e000000>lea eax,dword ptr ss:[esp+0xe0]
 *  005037ea  |. 50             push eax
 *  005037eb  |. e8 60c5f2ff    call bszex.0042fd50
 *  005037f0  |. 83c4 04        add esp,0x4
 *  005037f3  |> 8b5c24 10      mov ebx,dword ptr ss:[esp+0x10]
 *  005037f7  |. 8b7c24 40      mov edi,dword ptr ss:[esp+0x40]
 *  005037fb  |. 8bcb           mov ecx,ebx
 *  005037fd  |. 0faf4c24 0c    imul ecx,dword ptr ss:[esp+0xc]
 *  00503802  |. 33c0           xor eax,eax
 *  00503804  |. 85c9           test ecx,ecx
 *  00503806  |. 7e 09          jle short bszex.00503811
 *  00503808  |> c02c07 02      /shr byte ptr ds:[edi+eax],0x2
 *  0050380c  |. 40             |inc eax
 *  0050380d  |. 3bc1           |cmp eax,ecx
 *  0050380f  |.^7c f7          \jl short bszex.00503808
 *  00503811  |> 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  00503814  |. 33c0           xor eax,eax
 *  00503816  |. 8db424 f000000>lea esi,dword ptr ss:[esp+0xf0]
 *  0050381d  |. 8981 dc010000  mov dword ptr ds:[ecx+0x1dc],eax
 *  00503823  |. 8981 e0010000  mov dword ptr ds:[ecx+0x1e0],eax
 *  00503829  |. c78424 f000000>mov dword ptr ss:[esp+0xf0],bszex.00780e>
 *  00503834  |. e8 4702feff    call bszex.004e3a80
 *  00503839  |. e9 68010000    jmp bszex.005039a6
 *  0050383e  |> 8b0d 08a58200  mov ecx,dword ptr ds:[0x82a508]
 *  00503844  |. 51             push ecx                                 ; /hwnd => null
 *  00503845  |. ff15 d4e26f00  call dword ptr ds:[<&user32.getdc>]      ; \getdc
 *  0050384b  |. 68 50b08200    push bszex.0082b050                      ; /facename = ""
 *  00503850  |. 6a 00          push 0x0                                 ; |pitchandfamily = default_pitch|ff_dontcare
 *  00503852  |. 6a 02          push 0x2                                 ; |quality = proof_quality
 *  00503854  |. 6a 00          push 0x0                                 ; |clipprecision = clip_default_precis
 *  00503856  |. 6a 07          push 0x7                                 ; |outputprecision = out_tt_only_precis
 *  00503858  |. 68 80000000    push 0x80                                ; |charset = 128.
 *  0050385d  |. 6a 00          push 0x0                                 ; |strikeout = false
 *  0050385f  |. 6a 00          push 0x0                                 ; |underline = false
 *  00503861  |. 8bf8           mov edi,eax                              ; |
 *  00503863  |. 8b83 38010000  mov eax,dword ptr ds:[ebx+0x138]         ; |
 *  00503869  |. 6a 00          push 0x0                                 ; |italic = false
 *  0050386b  |. 68 84030000    push 0x384                               ; |weight = fw_heavy
 *  00503870  |. 99             cdq                                      ; |
 *  00503871  |. 6a 00          push 0x0                                 ; |orientation = 0x0
 *  00503873  |. 2bc2           sub eax,edx                              ; |
 *  00503875  |. 8b93 3c010000  mov edx,dword ptr ds:[ebx+0x13c]         ; |
 *  0050387b  |. 6a 00          push 0x0                                 ; |escapement = 0x0
 *  0050387d  |. d1f8           sar eax,1                                ; |
 *  0050387f  |. 50             push eax                                 ; |width
 *  00503880  |. 52             push edx                                 ; |height
 *  00503881  |. ff15 48e06f00  call dword ptr ds:[<&gdi32.createfonta>] ; \createfonta
 *  00503887  |. 50             push eax                                 ; /hobject
 *  00503888  |. 57             push edi                                 ; |hdc
 *  00503889  |. 894424 30      mov dword ptr ss:[esp+0x30],eax          ; |
 *  0050388d  |. ff15 4ce06f00  call dword ptr ds:[<&gdi32.selectobject>>; \selectobject
 *  00503893  |. 894424 1c      mov dword ptr ss:[esp+0x1c],eax
 *  00503897  |. 8d8424 4801000>lea eax,dword ptr ss:[esp+0x148]
 *  0050389e  |. 50             push eax                                 ; /ptextmetric
 *  0050389f  |. 57             push edi                                 ; |hdc
 *  005038a0  |. ff15 50e06f00  call dword ptr ds:[<&gdi32.gettextmetric>; \gettextmetricsa
 *  005038a6  |. 837e 14 10     cmp dword ptr ds:[esi+0x14],0x10
 *  005038aa  |. 72 02          jb short bszex.005038ae
 *  005038ac  |. 8b36           mov esi,dword ptr ds:[esi]
 *  005038ae  |> 56             push esi                                 ; /arg1
 *  005038af  |. e8 deccf7ff    call bszex.00480592                      ; \bszex.00480592
 *  005038b4  |. 83c4 04        add esp,0x4
 *  005038b7  |. 8d4c24 60      lea ecx,dword ptr ss:[esp+0x60]
 *  005038bb  |. 51             push ecx                                 ; /pmat2
 *  005038bc  |. 6a 00          push 0x0                                 ; |buffer = null
 *  005038be  |. 6a 00          push 0x0                                 ; |bufsize = 0x0
 *  005038c0  |. 8d9424 d800000>lea edx,dword ptr ss:[esp+0xd8]          ; |
 *  005038c7  |. 52             push edx                                 ; |pmetrics
 *  005038c8  |. 6a 06          push 0x6                                 ; |format = ggo_gray8_bitmap
 *  005038ca  |. 50             push eax                                 ; |char
 *  005038cb  |. 57             push edi                                 ; |hdc
 *  005038cc  |. 894424 30      mov dword ptr ss:[esp+0x30],eax          ; |
 *  005038d0  |. ff15 54e06f00  call dword ptr ds:[<&gdi32.getglyphoutli>; \getglyphoutlinea
 *  005038d6  |. 8bd8           mov ebx,eax
 *  005038d8  |. 85db           test ebx,ebx
 *  005038da  |. 0f84 d5070000  je bszex.005040b5
 *  005038e0  |. 83fb ff        cmp ebx,-0x1
 *  005038e3  |. 0f84 cc070000  je bszex.005040b5
 *  005038e9  |. 8d7424 40      lea esi,dword ptr ss:[esp+0x40]
 *  005038ed  |. e8 be18f1ff    call bszex.004151b0
 *  005038f2  |. 8b4c24 40      mov ecx,dword ptr ss:[esp+0x40]
 *  005038f6  |. 8d4424 60      lea eax,dword ptr ss:[esp+0x60]
 *  005038fa  |. 50             push eax                                 ; /pmat2
 *  005038fb  |. 8b4424 18      mov eax,dword ptr ss:[esp+0x18]          ; |
 *  005038ff  |. 51             push ecx                                 ; |buffer
 *  00503900  |. 53             push ebx                                 ; |bufsize
 *  00503901  |. 8d9424 d800000>lea edx,dword ptr ss:[esp+0xd8]          ; |
 *  00503908  |. 52             push edx                                 ; |pmetrics
 *  00503909  |. 6a 06          push 0x6                                 ; |format = ggo_gray8_bitmap
 *  0050390b  |. 50             push eax                                 ; |char
 *  0050390c  |. 57             push edi                                 ; |hdc
 *  0050390d  |. ff15 54e06f00  call dword ptr ds:[<&gdi32.getglyphoutli>; \getglyphoutlinea
 *  00503913  |. 8b4c24 1c      mov ecx,dword ptr ss:[esp+0x1c]
 *  00503917  |. 51             push ecx                                 ; /hobject
 *  00503918  |. 57             push edi                                 ; |hdc
 *  00503919  |. ff15 4ce06f00  call dword ptr ds:[<&gdi32.selectobject>>; \selectobject
 *  0050391f  |. 8b15 08a58200  mov edx,dword ptr ds:[0x82a508]
 *  00503925  |. 57             push edi                                 ; /hdc
 *  00503926  |. 52             push edx                                 ; |hwnd => null
 *  00503927  |. ff15 a4e26f00  call dword ptr ds:[<&user32.releasedc>]  ; \releasedc
 *  0050392d  |. 8b4424 28      mov eax,dword ptr ss:[esp+0x28]
 *  00503931  |. 50             push eax                                 ; /hobject
 *  00503932  |. ff15 58e06f00  call dword ptr ds:[<&gdi32.deleteobject>>; \deleteobject
 *  00503938  |. 8bb424 cc00000>mov esi,dword ptr ss:[esp+0xcc]
 *  0050393f  |. 8b8c24 d000000>mov ecx,dword ptr ss:[esp+0xd0]
 *  00503946  |. 83c6 03        add esi,0x3
 *  00503949  |. 81e6 fcff0000  and esi,0xfffc
 *  0050394f  |. 8bd1           mov edx,ecx
 *  00503951  |. 0fafd6         imul edx,esi
 *  00503954  |. 897424 0c      mov dword ptr ss:[esp+0xc],esi
 *  00503958  |. 894c24 10      mov dword ptr ss:[esp+0x10],ecx
 *  0050395c  |. 3bda           cmp ebx,edx
 *  0050395e  |. 74 1a          je short bszex.0050397a
 */
bool InsertNeXASHook()
{
  // There are two GetGlyphOutlineA, both of which seem to have the same texts
  ULONG addr = MemDbg::findCallAddress((ULONG)::GetGlyphOutlineA, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:NexAS: failed");
    return false;
  }

  // DWORD GetGlyphOutline(
  //   _In_   HDC hdc,
  //   _In_   UINT uChar,
  //   _In_   UINT uFormat,
  //   _Out_  LPGLYPHMETRICS lpgm,
  //   _In_   DWORD cbBuffer,
  //   _Out_  LPVOID lpvBuffer,
  //   _In_   const MAT2 *lpmat2
  // );
  enum stack { // current stack
    arg1_hdc = 4 * 0 // starting from 0 before function call
    , arg2_uChar = 4 * 1
    , arg3_uFormat = 4 * 2
    , arg4_lpgm = 4 * 3
    , arg5_cbBuffer = 4 * 4
    , arg6_lpvBuffer = 4 * 5
    , arg7_lpmat2 = 4 * 6
  };

  HookParam hp = {};
  //hp.addr = (DWORD)::GetGlyphOutlineA;
  hp.addr = addr;
  //hp.type = USING_STRING|USING_SPLIT;
  hp.type = BIG_ENDIAN|NO_CONTEXT|USING_SPLIT;
  hp.length_offset = 1; // determine string length at runtime
  hp.off = arg2_uChar; // = 0x4, arg2 before the function call, so it is: 0x4 * (2-1) = 4

  // Either lpgm or lpmat2 are good choices
  hp.split = arg4_lpgm; // = 0xc, arg4
  //hp.split = arg7_lpmat2; // = 0x18, arg7

  ConsoleOutput("vnreng: INSERT NeXAS");
  NewHook(hp, L"NeXAS");
  return true;
}

/** jichi 7/6/2014 YukaSystem2
 *  Sample game: セミラミスの天秤
 *
 *  Observations from Debug:
 *  - Ollydbg got UTF8 text memory address
 *  - Hardware break points have loops on 0x4010ED
 *  - The hooked function seems to take 3 parameters, and arg3 is the right text
 *  - The text appears character by character
 *
 *  Runtime stack:
 *  - return address
 *  - arg1 pointer's pointer
 *  - arg2 text
 *  - arg3 pointer's pointer
 *  - code address or -1, maybe a handle
 *  - unknown pointer
 *  - return address
 *  - usually zero
 *
 *  0040109d     cc             int3
 *  0040109e     cc             int3
 *  0040109f     cc             int3
 *  004010a0  /$ 55             push ebp
 *  004010a1  |. 8bec           mov ebp,esp
 *  004010a3  |. 8b45 14        mov eax,dword ptr ss:[ebp+0x14]
 *  004010a6  |. 50             push eax                                 ; /arg4
 *  004010a7  |. 8b4d 10        mov ecx,dword ptr ss:[ebp+0x10]          ; |
 *  004010aa  |. 51             push ecx                                 ; |arg3
 *  004010ab  |. 8b55 0c        mov edx,dword ptr ss:[ebp+0xc]           ; |
 *  004010ae  |. 52             push edx                                 ; |arg2
 *  004010af  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]           ; |
 *  004010b2  |. 50             push eax                                 ; |arg1
 *  004010b3  |. e8 48ffffff    call semirami.00401000                   ; \semirami.00401000
 *  004010b8  |. 83c4 10        add esp,0x10
 *  004010bb  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  004010be  |. 5d             pop ebp
 *  004010bf  \. c3             retn
 *  004010c0  /$ 55             push ebp
 *  004010c1  |. 8bec           mov ebp,esp
 *  004010c3  |. 8b45 14        mov eax,dword ptr ss:[ebp+0x14]
 *  004010c6  |. 50             push eax                                 ; /arg4
 *  004010c7  |. 8b4d 10        mov ecx,dword ptr ss:[ebp+0x10]          ; |
 *  004010ca  |. 51             push ecx                                 ; |arg3
 *  004010cb  |. 8b55 0c        mov edx,dword ptr ss:[ebp+0xc]           ; |
 *  004010ce  |. 52             push edx                                 ; |arg2
 *  004010cf  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]           ; |
 *  004010d2  |. 50             push eax                                 ; |arg1
 *  004010d3  |. e8 58ffffff    call semirami.00401030                   ; \semirami.00401030
 *  004010d8  |. 83c4 10        add esp,0x10
 *  004010db  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  004010de  |. 5d             pop ebp
 *  004010df  \. c3             retn
 *  004010e0  /$ 55             push ebp ; jichi: function begin, hook here, bp-based frame, arg2 is the text
 *  004010e1  |. 8bec           mov ebp,esp
 *  004010e3  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8] ; jichi: ebp+0x8 = arg2
 *  004010e6  |. 8b4d 0c        mov ecx,dword ptr ss:[ebp+0xc] ; jichi: arg3 is also a pointer of pointer
 *  004010e9  |. 8a11           mov dl,byte ptr ds:[ecx]
 *  004010eb  |. 8810           mov byte ptr ds:[eax],dl    ; jichi: eax is the data
 *  004010ed  |. 5d             pop ebp
 *  004010ee  \. c3             retn
 *  004010ef     cc             int3
 */

// Ignore image and music file names
// Sample text: "Voice\tou00012.ogg""運命論って云うのかなあ……神さまを信じてる人が多かったからだろうね、何があっても、それは神さまが自分たちに与えられた試練なんだって、そう思ってたみたい。勿論、今でもそう考えている人はいっぱいいるんだけど。"
// Though the input string is UTF-8, it should be ASCII compatible.
static bool _yk2garbage(const char *p)
{
  //Q_ASSERT(p);
  while (char ch = *p++) {
    if (ch >= '0' && ch <= '9' ||
        ch >= 'A' && ch <= 'z' || // also ignore ASCII 91-96: [ \ ] ^ _ `
        ch == '"' || ch == '.' || ch == '-' || ch == '#')
      continue;
    return false;
  }
  return true;
}

// Get text from arg2
static void SpecialHookYukaSystem2(DWORD esp_base, HookParam *hp, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD arg2 = argof(2, esp_base), // [esp+0x8]
        arg3 = argof(3, esp_base); // [esp+0xc]
        //arg4 = argof(4, esp_base); // there is no arg4. arg4 is properlly a function pointer
  LPCSTR text = (LPCSTR)arg2;
  if (*text && !_yk2garbage(text)) { // I am sure this could be null
    *data = (DWORD)text;
    *len = ::strlen(text); // UTF-8 is null-terminated
    if (arg3)
      *split = *(DWORD *)arg3;
  }
}

bool InsertYukaSystem2Hook()
{
  const BYTE bytes[] = {
    0x55,            // 004010e0  /$ 55             push ebp ; jichi; hook here
    0x8b,0xec,       // 004010e1  |. 8bec           mov ebp,esp
    0x8b,0x45, 0x08, // 004010e3  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8] ; jichi: ebp+0x8 = arg2
    0x8b,0x4d, 0x0c, // 004010e6  |. 8b4d 0c        mov ecx,dword ptr ss:[ebp+0xc]
    0x8a,0x11,       // 004010e9  |. 8a11           mov dl,byte ptr ds:[ecx]
    0x88,0x10,       // 004010eb  |. 8810           mov byte ptr ds:[eax],dl    ; jichi: eax is the address to text
    0x5d,            // 004010ed  |. 5d             pop ebp
    0xc3             // 004010ee  \. c3             retn
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:YukaSystem2: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = EXTERN_HOOK|NO_CONTEXT|USING_STRING; // UTF-8, though
  hp.extern_fun = SpecialHookYukaSystem2;
  ConsoleOutput("vnreng: INSERT YukaSystem2");
  NewHook(hp, L"YukaSystem2");
  return true;
}

/** jichi 8/2/2014 2RM
 *  Sample games:
 *  - [エロイット] 父娘愛 ～いけない子作り2～ - /HBN-20*0@54925:oyakoai.exe
 *  - [エロイット] いけない子作り ～親友のお母さんに種付けしまくる1週間～ -- /HS-1C@46FC9D (not used)
 *
 *  Observations from Debug of 父娘愛:
 *  - The executable shows product name as 2RM - Adventure Engine
 *  - 2 calls to GetGlyphOutlineA with incompleted game
 *  - Memory location of the text is fixed
 *  - The LAST place accessing the text is hooked
 *  - The actual text has pattern like this {surface,ruby} and hence not hooked
 *
 *  /HBN-20*0@54925:oyakoai.exe
 *  - addr: 346405 = 0x54925
 *  - length_offset: 1
 *  - module: 3918223605
 *  - off: 4294967260 = 0xffffffdc = -0x24 -- 0x24 comes from  mov ebp,dword ptr ss:[esp+0x24]
 *  - type: 1096 = 0x448
 *
 *  This is a very long function
 *  父娘愛:
 *  - 004548e1  |. 84db           test bl,bl
 *  - 004548e3  |. 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *  - 004548e7  |. 74 08          je short oyakoai.004548f1
 *  - 004548e9  |. c74424 24 0000>mov dword ptr ss:[esp+0x24],0x0
 *  - 004548f1  |> 8b6c24 3c      mov ebp,dword ptr ss:[esp+0x3c]
 *  - 004548f5  |. 837d 5c 00     cmp dword ptr ss:[ebp+0x5c],0x0
 *  - 004548f9  |. c74424 18 0000>mov dword ptr ss:[esp+0x18],0x0
 *  - 00454901  |. 0f8e da000000  jle oyakoai.004549e1
 *  - 00454907  |. 8b6c24 24      mov ebp,dword ptr ss:[esp+0x24]
 *  - 0045490b  |. eb 0f          jmp short oyakoai.0045491c
 *  - 0045490d  |  8d49 00        lea ecx,dword ptr ds:[ecx]
 *  - 00454910  |> 8b15 50bd6c00  mov edx,dword ptr ds:[0x6cbd50]
 *  - 00454916  |. 8b0d 94bd6c00  mov ecx,dword ptr ds:[0x6cbd94]
 *  - 0045491c  |> 803f 00        cmp byte ptr ds:[edi],0x0
 *  - 0045491f  |. 0f84 db000000  je oyakoai.00454a00
 *  - 00454925  |. 0fb717         movzx edx,word ptr ds:[edi]   ; jichi: hook here
 *  - 00454928  |. 8b4c24 10      mov ecx,dword ptr ss:[esp+0x10]
 *  - 0045492c  |. 52             push edx
 *  - 0045492d  |. 894c24 2c      mov dword ptr ss:[esp+0x2c],ecx
 *  - 00454931  |. e8 9a980100    call oyakoai.0046e1d0
 *  - 00454936  |. 83c4 04        add esp,0x4
 *  - 00454939  |. 85c0           test eax,eax
 *  - 0045493b  |. 74 50          je short oyakoai.0045498d
 *  - 0045493d  |. 0335 50bd6c00  add esi,dword ptr ds:[0x6cbd50]
 *  - 00454943  |. 84db           test bl,bl
 *  - 00454945  |. 74 03          je short oyakoai.0045494a
 *  - 00454947  |. 83c5 02        add ebp,0x2
 *  - 0045494a  |> 3b7424 1c      cmp esi,dword ptr ss:[esp+0x1c]
 *  - 0045494e  |. a1 54bd6c00    mov eax,dword ptr ds:[0x6cbd54]
 *  - 00454953  |. 7f 12          jg short oyakoai.00454967
 *  - 00454955  |. 84db           test bl,bl
 *  - 00454957  |. 0f84 ea000000  je oyakoai.00454a47
 *  - 0045495d  |. 3b6c24 40      cmp ebp,dword ptr ss:[esp+0x40]
 *  - 00454961  |. 0f85 e0000000  jnz oyakoai.00454a47
 *  - 00454967  |> 014424 10      add dword ptr ss:[esp+0x10],eax
 *  - 0045496b  |. 84db           test bl,bl
 *  - 0045496d  |. 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *  - 00454971  |. 0f84 d0000000  je oyakoai.00454a47
 *  - 00454977  |. 3b6c24 40      cmp ebp,dword ptr ss:[esp+0x40]
 *  - 0045497b  |. 0f85 c6000000  jnz oyakoai.00454a47
 *  - 00454981  |. 33ed           xor ebp,ebp
 *  - 00454983  |. 83c7 02        add edi,0x2
 *  - 00454986  |. 834424 18 01   add dword ptr ss:[esp+0x18],0x1
 *  - 0045498b  |. eb 3c          jmp short oyakoai.004549c9
 *  - 0045498d  |> a1 50bd6c00    mov eax,dword ptr ds:[0x6cbd50]
 *  - 00454992  |. d1e8           shr eax,1
 *  - 00454994  |. 03f0           add esi,eax
 *  - 00454996  |. 84db           test bl,bl
 *  - 00454998  |. 74 03          je short oyakoai.0045499d
 *  - 0045499a  |. 83c5 01        add ebp,0x1
 *  - 0045499d  |> 3b7424 1c      cmp esi,dword ptr ss:[esp+0x1c]
 *  - 004549a1  |. a1 54bd6c00    mov eax,dword ptr ds:[0x6cbd54]
 *  - 004549a6  |. 7f 0a          jg short oyakoai.004549b2
 *  - 004549a8  |. 84db           test bl,bl
 *
 *  いけない子作り:
 *  00454237   c74424 24 020000>mov dword ptr ss:[esp+0x24],0x2
 *  0045423f   3bf5             cmp esi,ebp
 *  00454241   7f 0e            jg short .00454251
 *  00454243   84db             test bl,bl
 *  00454245   74 1e            je short .00454265
 *  00454247   8b6c24 24        mov ebp,dword ptr ss:[esp+0x24]
 *  0045424b   3b6c24 40        cmp ebp,dword ptr ss:[esp+0x40]
 *  0045424f   75 14            jnz short .00454265
 *  00454251   014424 10        add dword ptr ss:[esp+0x10],eax
 *  00454255   84db             test bl,bl
 *  00454257   8b7424 20        mov esi,dword ptr ss:[esp+0x20]
 *  0045425b   74 08            je short .00454265
 *  0045425d   c74424 24 000000>mov dword ptr ss:[esp+0x24],0x0
 *  00454265   8b6c24 3c        mov ebp,dword ptr ss:[esp+0x3c]
 *  00454269   837d 5c 00       cmp dword ptr ss:[ebp+0x5c],0x0
 *  0045426d   c74424 18 000000>mov dword ptr ss:[esp+0x18],0x0
 *  00454275   0f8e d7000000    jle .00454352
 *  0045427b   8b6c24 24        mov ebp,dword ptr ss:[esp+0x24]
 *  0045427f   eb 0c            jmp short .0045428d
 *  00454281   8b15 18ad6c00    mov edx,dword ptr ds:[0x6cad18]
 *  00454287   8b0d 5cad6c00    mov ecx,dword ptr ds:[0x6cad5c]
 *  0045428d   803f 00          cmp byte ptr ds:[edi],0x0
 *  00454290   0f84 db000000    je .00454371
 *  00454296   0fb717           movzx edx,word ptr ds:[edi] ; jichi: hook here
 *  00454299   8b4c24 10        mov ecx,dword ptr ss:[esp+0x10]
 *  0045429d   52               push edx
 *  0045429e   894c24 2c        mov dword ptr ss:[esp+0x2c],ecx
 *  004542a2   e8 498a0100      call .0046ccf0
 *  004542a7   83c4 04          add esp,0x4
 *  004542aa   85c0             test eax,eax
 *  004542ac   74 50            je short .004542fe
 *  004542ae   0335 18ad6c00    add esi,dword ptr ds:[0x6cad18]
 *  004542b4   84db             test bl,bl
 *  004542b6   74 03            je short .004542bb
 *  004542b8   83c5 02          add ebp,0x2
 *  004542bb   3b7424 1c        cmp esi,dword ptr ss:[esp+0x1c]
 *  004542bf   a1 1cad6c00      mov eax,dword ptr ds:[0x6cad1c]
 *  004542c4   7f 12            jg short .004542d8
 *  004542c6   84db             test bl,bl
 *  004542c8   0f84 ea000000    je .004543b8
 *  004542ce   3b6c24 40        cmp ebp,dword ptr ss:[esp+0x40]
 *  004542d2   0f85 e0000000    jnz .004543b8
 *  004542d8   014424 10        add dword ptr ss:[esp+0x10],eax
 *  004542dc   84db             test bl,bl
 *  004542de   8b7424 20        mov esi,dword ptr ss:[esp+0x20]
 *  004542e2   0f84 d0000000    je .004543b8
 *  004542e8   3b6c24 40        cmp ebp,dword ptr ss:[esp+0x40]
 *  004542ec   0f85 c6000000    jnz .004543b8
 *  004542f2   33ed             xor ebp,ebp
 *  004542f4   83c7 02          add edi,0x2
 *  004542f7   834424 18 01     add dword ptr ss:[esp+0x18],0x1
 *  004542fc   eb 3c            jmp short .0045433a
 *  004542fe   a1 18ad6c00      mov eax,dword ptr ds:[0x6cad18]
 *  00454303   d1e8             shr eax,1
 *  00454305   03f0             add esi,eax
 *  00454307   84db             test bl,bl
 *  00454309   74 03            je short .0045430e
 *  0045430b   83c5 01          add ebp,0x1
 */
bool Insert2RMHook()
{
  const BYTE bytes[] = {
    0x80,0x3f, 0x00,                // 0045428d   803f 00          cmp byte ptr ds:[edi],0x0
    0x0f,0x84, 0xdb,0x00,0x00,0x00, // 00454290   0f84 db000000    je .00454371
    0x0f,0xb7,0x17,                 // 00454296   0fb717           movzx edx,word ptr ds:[edi] ; jichi: hook here
    0x8b,0x4c,0x24, 0x10,           // 00454299   8b4c24 10        mov ecx,dword ptr ss:[esp+0x10]
    0x52,                           // 0045429d   52               push edx
    0x89,0x4c,0x24, 0x2c,           // 0045429e   894c24 2c        mov dword ptr ss:[esp+0x2c],ecx
    0xe8 //, 498a0100               // 004542a2   e8 498a0100      call .0046ccf0
  };
  enum { hook_offset = 0x00454296 - 0x0045428d };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:2RM: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.length_offset = 1;
  hp.off = -0x24;
  hp.type = NO_CONTEXT|DATA_INDIRECT;
  ConsoleOutput("vnreng: INSERT 2RM");
  NewHook(hp, L"2RM");
  return true;
}

/** jichi 8/2/2014 side-B
 *  Sample games:
 *  - [side-B] メルトピア -- /HS-4@B4452:Martopia.exe
 *
 *  Observations:
 *
 *  /HS-4@B4452:Martopia.exe
 *  - addr: 738386 = 0xb4452
 *  - module: 3040177000
 *  - off: 4294967288 = 0xfffffff8 = -0x8
 *  - type: 65 = 0x41
 *
 *  Sample stack structure:
 *  - 0016F558   00EB74E9  RETURN to Martopia.00EB74E9
 *  - 0016F55C   0060EE30 ; jichi: this is the text
 *  - 0016F560   0016F5C8
 *  - 0016F564   082CAA98
 *  - 0016F568   00EBE735  RETURN to Martopia.00EBE735 from Martopia.00EB74C0
 *
 *  00f6440e   cc               int3
 *  00f6440f   cc               int3
 *  00f64410   55               push ebp    ; jichi: hook here, text in arg1 ([EncodeSystemPointer(+4])
 *  00f64411   8bec             mov ebp,esp
 *  00f64413   6a ff            push -0x1
 *  00f64415   68 c025fb00      push martopia.00fb25c0
 *  00f6441a   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  00f64420   50               push eax
 *  00f64421   83ec 3c          sub esp,0x3c
 *  00f64424   a1 c8620101      mov eax,dword ptr ds:[0x10162c8]
 *  00f64429   33c5             xor eax,ebp
 *  00f6442b   8945 f0          mov dword ptr ss:[ebp-0x10],eax
 *  00f6442e   53               push ebx
 *  00f6442f   56               push esi
 *  00f64430   57               push edi
 *  00f64431   50               push eax
 *  00f64432   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  00f64435   64:a3 00000000   mov dword ptr fs:[0],eax
 *  00f6443b   8bf9             mov edi,ecx
 *  00f6443d   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  00f64440   33db             xor ebx,ebx
 *  00f64442   3bcb             cmp ecx,ebx
 *  00f64444   74 40            je short martopia.00f64486
 *  00f64446   8bc1             mov eax,ecx
 *  00f64448   c745 e8 0f000000 mov dword ptr ss:[ebp-0x18],0xf
 *  00f6444f   895d e4          mov dword ptr ss:[ebp-0x1c],ebx
 *  00f64452   885d d4          mov byte ptr ss:[ebp-0x2c],bl   ; jichi: or hook here, get text in eax
 *  00f64455   8d70 01          lea esi,dword ptr ds:[eax+0x1]
 *  00f64458   8a10             mov dl,byte ptr ds:[eax]
 *  00f6445a   40               inc eax
 *  00f6445b   3ad3             cmp dl,bl
 *  00f6445d  ^75 f9            jnz short martopia.00f64458
 *  00f6445f   2bc6             sub eax,esi
 *  00f64461   50               push eax
 *  00f64462   51               push ecx
 *  00f64463   8d4d d4          lea ecx,dword ptr ss:[ebp-0x2c]
 *  00f64466   e8 f543f5ff      call martopia.00eb8860
 *  00f6446b   8d45 d4          lea eax,dword ptr ss:[ebp-0x2c]
 *  00f6446e   50               push eax
 *  00f6446f   8d4f 3c          lea ecx,dword ptr ds:[edi+0x3c]
 *  00f64472   895d fc          mov dword ptr ss:[ebp-0x4],ebx
 *  00f64475   e8 16d7f8ff      call martopia.00ef1b90
 *  00f6447a   837d e8 10       cmp dword ptr ss:[ebp-0x18],0x10
 *  00f6447e   72 47            jb short martopia.00f644c7
 *  00f64480   8b4d d4          mov ecx,dword ptr ss:[ebp-0x2c]
 *  00f64483   51               push ecx
 *  00f64484   eb 38            jmp short martopia.00f644be
 *  00f64486   53               push ebx
 *  00f64487   68 a11efd00      push martopia.00fd1ea1
 *  00f6448c   8d4d b8          lea ecx,dword ptr ss:[ebp-0x48]
 *  00f6448f   c745 cc 0f000000 mov dword ptr ss:[ebp-0x34],0xf
 *  00f64496   895d c8          mov dword ptr ss:[ebp-0x38],ebx
 *  00f64499   885d b8          mov byte ptr ss:[ebp-0x48],bl
 *  00f6449c   e8 bf43f5ff      call martopia.00eb8860
 *  00f644a1   8d55 b8          lea edx,dword ptr ss:[ebp-0x48]
 *  00f644a4   52               push edx
 *  00f644a5   8d4f 3c          lea ecx,dword ptr ds:[edi+0x3c]
 *  00f644a8   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  00f644af   e8 dcd6f8ff      call martopia.00ef1b90
 *  00f644b4   837d cc 10       cmp dword ptr ss:[ebp-0x34],0x10
 *  00f644b8   72 0d            jb short martopia.00f644c7
 *  00f644ba   8b45 b8          mov eax,dword ptr ss:[ebp-0x48]
 *  00f644bd   50               push eax
 *  00f644be   ff15 f891fc00    call dword ptr ds:[<&msvcr100.??3@yaxpax>; msvcr100.??3@yaxpax@z
 *  00f644c4   83c4 04          add esp,0x4
 *  00f644c7   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  00f644ca   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  00f644d1   59               pop ecx
 *  00f644d2   5f               pop edi
 *  00f644d3   5e               pop esi
 *  00f644d4   5b               pop ebx
 *  00f644d5   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  00f644d8   33cd             xor ecx,ebp
 *  00f644da   e8 77510400      call martopia.00fa9656
 *  00f644df   8be5             mov esp,ebp
 *  00f644e1   5d               pop ebp
 *  00f644e2   c2 0400          retn 0x4
 *  00f644e5   cc               int3
 *  00f644e6   cc               int3
 */
bool InsertSideBHook()
{
  const BYTE bytes[] = {
    0x64,0xa3, 0x00,0x00,0x00,0x00,       // 00f64435   64:a3 00000000   mov dword ptr fs:[0],eax
    0x8b,0xf9,                            // 00f6443b   8bf9             mov edi,ecx
    0x8b,0x4d, 0x08,                      // 00f6443d   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
    0x33,0xdb,                            // 00f64440   33db             xor ebx,ebx
    0x3b,0xcb,                            // 00f64442   3bcb             cmp ecx,ebx
    0x74, 0x40,                           // 00f64444   74 40            je short martopia.00f64486
    0x8b,0xc1,                            // 00f64446   8bc1             mov eax,ecx
    0xc7,0x45, 0xe8, 0x0f,0x00,0x00,0x00, // 00f64448   c745 e8 0f000000 mov dword ptr ss:[ebp-0x18],0xf
    0x89,0x5d, 0xe4,                      // 00f6444f   895d e4          mov dword ptr ss:[ebp-0x1c],ebx
    0x88,0x5d, 0xd4                       // 00f64452   885d d4          mov byte ptr ss:[ebp-0x2c],bl
  };
  enum { hook_offset = 0x00f64410 - 0x00f64435 }; // distance to the beginning of the function
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:SideB: pattern not found");
    return false;
  }
  addr += hook_offset;
  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (*(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:SideB: pattern found but the function offset is invalid");
    return false;
  }
  //ITH_GROWL_DWORD(addr);

  HookParam hp = {};
  hp.addr = addr;
  //hp.length_offset = 1;
  hp.off = 4; // [esp+4] == arg1
  hp.type = USING_STRING|NO_CONTEXT|USING_SPLIT|RELATIVE_SPLIT; // NO_CONTEXT && RELATIVE_SPLIT to get rid of floating return address
  //hp.split = 0; // use retaddr as split
  ConsoleOutput("vnreng: INSERT SideB");
  NewHook(hp, L"SideB");
  return true;
}

/** jichi 9/8/2014 EXP, http://www.exp-inc.jp
 *  Maker: EXP, 5pb
 *  Sample game: 剣の街の異邦人
 *
 *  There are three matched memory addresses with SHIFT-JIS.
 *  The middle one is used as it is aligned with zeros.
 *  The memory address is fixed.
 *
 *  There are three functions found using hardware breakpoints.
 *  The last one is used as the first two are looped.
 *
 *  reladdr = 0x138020
 *
 *  baseaddr = 0x00120000
 *
 *  0025801d   cc               int3
 *  0025801e   cc               int3
 *  0025801f   cc               int3
 *  00258020   55               push ebp  ; jichi: hook here
 *  00258021   8bec             mov ebp,esp
 *  00258023   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  00258026   83ec 08          sub esp,0x8
 *  00258029   85c0             test eax,eax
 *  0025802b   0f84 d8000000    je .00258109
 *  00258031   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0
 *  00258035   0f84 ce000000    je .00258109
 *  0025803b   8b10             mov edx,dword ptr ds:[eax]      ; jichi: edx is the text
 *  0025803d   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  00258040   53               push ebx
 *  00258041   56               push esi
 *  00258042   c745 f8 00000000 mov dword ptr ss:[ebp-0x8],0x0
 *  00258049   8945 fc          mov dword ptr ss:[ebp-0x4],eax
 *  0025804c   57               push edi
 *  0025804d   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  00258050   8a0a             mov cl,byte ptr ds:[edx]    jichi: text in accessed in edx
 *  00258052   8a45 14          mov al,byte ptr ss:[ebp+0x14]
 *  00258055   3ac1             cmp al,cl
 *  00258057   74 7a            je short .002580d3
 *  00258059   8b7d 10          mov edi,dword ptr ss:[ebp+0x10]
 *  0025805c   8b5d fc          mov ebx,dword ptr ss:[ebp-0x4]
 *  0025805f   33f6             xor esi,esi
 *  00258061   8bc2             mov eax,edx
 *  00258063   80f9 81          cmp cl,0x81
 *  00258066   72 05            jb short .0025806d
 *  00258068   80f9 9f          cmp cl,0x9f
 *  0025806b   76 0a            jbe short .00258077
 *  0025806d   80f9 e0          cmp cl,0xe0
 *  00258070   72 1d            jb short .0025808f
 *  00258072   80f9 fc          cmp cl,0xfc
 *  00258075   77 18            ja short .0025808f
 *  00258077   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 *  0025807a   85c0             test eax,eax
 *  0025807c   74 05            je short .00258083
 *  0025807e   8808             mov byte ptr ds:[eax],cl
 *  00258080   8d58 01          lea ebx,dword ptr ds:[eax+0x1]
 *  00258083   8b7d 10          mov edi,dword ptr ss:[ebp+0x10]
 *  00258086   8d42 01          lea eax,dword ptr ds:[edx+0x1]
 *  00258089   be 01000000      mov esi,0x1
 *  0025808e   4f               dec edi
 *  0025808f   85ff             test edi,edi
 *  00258091   74 36            je short .002580c9
 *  00258093   85db             test ebx,ebx
 *  00258095   74 04            je short .0025809b
 *  00258097   8a08             mov cl,byte ptr ds:[eax]
 *  00258099   880b             mov byte ptr ds:[ebx],cl
 *  0025809b   46               inc esi
 *  0025809c   33c0             xor eax,eax
 *  0025809e   66:3bc6          cmp ax,si
 *  002580a1   7f 47            jg short .002580ea
 *  002580a3   0fbfce           movsx ecx,si
 *  002580a6   03d1             add edx,ecx
 *  002580a8   3945 fc          cmp dword ptr ss:[ebp-0x4],eax
 *  002580ab   74 03            je short .002580b0
 *  002580ad   014d fc          add dword ptr ss:[ebp-0x4],ecx
 *  002580b0   294d 10          sub dword ptr ss:[ebp+0x10],ecx
 *  002580b3   014d f8          add dword ptr ss:[ebp-0x8],ecx
 *  002580b6   8a0a             mov cl,byte ptr ds:[edx]
 *  002580b8   80f9 0a          cmp cl,0xa
 *  002580bb   74 20            je short .002580dd
 *  002580bd   80f9 0d          cmp cl,0xd
 *  002580c0   74 1b            je short .002580dd
 *  002580c2   3945 10          cmp dword ptr ss:[ebp+0x10],eax
 *  002580c5  ^75 89            jnz short .00258050
 *  002580c7   eb 21            jmp short .002580ea
 *  002580c9   85db             test ebx,ebx
 *  002580cb   74 1d            je short .002580ea
 *  002580cd   c643 ff 00       mov byte ptr ds:[ebx-0x1],0x0
 *  002580d1   eb 17            jmp short .002580ea
 *  002580d3   84c0             test al,al
 *  002580d5   74 13            je short .002580ea
 *  002580d7   42               inc edx
 *  002580d8   ff45 f8          inc dword ptr ss:[ebp-0x8]
 *  002580db   eb 0d            jmp short .002580ea
 *  002580dd   8a42 01          mov al,byte ptr ds:[edx+0x1]
 *  002580e0   42               inc edx
 *  002580e1   3c 0a            cmp al,0xa
 *  002580e3   74 04            je short .002580e9
 *  002580e5   3c 0d            cmp al,0xd
 *  002580e7   75 01            jnz short .002580ea
 *  002580e9   42               inc edx
 *  002580ea   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 *  002580ed   5f               pop edi
 *  002580ee   5e               pop esi
 *  002580ef   5b               pop ebx
 *  002580f0   85c0             test eax,eax
 *  002580f2   74 09            je short .002580fd
 *  002580f4   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0
 *  002580f8   74 03            je short .002580fd
 *  002580fa   c600 00          mov byte ptr ds:[eax],0x0
 *  002580fd   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  00258100   8b45 f8          mov eax,dword ptr ss:[ebp-0x8]
 *  00258103   8911             mov dword ptr ds:[ecx],edx
 *  00258105   8be5             mov esp,ebp
 *  00258107   5d               pop ebp
 *  00258108   c3               retn
 *  00258109   33c0             xor eax,eax
 *  0025810b   8be5             mov esp,ebp
 *  0025810d   5d               pop ebp
 *  0025810e   c3               retn
 *  0025810f   cc               int3
 *
 *  Stack:
 *  0f14f87c   00279177  return to .00279177 from .00258020
 *  0f14f880   0f14f8b0 ; arg1  address of the text's pointer
 *  0f14f884   0f14f8c0 ; arg2  pointed to zero, maybe a buffer
 *  0f14f888   00000047 ; arg3  it is zero if no text, this value might be text size + 1
 *  0f14f88c   ffffff80 ; constant, used as split
 *  0f14f890   005768c8  .005768c8
 *  0f14f894   02924340 ; text is at 02924350
 *  0f14f898   00000001 ; this might also be a good split
 *  0f14f89c   1b520020
 *  0f14f8a0   00000000
 *  0f14f8a4   00000000
 *  0f14f8a8   029245fc
 *  0f14f8ac   0004bfd3
 *  0f14f8b0   0f14fae0
 *  0f14f8b4   00000000
 *  0f14f8b8   00000000
 *  0f14f8bc   02924340
 *  0f14f8c0   00000000
 *
 *  Registers:
 *  eax 0f14f8c0 ; floating at runtime
 *  ecx 0f14f8b0; floating at runtime
 *  edx 00000000
 *  ebx 0f14fae0; floating at runtime
 *  esp 0f14f87c; floating at runtime
 *  ebp 0f14facc; floating at runtime
 *  esi 00000047
 *  edi 02924340 ; text is in 02924350
 *  eip 00258020 .00258020
 *
 *  Memory access pattern:
 *  For long sentences, it first render the first line, then the second line, and so on.
 *  So, the second line is a subtext of the entire dialog.
 */
static void SpecialHookExp(DWORD esp_base, HookParam *hp, DWORD *data, DWORD *split, DWORD *len)
{
  static DWORD lasttext;
  // 00258020   55               push ebp  ; jichi: hook here
  // 00258021   8bec             mov ebp,esp
  // 00258023   8b45 08          mov eax,dword ptr ss:[ebp+0x8] ; jichi: move arg1 to eax
  // 00258029   85c0             test eax,eax   ; check if text is null
  // 0025802b   0f84 d8000000    je .00258109
  // 00258031   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0 ; jichi: compare 0 with arg3, which is size+1
  // 00258035   0f84 ce000000    je .00258109
  // 0025803b   8b10             mov edx,dword ptr ds:[eax] ; move text address to edx
  DWORD arg1 = argof(1, esp_base), // mov eax,dword ptr ss:[ebp+0x8]
        arg3 = argof(3, esp_base); // size - 1
  if (arg1 && arg3)
    if (DWORD text = *(DWORD *)arg1)
      if (!(text > lasttext && text < lasttext + VNR_TEXT_CAPACITY)) { // text is not a subtext of lastText
        *data = lasttext = text; // mov edx,dword ptr ds:[eax]
        //*len = arg3 - 1; // the last char is the '\0', so -1, but this value is not reliable
        *len = ::strlen((LPCSTR)text);
        // Registers are not used as split as all of them are floating at runtime
        //*split = argof(4, esp_base); // arg4, always -8, this will merge all threads and result in repetition
        *split = argof(7, esp_base); // reduce repetition, but still have sub-text repeat
      }
}
bool InsertExpHook()
{
  const BYTE bytes[] = {
    0x55,                   // 00258020   55               push ebp  ; jichi: hook here, function starts, text in [arg1], size+1 in arg3
    0x8b,0xec,              // 00258021   8bec             mov ebp,esp
    0x8b,0x45, 0x08,        // 00258023   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
    0x83,0xec, 0x08,        // 00258026   83ec 08          sub esp,0x8
    0x85,0xc0,              // 00258029   85c0             test eax,eax
    0x0f,0x84, XX4,         // 0025802b   0f84 d8000000    je .00258109
    0x83,0x7d, 0x10, 0x00,  // 00258031   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0
    0x0f,0x84, XX4,         // 00258035   0f84 ce000000    je .00258109
    0x8b,0x10,              // 0025803b   8b10             mov edx,dword ptr ds:[eax] ; jichi: edx is the text
    0x8b,0x45, 0x0c,        // 0025803d   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
    0x53,                   // 00258040   53               push ebx
    0x56,                   // 00258041   56               push esi
    0xc7,0x45, 0xf8, 0x00,0x00,0x00,0x00,   // 00258042   c745 f8 00000000 mov dword ptr ss:[ebp-0x8],0x0
    0x89,0x45, 0xfc,        // 00258049   8945 fc          mov dword ptr ss:[ebp-0x4],eax
    0x57,                   // 0025804c   57               push edi
    0x8d,0x49, 0x00,        // 0025804d   8d49 00          lea ecx,dword ptr ds:[ecx]
    0x8a,0x0a               // 00258050   8a0a             mov cl,byte ptr ds:[edx]  ; jichi: text accessed in edx
  };
  enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::matchBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:EXP: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.type = NO_CONTEXT|USING_STRING|EXTERN_HOOK; // NO_CONTEXT to get rid of floating address
  hp.extern_fun = SpecialHookExp;
  ConsoleOutput("vnreng: INSERT EXP");
  NewHook(hp, L"EXP");
  return true;
}





} // namespace Engine


// EOF
