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

#include "main.h"
#include "engine_p.h"
#include "engine.h"
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
		//Engine::GetName();
		Engine::init(hModule); 
		//RegisterEngineModule((DWORD)hModule, (DWORD)Engine::IdentifyEngine, (DWORD)Engine::InsertDynamicHook);
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


