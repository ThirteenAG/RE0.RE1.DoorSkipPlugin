#include "stdafx.h"
#include <windows.h>
#include "includes\injector\injector.hpp"
#include "includes\hooking\Hooking.Patterns.h"

const BYTE Pattern[5] =
{
	0x8B, 0x46, 0x48, 0x85, 0xC0
};
const BYTE DoorLoop[5] =
{
	0xE9, 0x9F, 0x00, 0x00, 0x00
};
const BYTE DoorEvent[] =
{
	0xE9, 0x7E, 0x00, 0x00, 0x00
};
const BYTE DoorEventReturn[] =
{
	0x5F, 0xC7, 0x86, 0x84, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x5E, 0x5D, 0x5B, 0xC2, 0x10, 0x00
};
const BYTE LiftFix[1] =
{
	0xFA
};

float m10 = -1.0f;

DWORD dword_552DDD;
void __declspec(naked) DoorHook()
{
	_asm
	{
		movss xmm0, m10
		movss   dword ptr[edi + 0x2C], xmm0
		jmp dword_552DDD
	}
}

DWORD WINAPI Thread(LPVOID)
{
	//Methods discovered by FluffyQuack
	
	auto pattern = hook::pattern("0F 84 CC 00 00 00 8B 47 3C");// RE0 HD 
	auto pattern3 = hook::pattern("8B 46 48 85 C0 0F 84 AA 00 00 00"); // RE1 HD

	while (!(pattern.size() > 0) && !(pattern3.size() > 0))
	{
		pattern = hook::pattern("0F 84 CC 00 00 00 8B 47 3C");
		pattern3 = hook::pattern("8B 46 48 85 C0 0F 84 AA 00 00 00");
	}

	//RE0 HD
	if (pattern.size() > 0)
	{
		DWORD* dword_5529D0 = pattern.get(0).get<DWORD>(0);
		injector::MakeNOP(dword_5529D0, 6, true);

		auto pattern2 = hook::pattern("F3 0F 11 47 2C 81 49 0C 00 04 00 00 EB 07");

		DWORD* dword_552DD8 = pattern2.get(0).get<DWORD>(0);
		injector::MakeJMP(dword_552DD8, DoorHook, true);
		dword_552DDD = (DWORD)dword_552DD8 + 5;
	}

	//RE1 HD
	if (pattern3.size() > 0)
	{
		DWORD* dword_41CD53 = pattern3.get(0).get<DWORD>(0);
		for (size_t i = 0; i < sizeof(DoorLoop); i++)
		{
			injector::WriteMemory<unsigned char>((DWORD)dword_41CD53 + i, DoorLoop[i], true);
		}

		DWORD* dword_41CEF5 = hook::pattern("C7 46 7C 00 00 00 00 C7 86 80 00 00 00 00 00 00 00 C7 86 84 00 00 00 02 00 00 00").get(0).get<DWORD>(0);
		for (size_t i = 0; i < sizeof(DoorEvent); i++)
		{
			injector::WriteMemory<unsigned char>((DWORD)dword_41CEF5 + i, DoorEvent[i], true);
		}

		DWORD* dword_41D0CF = hook::pattern("81 7E 78 19 01 00 00 75 07").get(0).get<DWORD>(0);
		for (size_t i = 0; i < sizeof(DoorEventReturn); i++)
		{
			injector::WriteMemory<unsigned char>((DWORD)dword_41D0CF + i, DoorEventReturn[i], true);
		}

		DWORD* dword_60E78A = hook::pattern("68 FB 00 00 00 EB 1D").get(0).get<DWORD>(1);
		injector::WriteMemory<unsigned char>((DWORD)dword_60E78A, LiftFix[0], true);
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Thread, NULL, 0, NULL);
	}
	return TRUE;
}
