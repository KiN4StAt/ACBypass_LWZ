#include <windows.h>
#include "MinHook.h"
#include "RakClient.h"
#include "BitStream.h"

#pragma pack(push, 1)
struct CNetGame {
    char                junk[0x3C9];
    RakClientInterface* m_pRakClient;
};
#pragma pack(pop)

char LWZBypass[] = "\xC7\x4F\x32\x00\x00\x00\x00\x00\x00\xE0\xFD\xCA\x17\x00\x00\x00\x00\x0A\x00\x00\x00\xF6\xFF\xFF\xFF\x0A\x00\x00\x00\x58\xFE\xCA\x17\x10\x00\x00\x00\x00\x00\x00\x00\xF3\x93\x2C\x55\x02\x00\x00\x00\x5C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
DWORD dwSampModule = 0;

typedef Packet* (__fastcall* ReceivePacket)(void*);
ReceivePacket fpReceive = NULL;

bool sendLWZVer() {
    BitStream bs;
    bs.Write(LWZBypass, 259);
    return (*reinterpret_cast<CNetGame**>(reinterpret_cast<DWORD>(GetModuleHandle(L"samp.dll")) + 0x21A0F8))->m_pRakClient->Send(&bs, PacketPriority::HIGH_PRIORITY, PacketReliability::UNRELIABLE_SEQUENCED, 0);
}

MH_STATUS MH_CreateAndEnableHook(DWORD dwTargetAddress, LPVOID pDetour, LPVOID* ppOriginal) {
	MH_CreateHook(reinterpret_cast<LPVOID>(dwTargetAddress), pDetour, ppOriginal);
	return MH_EnableHook(reinterpret_cast<LPVOID>(dwTargetAddress));
}

Packet* __fastcall HOOK_ReceivePacket(void* dis) {
    Packet* packet = fpReceive(dis);
    if (packet != nullptr && packet->data && packet->length > 0) {
        if (packet->data[0] == 41) {
            sendLWZVer();
        }
    }
    return packet;
}

BOOL APIENTRY DllMain(HMODULE hModule ,DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        MH_Initialize();
        dwSampModule = reinterpret_cast<DWORD>(GetModuleHandle(L"samp.dll"));
        if (dwSampModule == 0) return FALSE;
        MH_CreateAndEnableHook(dwSampModule + 0x31710, &HOOK_ReceivePacket, reinterpret_cast<LPVOID*>(&fpReceive));
    }
    return TRUE;
}
