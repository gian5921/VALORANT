#include <windows.h>
#include <tlhelp32.h>
#include <corecrt_math_defines.h>
#include <d3d9types.h>

#include <iostream>
#include <cstdint>
#include <thread>
#include <chrono>

#include "Importer.hpp"
#include "Encryption.hpp"
#include "Spoofer.hpp"

#define _DEBUG_MODE FALSE
#if _DEBUG_MODE

#endif

__int64 ( __fastcall* NtGdiXFORMOBJ_bApplyXform )( void* ); // qword_FFFFF97FFF066440
int ProcessID; // VALORANT-Win64-Shipping Identification
void* ImageBase; // VALORANT-Win64-Shipping Image

static ULONG Width = GetSystemMetrics ( SM_CXSCREEN );
static ULONG Height = GetSystemMetrics ( SM_CYSCREEN );

struct _MEMORY_STRUCT
{
	int              Special;
	bool             Write;
	bool             Read;
	bool             Base;
	bool             ReadAllocation;
	bool             SetAllocation;
	int              TargetProcess;
	unsigned long    Displacement;
	void*            Address;
	void*            Buffer;
	void*            ProcessBase;
	long             Size;
};
bool Initialise ( )
{
	SPOOF_FUNC;

	LI_FIND ( LoadLibraryA )( _XOR_ ( "user32.dll" ) );
	LI_FIND ( LoadLibraryA ) ( _XOR_ ( "win32u.dll" ) );

	const auto Base = LI_FIND ( GetModuleHandleA ) ( _XOR_ ( "win32u.dll" ) );
	if ( !Base )
		return false;

#if _DEBUG_MODE
	std::cout << _XOR_ ( "[+] Image => 0x" ) << Base << std::endl;
#endif

	auto Address = LI_FIND ( GetProcAddress ) ( Base, _XOR_ ( "NtGdiXFORMOBJ_bApplyXform" ) );
	*reinterpret_cast<void**>( &NtGdiXFORMOBJ_bApplyXform ) = Address;

#if _DEBUG_MODE
	std::cout << _XOR_ ( "[+] Address => 0x" ) << Address << std::endl;
#endif

	return NtGdiXFORMOBJ_bApplyXform;
};

auto GetProcessID ( LPCWSTR ProcessName ) -> DWORD
{
	SPOOF_FUNC;

	HANDLE Handle = LI_FIND ( CreateToolhelp32Snapshot ) ( TH32CS_SNAPPROCESS, NULL );
	DWORD ProcessID = NULL;

	if ( Handle == INVALID_HANDLE_VALUE )
		return ProcessID;

	PROCESSENTRY32W Process { 0 };
	Process.dwSize = sizeof ( PROCESSENTRY32W );

	if ( LI_FIND ( Process32FirstW ) ( Handle, &Process ) )
	{
		if ( !_wcsicmp ( ProcessName, Process.szExeFile ) )
		{
			ProcessID = Process.th32ProcessID;
		}
		else while ( LI_FIND ( Process32NextW )( Handle, &Process ) )
		{
			if ( !_wcsicmp ( ProcessName, Process.szExeFile ) )
			{
				ProcessID = Process.th32ProcessID;
			}
		}
	}

	LI_FIND ( CloseHandle ) ( Handle );
	return ProcessID;
};

auto SendCommand ( _MEMORY_STRUCT* Request ) -> void
{
	SPOOF_FUNC;

	SecureZeroMemory ( Request, NULL );
	NtGdiXFORMOBJ_bApplyXform ( Request );
};

auto GetImageBase ( ) -> PVOID
{
	SPOOF_FUNC;

	_MEMORY_STRUCT Request = { 0 };

	Request.Special = 0x1721;
	Request.TargetProcess = ProcessID;
	Request.Base = TRUE;

	SendCommand ( &Request );

	return Request.ProcessBase;
};

auto SetGuardedRegion ( ) -> void
{
	SPOOF_FUNC;

	_MEMORY_STRUCT Request = { 0 };

	Request.Special = 0x1721;
	Request.TargetProcess = ProcessID;
	Request.SetAllocation = TRUE;

	SendCommand ( &Request );
};

//////////////////////////////////////////////////////////////////

auto ReadProcessMemory ( std::uintptr_t Address, void* Buffer, long Size ) -> bool
{
	SPOOF_FUNC;

	_MEMORY_STRUCT Request = { 0 };

	Request.Special = 0x1721;
	Request.TargetProcess = ProcessID;
	Request.Read = TRUE;
	Request.Address = reinterpret_cast<void*>( Address );
	Request.Buffer = Buffer;
	Request.Size = Size;

	SendCommand ( &Request );

	return Request.ProcessBase;
};

auto ReadProcessGuardedMemory ( unsigned long Displacement, void* PointerBuffer, long CallBackBuffer ) -> bool
{
	SPOOF_FUNC;

	_MEMORY_STRUCT Request = { 0 };
	if ( Displacement > 0x200000 )
		return FALSE;

	RtlSecureZeroMemory ( PointerBuffer, CallBackBuffer );

	Request.Special = 0x1721;
	Request.TargetProcess = ProcessID;
	Request.ReadAllocation = TRUE;
	Request.Displacement = Displacement;
	Request.Buffer = PointerBuffer;
	Request.Size = CallBackBuffer;

	SendCommand ( &Request );

	return Request.ProcessBase;
};

template<typename Template>
auto Write ( std::uintptr_t Address, Template Buffer ) -> bool
{
	SPOOF_FUNC;

	_MEMORY_STRUCT Request = { 0 };

	Request.Special = 0x1721;
	Request.TargetProcess = ProcessID;
	Request.Write = TRUE;
	Request.Address = reinterpret_cast<void*>( Address );
	Request.Size = sizeof ( Template );
	Request.Buffer = &Buffer;

	SendCommand ( &Request );

	return Request.ProcessBase;
};

template<typename Template>
bool Read ( std::uintptr_t Address, Template* Buffer, long Size )
{
	SPOOF_FUNC;

	auto VirtualPointer = ( Address >> 0x24 );

	if ( VirtualPointer == 0x8 || VirtualPointer == 0x10 )
		ReadProcessGuardedMemory ( std::uintptr_t ( Address & 0xFFFFFF ), (PVOID) Buffer, sizeof ( Template ) );
	else
		ReadProcessMemory ( Address, (PVOID) Buffer, sizeof ( Template ) );

	return true;
};

template<typename Template>
Template Read ( std::uintptr_t Address )
{
	SPOOF_FUNC;

	Template Buffer {};
	Read ( Address, &Buffer, sizeof ( Template ) );
	return Buffer;
};