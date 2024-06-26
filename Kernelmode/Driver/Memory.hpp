namespace Utilities
{
	/// <summary>
	/// https://www.unknowncheats.me/forum/anti-cheat-bypass/300487-faq-tips-tricks-kernel-newbies-beginners.html
	/// </summary>
	PVOID NTAPI GetKernelProcAddress ( LPCWSTR SystemRoutineName )
	{
		UNICODE_STRING Name;
		RtlInitUnicodeString ( &Name, SystemRoutineName );
		return MmGetSystemRoutineAddress ( &Name );
	};

	/// <summary>
	/// https://www.unknowncheats.me/forum/valorant/495965-bypass-guarded-region-externally.html
	/// </summary>
	PVOID GuardedRegionAddress = 0;
	NTSTATUS SetGuardedRegion ( )
	{
		SPOOF_FUNC;

		PSYSTEM_BIGPOOL_INFORMATION PoolInfo = 0;
		NTSTATUS NtStatus = STATUS_SUCCESS;
		ULONG InfoLen = 0;

		NtStatus = ZQSI ( SystemBigPoolInformation, &InfoLen, 0, &InfoLen );
		while ( NtStatus == STATUS_INFO_LENGTH_MISMATCH )
		{
			if ( PoolInfo )
				EFPWT ( PoolInfo, NULL );

			PoolInfo = (PSYSTEM_BIGPOOL_INFORMATION) EAP ( NonPagedPool, InfoLen );
			NtStatus = ZQSI ( SystemBigPoolInformation, PoolInfo, InfoLen, &InfoLen );
		}

		if ( PoolInfo )
		{
			for ( ULONG Iteration = 0; Iteration < PoolInfo->Count; ++Iteration )
			{
				SYSTEM_BIGPOOL_ENTRY* Entry = &PoolInfo->AllocatedInfo [Iteration];
				PVOID VirtualAddress = (PVOID) ( (uintptr_t) Entry->VirtualAddress & ~1ull );
				SIZE_T SizeInBytes = Entry->SizeInBytes;
				BOOLEAN NonPaged = Entry->NonPaged;

				if ( NonPaged && SizeInBytes == 0x200000 )
				{
					ULONG VirtualPointer = ( *(uintptr_t*) ( (PBYTE) VirtualAddress + 0x60 ) >> 0x24 );

					if ( VirtualPointer == 0x8 || VirtualPointer == 0x10 )
					{
						GuardedRegionAddress = VirtualAddress;
#if _DEBUG_MODE
						Debug ( "VirtualGuardedRegion => 0x%p | 0x%p", VirtualAddress, Entry->VirtualAddress );
#endif
					}
				}
			}
		}

#if _DEBUG_MODE
		Debug ( "GuardedRegionAddress => 0x%p", GuardedRegionAddress );
#endif

		if ( !GuardedRegionAddress )
			NtStatus = STATUS_UNSUCCESSFUL;

		if ( PoolInfo )
			EFPWT ( PoolInfo, NULL );

		return NtStatus;
	};

	/// <summary>
	/// https://www.unknowncheats.me/forum/valorant/495965-bypass-guarded-region-externally.html
	/// </summary>
	NTSTATUS ReadGuardedRegion ( ULONG_PTR Displacement, PVOID PointerBuffer, ULONG CallBackBuffer )
	{
		SPOOF_FUNC;

		if ( !GuardedRegionAddress )
			return STATUS_UNSUCCESSFUL;

		__try
		{
			RtlCopyMemory ( PointerBuffer, (PVOID) ( (PBYTE) GuardedRegionAddress + Displacement ), CallBackBuffer );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			return STATUS_UNHANDLED_EXCEPTION;
		}

		if ( !RtlCopyMemory ( PointerBuffer, (PVOID) ( (PBYTE) GuardedRegionAddress + Displacement ), CallBackBuffer ) )
			return STATUS_UNSUCCESSFUL;

#if _DEBUG_MODE
		Debug ( "ReadGuardedRegion => Displacement (0x%p), PointerBuffer (0x%p), CallBackBuffer(0x%p)", Displacement, PointerBuffer, CallBackBuffer );
#endif

		return STATUS_SUCCESS;
	}
};

namespace Memory
{
	void RemoveCurrentApcs ( KThread* CurrentThread )
	{

		PKAPC_STATE ApcState = *(PKAPC_STATE*) ( uintptr_t ( CurrentThread ) + 0x98 ); // [0x98] KTHREAD->ApcState

		for ( LIST_ENTRY* CurrentApcListEntry = ApcState->ApcListHead [KernelMode].Flink; CurrentApcListEntry != &ApcState->ApcListHead [KernelMode]; CurrentApcListEntry = CurrentApcListEntry->Flink ) 
		{
			KAPC* CurrentApc = (KAPC*) ( (uintptr_t) CurrentApcListEntry - 0x10 ); // [0x10] KTHREAD::KAPC_STATE->ApcListEntry

			auto Address = CurrentApc->Reserved [2]; 

			CurrentThread->ApcQueueable = 0;
			RemoveEntryList ( CurrentApcListEntry );

#if _DEBUG_MODE
			Debug ( "[+] Current KernelMode Apc Routine: 0x%p - Inserted: %i\n", Address, CurrentApc->Inserted );
#endif

			break;
		}

		for ( LIST_ENTRY* CurrentApcListEntry = ApcState->ApcListHead [UserMode].Flink; CurrentApcListEntry != &ApcState->ApcListHead [UserMode]; CurrentApcListEntry = CurrentApcListEntry->Flink ) 
		{
			KAPC* CurrentApc = (KAPC*) ( (uintptr_t) CurrentApcListEntry - 0x10 ); // [0x10] KTHREAD::KAPC_STATE->ApcListEntry

			auto Address = CurrentApc->Reserved [2];

			CurrentThread->ApcQueueable = 0;
			RemoveEntryList ( CurrentApcListEntry );

#if _DEBUG_MODE
			Debug ( "[+] Current UserMode Apc Routine: 0x%p - Inserted: %i\n", Address, CurrentApc->Inserted );
#endif

			break;
		}
	};
	NTSTATUS FindProcess ( char* ProcessName, PEPROCESS* Process )
	{
		PEPROCESS SystemProcess = PsInitialSystemProcess;
		PEPROCESS CurrentEntry = SystemProcess;

		char Image [15];
		do
		{
			RtlCopyMemory ( (PVOID) ( &Image ), (PVOID) ( (uintptr_t) CurrentEntry + 0x5a8 ), sizeof ( Image ) );

			if ( strstr ( Image, ProcessName ) )
			{
				DWORD ActiveThreads;
				RtlCopyMemory ( (PVOID) &ActiveThreads, (PVOID) ( (uintptr_t) CurrentEntry + 0x5f0 ), sizeof ( ActiveThreads ) );
				if ( ActiveThreads )
				{
					*Process = CurrentEntry;
					return STATUS_SUCCESS;
				}
			}

			PLIST_ENTRY List = (PLIST_ENTRY) ( (uintptr_t) (CurrentEntry) +0x448 );
			CurrentEntry = (PEPROCESS) ( (uintptr_t) List->Flink - 0x448 );

		} while ( CurrentEntry != SystemProcess );

		return STATUS_NOT_FOUND;
	};

	UINT_PTR GetLoadedModule ( const wchar_t* Name, PLDR_DATA_TABLE_ENTRY* Entry = nullptr )
	{
		if ( !Name || IsListEmpty ( PLML ) )
			return NULL;

		UNICODE_STRING ModuleName;
		RIUS ( &ModuleName, Name );

		for ( PLIST_ENTRY EntryPoint = PLML->Flink; EntryPoint != PLML; EntryPoint = EntryPoint->Flink )
		{
			PLDR_DATA_TABLE_ENTRY Data = CONTAINING_RECORD ( EntryPoint, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
			if ( RtlEqualUnicodeString ( &Data->BaseDllName, &ModuleName, TRUE ) )
			{
				if ( Entry )
					*Entry = Data;
				return (UINT_PTR) Data->DllBase;
			}
		}
		return NULL;
	};

	UINT_PTR GetImportAddress ( IMAGE Image, const char* Name )
	{
		const auto Dos = reinterpret_cast<IMAGE_DOS_HEADER*> ( Image.Base );
		const auto Nt = reinterpret_cast<IMAGE_NT_HEADERS*>( Image.Base + Dos->e_lfanew );
		const auto ImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>( Image.Base + Nt->OptionalHeader.DataDirectory [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

		for ( auto Iteration = 0u; ImportDescriptor [Iteration].Characteristics; Iteration++ )
		{
			auto FirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*> ( Image.Base + ImportDescriptor [Iteration].FirstThunk );
			auto OriginalFirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*> ( Image.Base + ImportDescriptor [Iteration].OriginalFirstThunk );

			for ( ; OriginalFirstThunk->u1.Function; OriginalFirstThunk++, FirstThunk++ )
			{
				if ( OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
				{
					continue;
				}

				const auto import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*> ( Image.Base + OriginalFirstThunk->u1.AddressOfData );

				if ( strcmp ( import->Name, Name ) )
				{
					continue;
				}

				return FirstThunk->u1.Function;
			}
		}

		return 0;
	};

	UINT_PTR GetSystemModule ( const wchar_t* Name )
	{
		SPOOF_FUNC;

		NTSTATUS NtStatus = STATUS_SUCCESS;
		ANSI_STRING ANSIName;
		UNICODE_STRING UNICODEName;
		RIUS ( &UNICODEName, Name );
		RUSTAS ( &ANSIName, &UNICODEName, TRUE );

		PRTL_PROCESS_MODULES Modules = NULL;
		UINT32 SizeOfModules = 0;

		NtStatus = ZQSI ( SystemModuleInformation, 0, SizeOfModules, (PULONG) &SizeOfModules );
		if ( !SizeOfModules )
		{
			RFAS ( &ANSIName );
			return 0;
		}

		Modules = (PRTL_PROCESS_MODULES) EAP ( NonPagedPool, SizeOfModules );
		if ( !Modules )
		{
			RFAS ( &ANSIName );
			return 0;
		}
		RtlZeroMemory ( Modules, SizeOfModules );

		NtStatus = ZQSI ( SystemModuleInformation, Modules, SizeOfModules, (PULONG) &SizeOfModules );
		if ( !NT_SUCCESS ( NtStatus ) )
		{
			RFAS ( &ANSIName );
			EFPWT ( Modules, NULL );
			return 0;
		}

		UINT_PTR Base = 0;
		PRTL_PROCESS_MODULE_INFORMATION InformationModules = Modules->Modules;
		for ( ULONG Iteration = 0; Iteration < Modules->NumberOfModules && !Base; Iteration++ )
		{
			RTL_PROCESS_MODULE_INFORMATION ProcessModules = InformationModules [Iteration];
			char* FullPath = (char*) ProcessModules.FullPathName;
			if ( FullPath && strlen ( FullPath ) > 0 )
			{
				UINT32 Last = -1;
				char* BaseFullPath = (char*) ProcessModules.FullPathName;
				while ( *FullPath != 0 )
				{
					if ( *FullPath == '\\' )
						Last = ( FullPath - BaseFullPath ) + 1;
					FullPath++;
				}

				if ( Last >= 0 )
					FullPath = BaseFullPath + Last;
			}
			else continue;

			ANSI_STRING ANSIFullPath;
			RIAS ( &ANSIFullPath, FullPath );
			if ( RES ( &ANSIFullPath, &ANSIName, TRUE ) )
				Base = (UINT_PTR) ProcessModules.ImageBase;
		}

		RFAS ( &ANSIName );
		EFPWT ( Modules, NULL );
		return Base;
	};

	UINT_PTR GetRoutineAddress ( UINT_PTR Image, const char* Name )
	{
		SPOOF_FUNC;

		if ( !Image || !Name )
			return NULL;

		return (UINT_PTR) RFERBN ( (PVOID) Image, Name );
	}

	BOOLEAN DataCompare ( const BYTE* Data, const BYTE* ByteMask, const char* SizeMask )
	{
		for ( ; *SizeMask; ++SizeMask, ++Data, ++ByteMask )
			if ( *SizeMask == 'x' && *Data != *ByteMask )
				return 0;

		return ( *SizeMask ) == 0;
	};

	PIMAGE_NT_HEADERS GetHeader ( PVOID Module )
	{
		return (PIMAGE_NT_HEADERS) ( (PBYTE) Module + PIMAGE_DOS_HEADER ( Module )->e_lfanew );
	};

	PBYTE FindPattern ( PVOID Module, DWORD Size, LPCSTR Pattern, LPCSTR Mask )
	{
		auto CheckMask = [] ( PBYTE Buffer, LPCSTR Pattern, LPCSTR Mask ) -> BOOL
		{
			for ( auto Iteration = Buffer; *Mask; Pattern++, Mask++, Iteration++ )
			{
				auto Address = *(BYTE*) ( Pattern );
				if ( Address != *Iteration && *Mask != '?' )
					return FALSE;
			}

			return TRUE;
		};

		for ( auto Iteration = 0; Iteration < Size - strlen ( Mask ); Iteration++ )
		{
			auto Address = (PBYTE) Module + Iteration;
			if ( CheckMask ( Address, Pattern, Mask ) )
				return Address;
		}

		return NULL;
	};

	PBYTE FindPatternWork ( PVOID Base, LPCSTR Pattern, LPCSTR Mask )
	{
		auto Header = GetHeader ( Base );
		auto Section = IMAGE_FIRST_SECTION ( Header );

		for ( auto Iteration = 0; Iteration < Header->FileHeader.NumberOfSections; Iteration++, Section++ )
		{
			if ( !memcmp ( Section->Name, ".text", 5 ) || !memcmp ( Section->Name, "PAGE", 4 ) )
			{
				auto Address = FindPattern ( (PBYTE) Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask );
				if ( Address )
				{
#if _DEBUG_MODE
					Debug ( "[+] Found Section => [ %s ]", Section->Name );
#endif
					return Address;
				}
			}
		}

		return NULL;
	};
};

namespace Cleaners
{
	NTSTATUS NullPageFrameNumbersFromMdl ( PMDL MdlPages )
	{
		SPOOF_FUNC;

		PPFN_NUMBER NumberOfMdlPages = MmGetMdlPfnArray ( MdlPages );
		if ( !NumberOfMdlPages ) { return STATUS_UNSUCCESSFUL; }

		ULONG MdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES ( MmGetMdlVirtualAddress ( MdlPages ), MmGetMdlByteCount ( MdlPages ) );

		ULONG NullPfn = 0x0;
		MM_COPY_ADDRESS TargetSource = { 0 };
		TargetSource.VirtualAddress = &NullPfn;

		for ( ULONG Iteration = 0; Iteration < MdlPageCount; Iteration++ )
		{
			std::size_t Bytes = 0;
			MCM ( &NumberOfMdlPages [Iteration], TargetSource, sizeof ( ULONG ), MM_COPY_MEMORY_VIRTUAL, &Bytes );
		}

#if _DEBUG_MODE
		Debug ( "PageFrameNumbers => 0x%p", TargetSource.VirtualAddress );
		Debug ( "MdlPages => 0x%p", NumberOfMdlPages );
		Debug ( "MdlPageCount => 0x%p", MdlPageCount );
#endif

		return STATUS_SUCCESS;
	}

	NTSTATUS NullPageFrameNumbers ( std::uint64_t Start, std::uint32_t Size )
	{
		SPOOF_FUNC;

		NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
		PMDL MdlPage = IAM ( (PVOID) Start, (ULONG) Size, FALSE, FALSE, NULL );

		if ( !MdlPage )
			return NtStatus;

		NtStatus = NullPageFrameNumbersFromMdl ( MdlPage );

		IFM ( MdlPage );

		return NtStatus;
	}
};
