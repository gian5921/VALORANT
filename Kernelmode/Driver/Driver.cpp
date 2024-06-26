#include "Imports.hpp"
#include "Driver.hpp"

auto LoadKernelProcesses ( )
-> void {
    ZQSI = reinterpret_cast<ZwQuerySystemInformationStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"ZwQuerySystemInformation" ) ) );

    RIUS = reinterpret_cast<RtlInitUnicodeStringStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"RtlInitUnicodeString" ) ) );
    RIAS = reinterpret_cast<RtlInitAnsiStringStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"RtlInitAnsiString" ) ) );
    RES = reinterpret_cast<RtlEqualStringStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"RtlEqualString" ) ) );
    RFERBN = reinterpret_cast<RtlFindExportedRoutineByNameStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"RtlFindExportedRoutineByName" ) ) );
    RUSTAS = reinterpret_cast<RtlUnicodeStringToAnsiStringStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"RtlUnicodeStringToAnsiString" ) ) );
    RFAS = reinterpret_cast<RtlFreeAnsiStringStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"RtlFreeAnsiString" ) ) );

    EAP = reinterpret_cast<ExAllocatePoolStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"ExAllocatePool" ) ) );
    EAPWT = reinterpret_cast<ExAllocatePoolWithTagStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"ExAllocatePoolWithTag" ) ) );
    EFPWT = reinterpret_cast<ExFreePoolWithTagStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"ExFreePoolWithTag" ) ) );
    EGPM = reinterpret_cast<ExGetPreviousModeStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"ExGetPreviousMode" ) ) );

    MCM = reinterpret_cast<MmCopyMemoryStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"MmCopyMemory" ) ) );
    MCVM = reinterpret_cast<MmCopyVirtualMemoryStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"MmCopyVirtualMemory" ) ) );

    PLPBPI = reinterpret_cast<PsLookupProcessByProcessIdStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"PsLookupProcessByProcessId" ) ) );
    PGPSBA = reinterpret_cast<PsGetProcessSectionBaseAddressStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"PsGetProcessSectionBaseAddress" ) ) );
    PLML = reinterpret_cast<PsLoadedModuleListStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"PsLoadedModuleList" ) ) );

    IGCP = reinterpret_cast<IoGetCurrentProcessStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"IoGetCurrentProcess" ) ) );
    IAM = reinterpret_cast<IoAllocateMdlStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"IoAllocateMdl" ) ) );
    IFM = reinterpret_cast<IoFreeMdlStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"IoFreeMdl" ) ) );

    ODO = reinterpret_cast<ObfDereferenceObjectStruct>( Utilities::GetKernelProcAddress ( skCrypt ( L"ObfDereferenceObject" ) ) );

#if _DEBUG_MODE
    Debug ( "ZwQuerySystemInformation => 0x%p", ZQSI );

    Debug ( "RtlInitUnicodeString => 0x%p", RIUS );
    Debug ( "RtlInitAnsiString => 0x%p", RIAS );
    Debug ( "RtlEqualString => 0x%p", RES );
    Debug ( "RtlFindExportedRoutineByName => 0x%p", RFERBN );
    Debug ( "RtlUnicodeStringToAnsiString => 0x%p", RUSTAS );
    Debug ( "RtlFreeAnsiString => 0x%p", RFAS );

    Debug ( "ExAllocatePool => 0x%p", EAP );
    Debug ( "ExAllocatePoolWithTag => 0x%p", EAPWT );
    Debug ( "ExFreePoolWithTag => 0x%p", EFPWT );
    Debug ( "ExGetPreviousMode => 0x%p", EGPM );

    Debug ( "PsGetProcessSectionBaseAddress => 0x%p", PGPSBA );
    Debug ( "PsLookupProcessByProcessId => 0x%p", PLPBPI );
    Debug ( "PsLoadedModuleList => 0x%p", PLML );

    Debug ( "MmCopyMemory => 0x%p", MCM );
    Debug ( "MmCopyVirtualMemory => 0x%p", MCVM );

    Debug ( "IoAllocateMdl => 0x%p", IAM );
    Debug ( "IoFreeMdl => 0x%p", IFM );
    Debug ( "IoGetCurrentProcess => 0x%p", IGCP );

    Debug ( "ObfDereferenceObject => 0x%p", ODO );
#endif
};

auto CleanMdlPages ( PENTRY_PARAMETERS Page )
-> void {
    Cleaners::NullPageFrameNumbers ( PoolBase, Size );
};

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT    DriverObject,
    IN PUNICODE_STRING   RegistryPath,
    IN PENTRY_PARAMETERS EntryParams
)
{
    UNREFERENCED_PARAMETER ( DriverObject );
    UNREFERENCED_PARAMETER ( RegistryPath );

    EntryPoint = EntryParams->EntryPoint;
    PoolBase = EntryParams->PoolBase;
    Size = EntryParams->Size;

    LoadKernelProcesses ( );

    auto Image = Memory::GetSystemModule ( skCrypt ( L"win32k.sys" ) );
    if ( !Image )
    {
#if _DEBUG_MODE
        Debug ( "An unexpected error has occurred => System module failed. (win32kbase.sys)\n" );
#endif
        return STATUS_ABANDONED;
    }

#if _DEBUG_MODE
    Debug ( "Image => 0x%p", Image );
#endif

    pNtGdiXFORMOBJ_bApplyXform = Image + 0x66440;
    oNtGdiXFORMOBJ_bApplyXform = *reinterpret_cast<fNtGdiXFORMOBJ_bApplyXform*>( pNtGdiXFORMOBJ_bApplyXform );
    *reinterpret_cast<fNtGdiXFORMOBJ_bApplyXform*>( pNtGdiXFORMOBJ_bApplyXform ) = ( &hNtGdiXFORMOBJ_bApplyXform );

#if _DEBUG_MODE
    Debug ( "QWORD => 0x%p", oNtGdiXFORMOBJ_bApplyXform );
#endif

    CleanMdlPages ( EntryParams );

#if _DEBUG_MODE
    Debug ( "Driver Loaded" );
#endif

    return STATUS_SUCCESS;
};