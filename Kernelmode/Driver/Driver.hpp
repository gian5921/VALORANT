#pragma once

typedef __int64 ( __fastcall* fNtGdiXFORMOBJ_bApplyXform )( void* a1 );
fNtGdiXFORMOBJ_bApplyXform oNtGdiXFORMOBJ_bApplyXform = (fNtGdiXFORMOBJ_bApplyXform) NULL;

std::uintptr_t pNtGdiXFORMOBJ_bApplyXform = NULL;

__int64 __fastcall hNtGdiXFORMOBJ_bApplyXform ( void* a1 )
{
    SPOOF_FUNC;

    /*static bool ApcThread = false;
    if ( !ApcThread )
    {
        auto* APCQueueable = reinterpret_cast<uint32_t*> ( reinterpret_cast<uint8_t*>( PsGetCurrentThread ( ) ) + 0x74 );
        *APCQueueable &= 0xFFFFBFFF;
        
        ApcThread = true;   
    };*/

    if ( EGPM ( ) != UserMode )
    {
#if _DEBUG_MODE 
        Debug ( "An unexpected error has occurred => ExGetPreviousMode () != UserMode" );
#endif
        return oNtGdiXFORMOBJ_bApplyXform ( a1 );
    }

    if ( !a1 )
    {
#if _DEBUG_MODE 
        Debug ( "An unexpected error has occurred => Invalid argument" );
#endif
        return oNtGdiXFORMOBJ_bApplyXform ( a1 );
    }

    _MEMORY_STRUCT* Request = (_MEMORY_STRUCT*) a1;

    if ( Request->Special != 0x1721 )
    {
#if _DEBUG_MODE 
        Debug ( "An unexpected error has occurred => Invalid request" );
#endif
        return oNtGdiXFORMOBJ_bApplyXform ( a1 );
    }

    if ( Request->Write )
    {
        if ( !Request->Address || !Request->TargetProcess || !Request->Size )
            return STATUS_INVALID_PARAMETER;

        PEPROCESS Process { };
        if ( NT_SUCCESS ( PLPBPI ( (HANDLE) Request->TargetProcess, &Process ) ) )
        {
            SIZE_T Bytes = 0;
            NTSTATUS Write = MCVM ( IGCP ( ), Request->Buffer, Process, Request->Address, Request->Size, UserMode, &Bytes );
        }
    }
    else if ( Request->Read )
    {
        if ( !Request->Address || !Request->TargetProcess || !Request->Size )
            return STATUS_INVALID_PARAMETER;

        PEPROCESS Process { };
        if ( NT_SUCCESS ( PLPBPI ( (HANDLE) Request->TargetProcess, &Process ) ) )
        {
            SIZE_T Bytes = 0;
            NTSTATUS Read = MCVM ( Process, Request->Address, IGCP ( ), Request->Buffer, Request->Size, UserMode, &Bytes );
        }
    }
    else if ( Request->Base )
    {
        PEPROCESS TargetProcess;
        PLPBPI ( (HANDLE) Request->TargetProcess, &TargetProcess );
        Request->ProcessBase = PGPSBA ( TargetProcess );
        ODO ( TargetProcess );

        return STATUS_SUCCESS;
    }
    else if ( Request->ReadAllocation )
    {
        Utilities::ReadGuardedRegion ( Request->Displacement, Request->Buffer, Request->Size );

        return STATUS_SUCCESS;
    }
    else if ( Request->SetAllocation )
    {
        Utilities::SetGuardedRegion ( );

        return STATUS_SUCCESS;
    }
    else
    {
        return oNtGdiXFORMOBJ_bApplyXform ( a1 );
    }

    /*KeEnterCriticalRegion ( );
    KeEnterGuardedRegion ( );*/

    return oNtGdiXFORMOBJ_bApplyXform ( a1 );
};