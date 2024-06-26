#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include <windef.h>

#include <cstdint>
#include <cstddef>
#include <utility>

/// <summary>
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm
/// </summary>
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformationNative,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation,
	SystemLoadGdiDriverInSystemSpaceInformation,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHanfleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchDogTimerHandler,
	SystemWatchDogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWo64SharedInformationObosolete,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPathInformation,
	SystemVerifierFaultsInformation,
	MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

/// <summary>
/// https://www.tarasco.org/security/handle/html/struct___s_y_s_t_e_m___h_a_n_d_l_e.html
/// </summary>
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UINT8 ObjectTypeNumber;
	UINT8 Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

/// <summary>
/// https://processhacker.sourceforge.io/doc/struct___s_y_s_t_e_m___h_a_n_d_l_e___i_n_f_o_r_m_a_t_i_o_n.html
/// </summary>
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles [0];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

/// <summary>
/// https://processhacker.sourceforge.io/doc/struct___s_y_s_t_e_m___b_i_g_p_o_o_l___e_n_t_r_y.html
/// </summary>
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag [4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

/// <summary>
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
/// </summary>
typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo [ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

/// <summary>
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/process_module_information.htm
/// </summary>
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName [256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

/// <summary>
/// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
/// </summary>
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

/// <summary>
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/process_modules.htm
/// </summary>
typedef struct RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules [ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

/// <summary>
/// 
/// </summary>
typedef union _KWAIT_STATUS_REGISTER
{
	union
	{
		/* 0x0000 */ unsigned char Flags;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned char State : 3; /* bit position: 0 */
			/* 0x0000 */ unsigned char Affinity : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned char Priority : 1; /* bit position: 4 */
			/* 0x0000 */ unsigned char Apc : 1; /* bit position: 5 */
			/* 0x0000 */ unsigned char UserApc : 1; /* bit position: 6 */
			/* 0x0000 */ unsigned char Alert : 1; /* bit position: 7 */
		}; /* bitfield */
	}; /* size: 0x0001 */
} KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER; /* size: 0x0001 */

/// <summary>
/// 
/// </summary>
typedef struct _KTHREAD_META
{
	/* 0x0000 */ struct _DISPATCHER_HEADER Header;
	/* 0x0018 */ void* SListFaultAddress;
	/* 0x0020 */ unsigned __int64 QuantumTarget;
	/* 0x0028 */ void* InitialStack;
	/* 0x0030 */ void* volatile StackLimit;
	/* 0x0038 */ void* StackBase;
	/* 0x0040 */ unsigned __int64 ThreadLock;
	/* 0x0048 */ volatile unsigned __int64 CycleTime;
	/* 0x0050 */ unsigned long CurrentRunTime;
	/* 0x0054 */ unsigned long ExpectedRunTime;
	/* 0x0058 */ void* KernelStack;
	/* 0x0060 */ struct _XSAVE_FORMAT* StateSaveArea;
	/* 0x0068 */ struct _KSCHEDULING_GROUP* volatile SchedulingGroup;
	/* 0x0070 */ union _KWAIT_STATUS_REGISTER WaitRegister;
	/* 0x0071 */ volatile unsigned char Running;
	/* 0x0072 */ unsigned char Alerted [2];
	union
	{
		struct /* bitfield */
		{
			/* 0x0074 */ unsigned long AutoBoostActive : 1; /* bit position: 0 */
			/* 0x0074 */ unsigned long ReadyTransition : 1; /* bit position: 1 */
			/* 0x0074 */ unsigned long WaitNext : 1; /* bit position: 2 */
			/* 0x0074 */ unsigned long SystemAffinityActive : 1; /* bit position: 3 */
			/* 0x0074 */ unsigned long Alertable : 1; /* bit position: 4 */
			/* 0x0074 */ unsigned long UserStackWalkActive : 1; /* bit position: 5 */
			/* 0x0074 */ unsigned long ApcInterruptRequest : 1; /* bit position: 6 */
			/* 0x0074 */ unsigned long QuantumEndMigrate : 1; /* bit position: 7 */
			/* 0x0074 */ unsigned long UmsDirectedSwitchEnable : 1; /* bit position: 8 */
			/* 0x0074 */ unsigned long TimerActive : 1; /* bit position: 9 */
			/* 0x0074 */ unsigned long SystemThread : 1; /* bit position: 10 */
			/* 0x0074 */ unsigned long ProcessDetachActive : 1; /* bit position: 11 */
			/* 0x0074 */ unsigned long CalloutActive : 1; /* bit position: 12 */
			/* 0x0074 */ unsigned long ScbReadyQueue : 1; /* bit position: 13 */
			/* 0x0074 */ unsigned long ApcQueueable : 1; /* bit position: 14 */
			/* 0x0074 */ unsigned long ReservedStackInUse : 1; /* bit position: 15 */
			/* 0x0074 */ unsigned long UmsPerformingSyscall : 1; /* bit position: 16 */
			/* 0x0074 */ unsigned long TimerSuspended : 1; /* bit position: 17 */
			/* 0x0074 */ unsigned long SuspendedWaitMode : 1; /* bit position: 18 */
			/* 0x0074 */ unsigned long SuspendSchedulerApcWait : 1; /* bit position: 19 */
			/* 0x0074 */ unsigned long CetUserShadowStack : 1; /* bit position: 20 */
			/* 0x0074 */ unsigned long BypassProcessFreeze : 1; /* bit position: 21 */
			/* 0x0074 */ unsigned long CetKernelShadowStack : 1; /* bit position: 22 */
			/* 0x0074 */ unsigned long Reserved : 9; /* bit position: 23 */
		}; /* bitfield */
		/* 0x0074 */ long MiscFlags;
	}; /* size: 0x0004 */
} KTHREAD_META, * PKTHREAD_META; /* size: 0x0430 */

typedef struct _KDPC_LIST
{
    struct _SINGLE_LIST_ENTRY ListHead;                                     //0x0
    struct _SINGLE_LIST_ENTRY* LastEntry;                                   //0x8
} KDPC_LIST;

typedef struct _KDPC_DATA
{
    struct _KDPC_LIST DpcList;                                              //0x0
    ULONGLONG DpcLock;                                                      //0x10
    volatile LONG DpcQueueDepth;                                            //0x18
    ULONG DpcCount;                                                         //0x1c
    struct _KDPC* volatile ActiveDpc;                                       //0x20
} KDPC_DATA;

typedef struct _KPRCB
{
    unsigned long MxCsr;                                                            //0x0
    unsigned __int8 LegacyNumber;                                                     //0x4
    unsigned __int8 ReservedMustBeZero;                                               //0x5
    unsigned __int8 InterruptRequest;                                                 //0x6
    unsigned __int8 IdleHalt;                                                         //0x7
    struct _KTHREAD* CurrentThread;                                         //0x8
    struct _KTHREAD* NextThread;                                            //0x10
    struct _KTHREAD* IdleThread;                                            //0x18
    unsigned __int8 NestingLevel;                                                     //0x20
    unsigned __int8 ClockOwner;                                                       //0x21
    union
    {
        unsigned __int8 PendingTickFlags;                                             //0x22
        struct
        {
            unsigned __int8 PendingTick : 1;                                            //0x22
            unsigned __int8 PendingBackupTick : 1;                                      //0x22
        };
    };
    unsigned __int8 IdleState;                                                        //0x23
    unsigned long Number;                                                           //0x24
    unsigned __int64 RspBase;                                                      //0x28
    unsigned __int64 PrcbLock;                                                     //0x30
    char* PriorityState;                                                    //0x38
    char CpuType;                                                           //0x40
    char CpuID;                                                             //0x41
    union
    {
        unsigned __int8 CpuStep;                                                     //0x42
        struct
        {
            unsigned __int8 CpuStepping;                                              //0x42
            unsigned __int8 CpuModel;                                                 //0x43
        };
    };
    unsigned long MHz;                                                              //0x44
    unsigned __int64 HalReserved [8];                                               //0x48
    unsigned __int8 MinorVersion;                                                    //0x88
    unsigned __int8 MajorVersion;                                                    //0x8a
    unsigned __int8 BuildType;                                                        //0x8c
    unsigned __int8 CpuVendor;                                                        //0x8d
    unsigned __int8 CoresPerPhysicalProcessor;                                        //0x8e
    unsigned __int8 LogicalProcessorsPerCore;                                         //0x8f
    unsigned __int64 PrcbPad04 [6];                                                 //0x90
    struct _KNODE* ParentNode;                                              //0xc0
    unsigned __int64 GroupSetMember;                                               //0xc8
    unsigned __int8 Group;                                                            //0xd0
    unsigned __int8 GroupIndex;                                                       //0xd1
    unsigned __int8 PrcbPad05 [2];                                                     //0xd2
    unsigned long InitialApicId;                                                    //0xd4
    unsigned long ScbOffset;                                                        //0xd8
    unsigned long ApicMask;                                                         //0xdc
    void* AcpiReserved;                                                     //0xe0
    unsigned long CFlushSize;                                                       //0xe8
    unsigned char pad [4];                                                   //0xec
    union
    {
        struct
        {
            unsigned __int64 TrappedSecurityDomain;                                //0xf0
            union
            {
                unsigned __int8 BpbState;                                             //0xf8
                struct
                {
                    unsigned __int8 BpbCpuIdle : 1;                                     //0xf8
                    unsigned __int8 BpbFlushRsbOnTrap : 1;                              //0xf8
                    unsigned __int8 BpbIbpbOnReturn : 1;                                //0xf8
                    unsigned __int8 BpbIbpbOnTrap : 1;                                  //0xf8
                    unsigned __int8 BpbIbpbOnRetpolineExit : 1;                         //0xf8
                    unsigned __int8 BpbStateReserved : 3;                               //0xf8
                };
            };
            union
            {
                unsigned __int8 BpbFeatures;                                          //0xf9
                struct
                {
                    unsigned __int8 BpbClearOnIdle : 1;                                 //0xf9
                    unsigned __int8 BpbEnabled : 1;                                     //0xf9
                    unsigned __int8 BpbSmep : 1;                                        //0xf9
                    unsigned __int8 BpbFeaturesReserved : 5;                            //0xf9
                };
            };
            unsigned __int8 BpbCurrentSpecCtrl;                                       //0xfa
            unsigned __int8 BpbKernelSpecCtrl;                                        //0xfb
            unsigned __int8 BpbNmiSpecCtrl;                                           //0xfc
            unsigned __int8 BpbUserSpecCtrl;                                          //0xfd
            volatile SHORT PairRegister;                                    //0xfe
        };
        unsigned __int64 PrcbPad11 [2];                                             //0xf0
    };
    unsigned char ProcessorState [0x5c0];                                //0x100
    struct _XSAVE_AREA_HEADER* ExtendedSupervisorState;                     //0x6c0
    unsigned long ProcessorSignature;                                               //0x6c8
    unsigned long ProcessorFlags;                                                   //0x6cc
    union
    {
        struct
        {
            unsigned __int8 BpbRetpolineExitSpecCtrl;                                 //0x6d0
            unsigned __int8 BpbTrappedRetpolineExitSpecCtrl;                          //0x6d1
            union
            {
                unsigned __int8 BpbTrappedBpbState;                                   //0x6d2
                struct
                {
                    unsigned __int8 BpbTrappedCpuIdle : 1;                              //0x6d2
                    unsigned __int8 BpbTrappedFlushRsbOnTrap : 1;                       //0x6d2
                    unsigned __int8 BpbTrappedIbpbOnReturn : 1;                         //0x6d2
                    unsigned __int8 BpbTrappedIbpbOnTrap : 1;                           //0x6d2
                    unsigned __int8 BpbTrappedIbpbOnRetpolineExit : 1;                  //0x6d2
                    unsigned __int8 BpbtrappedBpbStateReserved : 3;                     //0x6d2
                };
            };
            union
            {
                unsigned __int8 BpbRetpolineState;                                    //0x6d3
                struct
                {
                    unsigned __int8 BpbRunningNonRetpolineCode : 1;                     //0x6d3
                    unsigned __int8 BpbIndirectCallsSafe : 1;                           //0x6d3
                    unsigned __int8 BpbRetpolineEnabled : 1;                            //0x6d3
                    unsigned __int8 BpbRetpolineStateReserved : 5;                      //0x6d3
                };
            };
            unsigned long PrcbPad12b;                                               //0x6d4
        };
        unsigned __int64 PrcbPad12a;                                               //0x6d0
    };
    unsigned __int64 PrcbPad12 [3];                                                 //0x6d8
    struct _KSPIN_LOCK_QUEUE LockQueue [17];                                 //0x6f0
    unsigned char PPLookasideList [0x100];                          //0x800
    struct _GENERAL_LOOKASIDE_POOL PPNxPagedLookasideList [32];              //0x900
    struct _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList [32];               //0x1500
    struct _GENERAL_LOOKASIDE_POOL PPPagedLookasideList [32];                //0x2100
    unsigned __int64 PrcbPad20;                                                    //0x2d00
    struct _SINGLE_LIST_ENTRY DeferredReadyListHead;                        //0x2d08
    volatile long MmPageFaultCount;                                         //0x2d10
    volatile long MmCopyOnWriteCount;                                       //0x2d14
    volatile long MmTransitionCount;                                        //0x2d18
    volatile long MmDemandZeroCount;                                        //0x2d1c
    volatile long MmPageReadCount;                                          //0x2d20
    volatile long MmPageReadIoCount;                                        //0x2d24
    volatile long MmDirtyPagesWriteCount;                                   //0x2d28
    volatile long MmDirtyWriteIoCount;                                      //0x2d2c
    volatile long MmMappedPagesWriteCount;                                  //0x2d30
    volatile long MmMappedWriteIoCount;                                     //0x2d34
    unsigned long KeSystemCalls;                                                    //0x2d38
    unsigned long KeContextSwitches;                                                //0x2d3c
    unsigned long PrcbPad40;                                                        //0x2d40
    unsigned long CcFastReadNoWait;                                                 //0x2d44
    unsigned long CcFastReadWait;                                                   //0x2d48
    unsigned long CcFastReadNotPossible;                                            //0x2d4c
    unsigned long CcCopyReadNoWait;                                                 //0x2d50
    unsigned long CcCopyReadWait;                                                   //0x2d54
    unsigned long CcCopyReadNoWaitMiss;                                             //0x2d58
    volatile long IoReadOperationCount;                                     //0x2d5c
    volatile long IoWriteOperationCount;                                    //0x2d60
    volatile long IoOtherOperationCount;                                    //0x2d64
    union _LARGE_INTEGER IoReadTransferCount;                               //0x2d68
    union _LARGE_INTEGER IoWriteTransferCount;                              //0x2d70
    union _LARGE_INTEGER IoOtherTransferCount;                              //0x2d78
    volatile long PacketBarrier;                                            //0x2d80
    volatile long TargetCount;                                              //0x2d84
    volatile unsigned long IpiFrozen;                                               //0x2d88
    unsigned long PrcbPad30;                                                        //0x2d8c
    void* IsrDpcStats;                                                      //0x2d90
    unsigned long DeviceInterrupts;                                                 //0x2d98
    long LookasideIrpFloat;                                                 //0x2d9c
    unsigned long InterruptLastCount;                                               //0x2da0
    unsigned long InterruptRate;                                                    //0x2da4
    unsigned __int64 LastNonHrTimerExpiration;                                     //0x2da8
    struct _KPRCB* PairPrcb;                                                //0x2db0
    unsigned __int64 PrcbPad35 [1];                                                 //0x2db8
    union _SLIST_HEADER InterruptObjectPool;                                //0x2dc0
    unsigned __int64 PrcbPad41 [6];                                                 //0x2dd0
    KDPC_DATA DpcData [2];                                           //0x2e00
    void* DpcStack;                                                         //0x2e50
    long MaximumDpcQueueDepth;                                              //0x2e58
    unsigned long DpcRequestRate;                                                   //0x2e5c
    unsigned long MinimumDpcRate;                                                   //0x2e60
    unsigned long DpcLastCount;                                                     //0x2e64
    unsigned __int8 ThreadDpcEnable;                                                  //0x2e68
    volatile unsigned __int8 QuantumEnd;                                              //0x2e69
    volatile unsigned __int8 DpcRoutineActive;                                        //0x2e6a
    volatile unsigned __int8 IdleSchedule;                                            //0x2e6b
    union
    {
        volatile long DpcRequestSummary;                                    //0x2e6c
        SHORT DpcRequestSlot [2];                                            //0x2e6c
        struct
        {
            SHORT NormalDpcState;                                           //0x2e6c
            SHORT ThreadDpcState;                                           //0x2e6e
        };
        struct
        {
            unsigned long DpcNormalProcessingActive : 1;                              //0x2e6c
            unsigned long DpcNormalProcessingRequested : 1;                           //0x2e6c
            unsigned long DpcNormalThreadSignal : 1;                                  //0x2e6c
            unsigned long DpcNormalTimerExpiration : 1;                               //0x2e6c
            unsigned long DpcNormalDpcPresent : 1;                                    //0x2e6c
            unsigned long DpcNormalLocalInterrupt : 1;                                //0x2e6c
            unsigned long DpcNormalSpare : 10;                                        //0x2e6c
            unsigned long DpcThreadActive : 1;                                        //0x2e6c
            unsigned long DpcThreadRequested : 1;                                     //0x2e6c
            unsigned long DpcThreadSpare : 14;                                        //0x2e6c
        };
    };
    unsigned long LastTimerHand;                                                    //0x2e70
    unsigned long LastTick;                                                         //0x2e74
    unsigned long ClockInterrupts;                                                  //0x2e78
    unsigned long ReadyScanTick;                                                    //0x2e7c
    void* InterruptObject [256];                                             //0x2e80
    unsigned char TimerTable [0x2200];                                        //0x3680
    struct _KGATE DpcGate;                                                  //0x5880
    void* PrcbPad52;                                                        //0x5898
    struct _KDPC CallDpc;                                                   //0x58a0
    long ClockKeepAlive;                                                    //0x58e0
    unsigned __int8 PrcbPad60 [2];                                                     //0x58e4
    unsigned __int8 NmiActive;                                                       //0x58e6
    long DpcWatchdogPeriod;                                                 //0x58e8
    long DpcWatchdogCount;                                                  //0x58ec
    volatile long KeSpinLockOrdering;                                       //0x58f0
    unsigned long DpcWatchdogProfileCumulativeDpcThreshold;                         //0x58f4
    void* CachedPtes;                                                       //0x58f8
    struct _LIST_ENTRY WaitListHead;                                        //0x5900
    unsigned __int64 WaitLock;                                                     //0x5910
    unsigned long ReadySummary;                                                     //0x5918
    long AffinitizedSelectionMask;                                          //0x591c
    unsigned long QueueIndex;                                                       //0x5920
    unsigned long PrcbPad75 [3];                                                     //0x5924
    struct _KDPC TimerExpirationDpc;                                        //0x5930
    unsigned char ScbQueue [0x10];                                           //0x5970
    struct _LIST_ENTRY DispatcherReadyListHead [32];                         //0x5980
    unsigned long InterruptCount;                                                   //0x5b80
    unsigned long KernelTime;                                                       //0x5b84
    unsigned long UserTime;                                                         //0x5b88
    unsigned long DpcTime;                                                          //0x5b8c
    unsigned long InterruptTime;                                                    //0x5b90
    unsigned long AdjustDpcThreshold;                                               //0x5b94
    unsigned __int8 DebuggerSavedIRQL;                                                //0x5b98
    unsigned __int8 GroupSchedulingOverQuota;                                         //0x5b99
    volatile unsigned __int8 DeepSleep;                                               //0x5b9a
    unsigned __int8 PrcbPad80;                                                        //0x5b9b
    unsigned long DpcTimeCount;                                                     //0x5b9c
    unsigned long DpcTimeLimit;                                                     //0x5ba0
    unsigned long PeriodicCount;                                                    //0x5ba4
    unsigned long PeriodicBias;                                                     //0x5ba8
    unsigned long AvailableTime;                                                    //0x5bac
    unsigned long KeExceptionDispatchCount;                                         //0x5bb0
    unsigned long ReadyThreadCount;                                                 //0x5bb4
    unsigned __int64 ReadyQueueExpectedRunTime;                                    //0x5bb8
    unsigned __int64 StartCycles;                                                  //0x5bc0
    unsigned __int64 TaggedCyclesStart;                                            //0x5bc8
    unsigned __int64 TaggedCycles [2];                                              //0x5bd0
    unsigned __int64 GenerationTarget;                                             //0x5be0
    unsigned __int64 AffinitizedCycles;                                            //0x5be8
    unsigned __int64 ImportantCycles;                                              //0x5bf0
    unsigned __int64 UnimportantCycles;                                            //0x5bf8
    unsigned long DpcWatchdogProfileSingleDpcThreshold;                             //0x5c00
    volatile long MmSpinLockOrdering;                                       //0x5c04
    void* volatile CachedStack;                                             //0x5c08
    unsigned long PageColor;                                                        //0x5c10
    unsigned long NodeColor;                                                        //0x5c14
    unsigned long NodeShiftedColor;                                                 //0x5c18
    unsigned long SecondaryColorMask;                                               //0x5c1c
    unsigned __int8 PrcbPad81 [7];                                                     //0x5c20
    unsigned __int8 TbFlushListActive;                                                //0x5c27
    unsigned __int64 PrcbPad82 [2];                                                 //0x5c28
    unsigned __int64 CycleTime;                                                    //0x5c38
    unsigned __int64 Cycles [4][2];                                                 //0x5c40
    unsigned long CcFastMdlReadNoWait;                                              //0x5c80
    unsigned long CcFastMdlReadWait;                                                //0x5c84
    unsigned long CcFastMdlReadNotPossible;                                         //0x5c88
    unsigned long CcMapDataNoWait;                                                  //0x5c8c
    unsigned long CcMapDataWait;                                                    //0x5c90
    unsigned long CcPinMappedDataCount;                                             //0x5c94
    unsigned long CcPinReadNoWait;                                                  //0x5c98
    unsigned long CcPinReadWait;                                                    //0x5c9c
    unsigned long CcMdlReadNoWait;                                                  //0x5ca0
    unsigned long CcMdlReadWait;                                                    //0x5ca4
    unsigned long CcLazyWriteHotSpots;                                              //0x5ca8
    unsigned long CcLazyWriteIos;                                                   //0x5cac
    unsigned long CcLazyWritePages;                                                 //0x5cb0
    unsigned long CcDataFlushes;                                                    //0x5cb4
    unsigned long CcDataPages;                                                      //0x5cb8
    unsigned long CcLostDelayedWrites;                                              //0x5cbc
    unsigned long CcFastReadResourceMiss;                                           //0x5cc0
    unsigned long CcCopyReadWaitMiss;                                               //0x5cc4
    unsigned long CcFastMdlReadResourceMiss;                                        //0x5cc8
    unsigned long CcMapDataNoWaitMiss;                                              //0x5ccc
    unsigned long CcMapDataWaitMiss;                                                //0x5cd0
    unsigned long CcPinReadNoWaitMiss;                                              //0x5cd4
    unsigned long CcPinReadWaitMiss;                                                //0x5cd8
    unsigned long CcMdlReadNoWaitMiss;                                              //0x5cdc
    unsigned long CcMdlReadWaitMiss;                                                //0x5ce0
    unsigned long CcReadAheadIos;                                                   //0x5ce4
    volatile long MmCacheTransitionCount;                                   //0x5ce8
    volatile long MmCacheReadCount;                                         //0x5cec
    volatile long MmCacheIoCount;                                           //0x5cf0
    unsigned long PrcbPad91;                                                        //0x5cf4
    void* MmInternal;                                                       //0x5cf8
    unsigned char PowerState [0x200];                               //0x5d00
    void* HyperPte;                                                         //0x5f00
    struct _LIST_ENTRY ScbList;                                             //0x5f08
    struct _KDPC ForceIdleDpc;                                              //0x5f18
    struct _KDPC DpcWatchdogDpc;                                            //0x5f58
    struct _KTIMER DpcWatchdogTimer;                                        //0x5f98
    struct _CACHE_DESCRIPTOR Cache [5];                                      //0x5fd8
    unsigned long CacheCount;                                                       //0x6014
    volatile unsigned long CachedCommit;                                            //0x6018
    volatile unsigned long CachedResidentAvailable;                                 //0x601c
    void* WheaInfo;                                                         //0x6020
    void* EtwSupport;                                                       //0x6028
    void* ExSaPageArray;                                                    //0x6030
    unsigned long KeAlignmentFixupCount;                                            //0x6038
    unsigned long PrcbPad95;                                                        //0x603c
    union _SLIST_HEADER HypercallPageList;                                  //0x6040
    unsigned __int64* StatisticsPage;                                              //0x6050
    unsigned __int64 PrcbPad85 [5];                                                 //0x6058
    void* HypercallCachedPages;                                             //0x6080
    void* VirtualApicAssist;                                                //0x6088
    unsigned char PackageProcessorSet [0xa8];                               //0x6090
    unsigned __int64 PrcbPad86;                                                    //0x6138
    unsigned __int64 SharedReadyQueueMask;                                         //0x6140
    struct _KSHARED_READY_QUEUE* SharedReadyQueue;                          //0x6148
    unsigned long SharedQueueScanOwner;                                             //0x6150
    unsigned long ScanSiblingIndex;                                                 //0x6154
    unsigned __int64 CoreProcessorSet;                                             //0x6158
    unsigned __int64 ScanSiblingMask;                                              //0x6160
    unsigned __int64 LLCMask;                                                      //0x6168
    unsigned __int64 CacheProcessorMask [5];                                        //0x6170
    struct _PROCESSOR_PROFILE_CONTROL_AREA* ProcessorProfileControlArea;    //0x6198
    void* ProfileEventIndexAddress;                                         //0x61a0
    void** DpcWatchdogProfile;                                              //0x61a8
    void** DpcWatchdogProfileCurrentEmptyCapture;                           //0x61b0
    void* SchedulerAssist;                                                  //0x61b8
    unsigned char SynchCounters [0xb8];                                   //0x61c0
    unsigned __int64 PrcbPad94;                                                    //0x6278
    unsigned char FsCounters [0x10];                            //0x6280
    unsigned __int8 VendorString [13];                                                 //0x6290
    unsigned __int8 PrcbPad100 [3];                                                    //0x629d
    unsigned __int64 FeatureBits;                                                  //0x62a0
    union _LARGE_INTEGER UpdateSignature;                                   //0x62a8
    unsigned __int64 PteBitCache;                                                  //0x62b0
    unsigned long PteBitOffset;                                                     //0x62b8
    unsigned long PrcbPad105;                                                       //0x62bc
    struct _CONTEXT* Context;                                               //0x62c0
    unsigned long ContextFlagsInit;                                                 //0x62c8
    unsigned long PrcbPad115;                                                       //0x62cc
    struct _XSAVE_AREA* ExtendedState;                                      //0x62d0
    void* IsrStack;                                                         //0x62d8
    unsigned char EntropyTimingState [0x150];                       //0x62e0
    unsigned __int64 PrcbPad110;                                                   //0x6430
    struct
    {
        unsigned long UpdateCycle;                                                  //0x6438
        union
        {
            SHORT PairLocal;                                                //0x643c
            struct
            {
                unsigned __int8 PairLocalLow;                                         //0x643c
                unsigned __int8 PairLocalForceStibp : 1;                                //0x643d
                unsigned __int8 Reserved : 4;                                           //0x643d
                unsigned __int8 Frozen : 1;                                             //0x643d
                unsigned __int8 ForceUntrusted : 1;                                     //0x643d
                unsigned __int8 SynchIpi : 1;                                           //0x643d
            };
        };
        union
        {
            SHORT PairRemote;                                               //0x643e
            struct
            {
                unsigned __int8 PairRemoteLow;                                        //0x643e
                unsigned __int8 Reserved2;                                            //0x643f
            };
        };
        unsigned __int8 Trace [24];                                                    //0x6440
        unsigned __int64 LocalDomain;                                              //0x6458
        unsigned __int64 RemoteDomain;                                             //0x6460
        struct _KTHREAD* Thread;                                            //0x6468
    } StibpPairingTrace;                                                    //0x6438
    struct _SINGLE_LIST_ENTRY AbSelfIoBoostsList;                           //0x6470
    struct _SINGLE_LIST_ENTRY AbPropagateBoostsList;                        //0x6478
    struct _KDPC AbDpc;                                                     //0x6480
    unsigned char IoIrpStackProfilerCurrent [0x54];               //0x64c0
    unsigned char IoIrpStackProfilerPrevious [0x54];              //0x6514
    unsigned char SecureFault [0x10];                          //0x6568
    unsigned __int64 PrcbPad120;                                                   //0x6578
    unsigned char LocalSharedReadyQueue [0x270];                      //0x6580
    unsigned __int64 PrcbPad125 [2];                                                //0x67f0
    unsigned long TimerExpirationTraceCount;                                        //0x6800
    unsigned long PrcbPad127;                                                       //0x6804
    unsigned char TimerExpirationTrace [0x100];               //0x6808
    unsigned __int64 PrcbPad128 [7];                                                //0x6908
    struct _REQUEST_MAILBOX* Mailbox;                                       //0x6940
    unsigned __int64 PrcbPad130 [7];                                                //0x6948
    unsigned char McheckContext [0x50 * 2];                         //0x6980
    unsigned __int64 PrcbPad134 [4];                                                //0x6a20
    struct _KLOCK_QUEUE_HANDLE SelfmapLockHandle [4];                        //0x6a40
    unsigned __int64 PrcbPad134a [4];                                               //0x6aa0
    unsigned __int8 PrcbPad138 [960];                                                  //0x6ac0
    unsigned __int64 KernelDirectoryTableBase;                                     //0x6e80
    unsigned __int64 RspBaseShadow;                                                //0x6e88
    unsigned __int64 UserRspShadow;                                                //0x6e90
    unsigned long ShadowFlags;                                                      //0x6e98
    unsigned long DbgMceNestingLevel;                                               //0x6e9c
    unsigned long DbgMceFlags;                                                      //0x6ea0
    unsigned long PrcbPad139;                                                       //0x6ea4
    unsigned __int64 PrcbPad140 [507];                                              //0x6ea8
    unsigned char RequestMailbox [0x40];                              //0x7e80
} KPRCB;

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    char WaitRegister;                                                      //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted [2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG UmsDirectedSwitchEnable : 1;                                //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG UmsPerformingSyscall : 1;                                   //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetShadowStack : 1;                                         //0x74
            ULONG Reserved : 11;                                              //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG BamQosLevel : 2;                                            //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG ThreadFlagsSpare : 1;                                       //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill [43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock [4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4 [20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5 [68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6 [116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7 [164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8 [40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9 [88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10 [136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11 [176];                                     //0x140
            struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
            struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
        };
    };
    VOID* Spare21;                                                          //0x200
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    union
    {
        struct _GROUP_AFFINITY UserAffinity;                                //0x228
        struct
        {
            UCHAR UserAffinityFill [10];                                     //0x228
            CHAR PreviousMode;                                              //0x232
            CHAR BasePriority;                                              //0x233
            union
            {
                CHAR PriorityDecrement;                                     //0x234
                struct
                {
                    UCHAR ForegroundBoost : 4;                                //0x234
                    UCHAR UnusualBoost : 4;                                   //0x234
                };
            };
            UCHAR Preempted;                                                //0x235
            UCHAR AdjustReason;                                             //0x236
            CHAR AdjustIncrement;                                           //0x237
        };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
        struct _GROUP_AFFINITY Affinity;                                    //0x240
        struct
        {
            UCHAR AffinityFill [10];                                         //0x240
            UCHAR ApcStateIndex;                                            //0x24a
            UCHAR WaitBlockCount;                                           //0x24b
            ULONG IdealProcessor;                                           //0x24c
        };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill [43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill0 [1];                                     //0x288
            UCHAR ResourceIndex;                                            //0x289
        };
        struct
        {
            UCHAR SchedulerApcFill1 [3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2 [4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3 [64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4 [72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5 [83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    char LockEntries [0x240];                                                //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x560
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x568
    UCHAR PriorityFloorCounts [16];                                          //0x570
    ULONG PriorityFloorSummary;                                             //0x580
    volatile LONG AbCompletedIoBoostCount;                                  //0x584
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x588
    volatile SHORT KeReferenceCount;                                        //0x58c
    UCHAR AbOrphanedEntrySummary;                                           //0x58e
    UCHAR AbOwnedEntryCount;                                                //0x58f
    ULONG ForegroundLossTime;                                               //0x590
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x598
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x598
            ULONGLONG InGlobalForegroundList;                               //0x5a0
        };
    };
    LONGLONG ReadOperationCount;                                            //0x5a8
    LONGLONG WriteOperationCount;                                           //0x5b0
    LONGLONG OtherOperationCount;                                           //0x5b8
    LONGLONG ReadTransferCount;                                             //0x5c0
    LONGLONG WriteTransferCount;                                            //0x5c8
    LONGLONG OtherTransferCount;                                            //0x5d0
    struct _KSCB* QueuedScb;                                                //0x5d8
    volatile ULONG ThreadTimerDelay;                                        //0x5e0
    union
    {
        volatile LONG ThreadFlags2;                                         //0x5e4
        struct
        {
            ULONG PpmPolicy : 2;                                              //0x5e4
            ULONG ThreadFlags2Reserved : 30;                                  //0x5e4
        };
    };
    VOID* SchedulerAssist;                                                  //0x5e8
} KThread;

/// <summary>
/// https://github.com/EricYoong/impfinder/blob/c1b58e56e1219235f3d6e08d6dc3fb4643312199/defines.h#L73
/// </summary>
typedef struct _IMAGE
{
	UINT_PTR Base;
	SIZE_T Size;
}IMAGE, * PIMAGE;

/// <summary>
/// 
/// </summary>
typedef struct _ENTRY_PARAMETERS
{
	UINT64 PoolBase;
	UINT32 EntryPoint;
	UINT64 Size;
} ENTRY_PARAMETERS, * PENTRY_PARAMETERS;

/// <summary>
/// 
/// </summary>

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

///////////////////////////////////////////////////////////////////////////////////////////
//extern "C"
//{
//	NTSTATUS WINAPI ZwQuerySystemInformation (
//		_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
//		_Inout_   PVOID                    SystemInformation,
//		_In_      ULONG                    SystemInformationLength,
//		_Out_opt_ PULONG                   ReturnLength
//	);
//	NTSTATUS WINAPI MmCopyVirtualMemory (
//		_In_  PEPROCESS                SourceProcess,
//		_In_  PVOID                    SourceAddress,
//		_In_  PEPROCESS                TargetProcess,
//		_Out_ PVOID                    TargetAddress,
//		_In_  SIZE_T                   BufferSize,
//		_In_  KPROCESSOR_MODE          PreviousMode,
//		_Out_ PSIZE_T                  ReturnSize
//	);
//	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress (
//		__in PEPROCESS Process
//	);
//};
///////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////

typedef NTSYSAPI NTSTATUS ( WINAPI* ZwQuerySystemInformationStruct )(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);
typedef NTSYSAPI PVOID ( WINAPI* RtlFindExportedRoutineByNameStruct )(
	_In_ PVOID ImageBase,
	_In_ PCCH  RoutineName
	);
typedef NTSYSAPI VOID ( WINAPI* RtlInitUnicodeStringStruct )(
	_Out_                       PUNICODE_STRING DestinationString,
	_In_opt_z_ __drv_aliasesMem PCWSTR SourceString
	);
typedef NTSYSAPI NTSTATUS ( WINAPI* RtlUnicodeStringToAnsiStringStruct )(
	_When_ ( AllocateDestinationString, _Out_ _At_ ( DestinationString->Buffer, __drv_allocatesMem ( Mem ) ) )
	_When_ ( !AllocateDestinationString, _Inout_ )
	PANSI_STRING              DestinationString,
	_In_   PCUNICODE_STRING   SourceString,
	_In_   BOOLEAN            AllocateDestinationString
	);
typedef NTSYSAPI VOID ( WINAPI* RtlFreeAnsiStringStruct )(
	_Inout_ _At_ ( AnsiString->Buffer, _Frees_ptr_opt_ )
	PANSI_STRING AnsiString
	);
typedef NTSYSAPI VOID ( WINAPI* ExFreePoolWithTagStruct )(
	_Pre_notnull_ __drv_freesMem ( Mem ) PVOID P,
	_In_ ULONG                                 Tag
	);
typedef NTSYSAPI PVOID ( WINAPI* ExAllocatePoolWithTagStruct )(
	_In_ __drv_strictTypeMatch ( __drv_typeExpr ) POOL_TYPE PoolType,
	_In_ SIZE_T                                             NumberOfBytes,
	_In_ ULONG                                              Tag
	);
typedef NTSYSAPI PVOID ( WINAPI* ExAllocatePoolStruct )(
	__drv_strictTypeMatch ( __drv_typeExpr ) _In_ POOL_TYPE PoolType,
	_In_ SIZE_T                                             NumberOfBytes
	);
typedef NTSYSAPI VOID ( WINAPI* RtlInitAnsiStringStruct )(
	_Out_ PANSI_STRING               DestinationString,
	_In_opt_z_ __drv_aliasesMem PCSZ SourceString
	);
typedef NTSYSAPI BOOLEAN ( WINAPI* RtlEqualStringStruct )(
	_In_ const   STRING* String1,
	_In_ const   STRING* String2,
	_In_         BOOLEAN           CaseInSensitive
	);
typedef NTSYSAPI NTSTATUS ( WINAPI* MmCopyMemoryStruct )(
	_In_         PVOID              TargetAddress,
	_In_         MM_COPY_ADDRESS    SourceAddress,
	_In_         SIZE_T             NumberOfBytes,
	_In_         ULONG              Flags,
	_Out_        PSIZE_T            NumberOfBytesTransferred
	);
typedef NTSYSAPI PVOID ( WINAPI* PsGetProcessSectionBaseAddressStruct )(
	_In_         PEPROCESS       Process
	);
typedef NTSYSAPI PMDL ( WINAPI* IoAllocateMdlStruct )(
	_In_opt_ __drv_aliasesMem PVOID    VirtualAddress,
	_In_                      ULONG    Length,
	_In_                      BOOLEAN  SecondaryBuffer,
	_In_                      BOOLEAN  ChargeQuota,
	_Inout_opt_               PIRP     Irp
	);
typedef NTSYSAPI VOID ( WINAPI* IoFreeMdlStruct )(
	_In_         PMDL           Mdl
	);
typedef NTSYSAPI PEPROCESS ( WINAPI* IoGetCurrentProcessStruct )(
	VOID
	);
typedef NTSYSAPI NTSTATUS ( WINAPI* PsLookupProcessByProcessIdStruct )(
	_In_         HANDLE             ProcessId,
	_Outptr_     PEPROCESS* Process
	);
typedef NTSYSAPI KPROCESSOR_MODE ( WINAPI* ExGetPreviousModeStruct )(
	VOID
	);
typedef NTSYSAPI NTSTATUS ( WINAPI* MmCopyVirtualMemoryStruct )(
	_In_         PEPROCESS          FromProcess,
	_In_         CONST VOID* FromAddress,
	_In_         PEPROCESS          ToProcess,
	_Out_        PVOID              ToAddress,
	_In_         SIZE_T             BufferSize,
	_In_         KPROCESSOR_MODE    PreviousMode,
	_Out_        PSIZE_T            NumberOfBytesCopied
	);
typedef NTSYSAPI LONG_PTR ( FASTCALL* ObfDereferenceObjectStruct )(
	_In_         PVOID                Object
	);

typedef NTSYSAPI PLIST_ENTRY PsLoadedModuleListStruct;

///////////////////////////////////////////////////////////////////////////////////////////

ZwQuerySystemInformationStruct ZQSI { };

RtlInitUnicodeStringStruct RIUS { };
RtlInitAnsiStringStruct RIAS { };
RtlEqualStringStruct RES { };
RtlFindExportedRoutineByNameStruct RFERBN { };
RtlUnicodeStringToAnsiStringStruct RUSTAS { };
RtlFreeAnsiStringStruct RFAS { };

ExAllocatePoolStruct EAP { };
ExAllocatePoolWithTagStruct EAPWT { };
ExFreePoolWithTagStruct EFPWT { };
ExGetPreviousModeStruct EGPM { };

MmCopyMemoryStruct MCM { };
MmCopyVirtualMemoryStruct MCVM { };

PsGetProcessSectionBaseAddressStruct PGPSBA { };
PsLookupProcessByProcessIdStruct PLPBPI { };
PsLoadedModuleListStruct PLML { };

IoGetCurrentProcessStruct IGCP { };
IoAllocateMdlStruct IAM { };
IoFreeMdlStruct IFM { };

ObfDereferenceObjectStruct ODO { };

UINT EntryPoint { };
ULONGLONG PoolBase { };
UINT Size { };

#include "Encryption.hpp"
#include "Spoofer.hpp"

#define MISC_FLAG_ALERTABLE		4
#define MISC_FLAG_APC			14

#define _DEBUG_MODE TRUE
#if _DEBUG_MODE
#define Debug( Content, ... ) DbgPrintEx( NULL, NULL, skCrypt("[+] " Content " \n", __VA_ARGS__) )
#endif
#define Dereference(Pointer) (const std::uintptr_t)(Pointer + *( int * )( ( BYTE * )Pointer + 3 ) + 7)
#ifdef __cplusplus
extern "C" {
#endif
	int _fltused = 0;
#ifdef __cplusplus
}
#endif

#include "Memory.hpp"
