#include "includes.h"
#include "RequestHandling/RequestHandling.h"

__int64(__fastcall* pfnWdfChildListBeginScan_original)(void* a1, void* a2);
__int64 __fastcall FirmwareTableInformationHandlerWStack(void* a1, void* StackVar1)
{
	if (a1)
	{
		PVOID RequestBufferPtr = 0;
		memcpy(&RequestBufferPtr, reinterpret_cast<SYSTEM_FIRMWARE_TABLE_INFORMATION*>(a1)->TableBuffer, sizeof(PVOID));
		if (FoxUtils::GoodPtr(RequestBufferPtr))
		{
			if (auto req = reinterpret_cast<RequestHandling::RequestBuild*>(RequestBufferPtr)) {
				if (req->MagicKey == RequestHandling::ReqMagicKey)
				{
					if (req->ReqType == RequestHandling::RequestTypes::ReqDrvHandShake)
					{
						*(bool*)req->args = true;
						*req->ResultStatus = STATUS_SUCCESS;
					}
					else if (req->ReqType == RequestHandling::RequestTypes::ReqModuleBasicInfo)
					{
						auto args = reinterpret_cast<RequestHandling::pDataModule>(req->args);
						*req->ResultStatus = STATUS_INVALID_PARAMETER;
						if (args)
						{
							*req->ResultStatus = RequestHandling::HandleModule(args);
						}
					}
					else if (req->ReqType == RequestHandling::RequestTypes::ReqMemcpy)
					{
						auto args = reinterpret_cast<RequestHandling::pDataMemcopy>(req->args);
						*req->ResultStatus = STATUS_INVALID_PARAMETER;
						if (args)
						{
							*req->ResultStatus = RequestHandling::HandleMemcopy(args);
						}
					}
					else if (req->ReqType == RequestHandling::RequestTypes::ReqKernelMouseInput)
					{
						auto args = reinterpret_cast<RequestHandling::pDataKernelMouseInput>(req->args);
						*req->ResultStatus = STATUS_INVALID_PARAMETER;
						if (args)
						{
							*req->ResultStatus = RequestHandling::HandleKernelMouseInput(args);
						}
					}
					return STATUS_SUCCESS;
				}
			}
		}
	}
	
	if(pfnWdfChildListBeginScan_original)
		return pfnWdfChildListBeginScan_original(a1, StackVar1);
	return 0;
}

bool MainInit(MDL* MdlPtr)
{
	{
		ImpSet(MmIsAddressValid);
		ImpSet(RtlInitUnicodeString);
		ImpSet(ZwQuerySystemInformation);
		ImpSet(ExAllocatePoolWithTag);
		ImpSet(ExFreePoolWithTag);
		ImpSet(RtlEqualUnicodeString);
		ImpSet(PsLookupProcessByProcessId);
		ImpSet(strcmp);
		ImpSet(strlen);
		ImpSet(IoGetDeviceObjectPointer);
		ImpSet(KeStackAttachProcess);
		ImpSet(KeUnstackDetachProcess);
		ImpSet(ObfDereferenceObject);
		ImpSet(MmCopyMemory);
		ImpSet(DbgPrintEx);
		ImpSet(ZwSetSystemInformation);
		ImpSet(PsGetProcessPeb);
		ImpSet(RtlCompareUnicodeString);
		ImpSet(IoGetCurrentProcess);
		ImpSet(MmCopyVirtualMemory);
		ImpSet(ObReferenceObjectByName);
	}
	if(FoxUtils::GoodPtr(MdlPtr))
	{
		if (!FoxUtils::secure::null_pfn(MdlPtr))
			return false;
	}
	else
	{
		return false;
	}

	if (!FoxUtils::ki.InitKiStackUtils(KrlBase))
	{
		return false;
	}

	auto GUIProcess = FoxUtils::GetGUIAttachEProcess();
	if (!GUIProcess)
	{
		return false;
	}

	size_t JumpDriverSize = 0;
	auto JumpDriverBase = FoxUtils::GetKernelModule("Wdf01000.sys", &JumpDriverSize);
	if (!JumpDriverBase)
	{
		IC(ObfDereferenceObject, GUIProcess);
		return false;
	}

	bool bSuccess = false;
	UINT64 JumpFunction;
	UINT64 JumpFunctionPtr;
	SYSTEM_FIRMWARE_TABLE_HANDLER* pTableHandlerDataBuffer;
	NTSTATUS status;
	PDRIVER_OBJECT DriverObj;

	auto KState = FoxUtils::ki.Attach(GUIProcess);

	JumpFunction = FoxUtils::FindPatternImage(JumpDriverBase, "\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x4C\x8B\x54\x24\x00\x48\x8B\x05\x00\x00\x00\x00\x4C\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00", 
		"xxxxxxx????xx????xxxxxxxxxxxxxxxxxxxxxxx?xxx????xxxx?xx????xxxxxxxxxxxxxxxxxxxxxxxxxxxx????xx????xxxxxxxxxxxxxxxxxxxxxx????xx????xxxxxxxxxxxxxxxxxxxxxx????xx????xxxxxxxxxxxxxxxxxxxxxx????xx????xxxxxxxxxxxxxxxxxxxxxx????");
	if (!FoxUtils::GoodPtr((PVOID)JumpFunction))
	{
		goto exit;
	}

	JumpFunctionPtr = RVA(JumpFunction + 0x4, 7);
	if (!FoxUtils::GoodPtr((PVOID)JumpFunctionPtr))
	{
		goto exit;
	}

	pTableHandlerDataBuffer = (SYSTEM_FIRMWARE_TABLE_HANDLER*)IC(ExAllocatePoolWithTag, NonPagedPool, sizeof(SYSTEM_FIRMWARE_TABLE_HANDLER), 'WSMB');
	if (!pTableHandlerDataBuffer)
	{
		goto exit;
	}

	status = FoxUtils::GetDriverObject((L"\\Device\\RawCdRom"), &DriverObj);
	if (!NT_SUCCESS(status) || !DriverObj) {
		goto exit;
	}

	*(LONG64*)&pfnWdfChildListBeginScan_original = _InterlockedExchange64((LONG64*)JumpFunctionPtr, (LONG64)FirmwareTableInformationHandlerWStack);

	pTableHandlerDataBuffer->DriverObject = DriverObj;
	pTableHandlerDataBuffer->ProviderSignature = 'WDF';
	pTableHandlerDataBuffer->Register = TRUE;
	pTableHandlerDataBuffer->FirmwareTableHandler = reinterpret_cast<PFNFTH>(JumpFunction);
	status = IC(ZwSetSystemInformation, SystemRegisterFirmwareTableInformationHandler, pTableHandlerDataBuffer, sizeof(SYSTEM_FIRMWARE_TABLE_HANDLER));
	if (!NT_SUCCESS(status)) {
		goto exit;
	}
	bSuccess = true;

	exit:
	FoxUtils::ki.Detach(&KState);
	IC(ObfDereferenceObject, GUIProcess);
	return bSuccess;
}

NTSTATUS DriverEntryA(UINT64 MDL_PTR, UINT64 CODE_DATA)
{
	KrlBase = FoxUtils::direct_assembly::GetKernelBase();
	if (!KrlBase)
		return 0x1;

	KrlSize = FoxUtils::pe::GetSizeOfModule(KrlBase);
	if (!KrlSize || KrlSize < 0xF)
		return 0x2;

	if (!MainInit((MDL*)MDL_PTR))
		return 0x3;

	return STATUS_SUCCESS;
}