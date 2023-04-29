#include "../includes.h"
#include "RequestHandling.h"

inline PLDR_DATA_TABLE_ENTRY GetModuleByName(PEPROCESS process, PWCHAR moduleName)
{
	UNICODE_STRING moduleNameStr = { 0 };
	IC(RtlInitUnicodeString, (PUNICODE_STRING)&moduleNameStr, (PCWSTR)moduleName);
	PLIST_ENTRY list = &(IC(PsGetProcessPeb, process)->Ldr->InLoadOrderModuleList);
	if (!list)
		return 0;
	for (PLIST_ENTRY entry = list->Flink; entry != list; ) {
		if (!entry)
			break;
		PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (module)
		{
			if (IC(RtlCompareUnicodeString, &module->BaseDllName, &moduleNameStr, TRUE) == 0) {
				return module;
			}
		}
		entry = module->InLoadOrderLinks.Flink;
	}
	return 0;
}

NTSTATUS RequestHandling::HandleModule(pDataModule args)
{
	if (!args->module_name || !args->proc_id)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS process = NULL;
	NTSTATUS status = IC(PsLookupProcessByProcessId, (HANDLE)args->proc_id, &process);
	if (NT_SUCCESS(status) && process) {

		PVOID base = NULL;
		DWORD size = 0;
		KAPC_STATE state;

		WCHAR ModuleNameCopy[155] = { 0 };
		memcpy(ModuleNameCopy, args->module_name, sizeof(ModuleNameCopy));

		auto KState = FoxUtils::ki.Attach(process);
		PLDR_DATA_TABLE_ENTRY module_ = GetModuleByName(process, ModuleNameCopy);
		if (module_ && IC(MmIsAddressValid, module_)) {
			base = module_->DllBase;
			size = module_->SizeOfImage;
		}
		else {
			status = STATUS_NOT_FOUND;
		}
		FoxUtils::ki.Detach(&KState);
		if (NT_SUCCESS(status)) {
			if (args->dest)
				*(PVOID*)args->dest = base;

			if (args->size)
				*args->size = size;
		}
		IC(ObfDereferenceObject, process);
	}
	return status;
}

NTSTATUS RequestHandling::HandleMemcopy(pDataMemcopy args)
{
	static PVOID Import_MmHighestUserAddress = 0;
	if (!Import_MmHighestUserAddress) {
		Import_MmHighestUserAddress = (PVOID)FoxUtils::pe::GetProcAdress(KrlBase, ("MmHighestUserAddress"));
	}
	if (!Import_MmHighestUserAddress)
		return STATUS_ABANDONED;
	
	if (((PBYTE)args->src + args->size < (PBYTE)args->src) ||
		((PBYTE)args->dest + args->size < (PBYTE)args->dest) ||
		((PVOID)((PBYTE)args->src + args->size) > Import_MmHighestUserAddress) ||
		((PVOID)((PBYTE)args->dest + args->size) > Import_MmHighestUserAddress)) {

		return STATUS_ACCESS_VIOLATION;
	}
	
	PEPROCESS process = NULL;
	NTSTATUS status = IC(PsLookupProcessByProcessId, (HANDLE)args->proc_id, &process);
	if (NT_SUCCESS(status) && process) {
		SIZE_T outSize = 0;
		if (args->bWrite) {
			status = IC(MmCopyVirtualMemory, IC(IoGetCurrentProcess), args->src, process, args->dest, (SIZE_T)args->size, KernelMode, &outSize);
		}
		else
			status = IC(MmCopyVirtualMemory, process, args->src, IC(IoGetCurrentProcess), args->dest, (SIZE_T)args->size, KernelMode, &outSize);
		IC(ObfDereferenceObject, process);
	}

	return status;
}

typedef struct _MOUSE_INPUT_DATA {
	USHORT UnitId;
	USHORT Flags;
	union {
		ULONG Buttons;
		struct {
			USHORT ButtonFlags;
			USHORT ButtonData;
		};
	};
	ULONG  RawButtons;
	LONG   LastX;
	LONG   LastY;
	ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

NTSTATUS RequestHandling::HandleKernelMouseInput(pDataKernelMouseInput args)
{
	static PDEVICE_OBJECT MouseDevice = 0;
	static void(*MouseClassServiceCallbackFn)(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, BYTE* InputDataEnd, PULONG InputDataConsumed) = 0;

	NTSTATUS status{ STATUS_SUCCESS };
	if(!MouseClassServiceCallbackFn || !MouseDevice)
	{
		if(!MouseClassServiceCallbackFn)
		{
			auto GUIProcess = FoxUtils::GetGUIAttachEProcess();
			
			size_t mouclassSize = 0;
			auto mouclassBase = FoxUtils::GetKernelModule("mouclass.sys", &mouclassSize);
			if (!mouclassBase)
			{
				IC(ObfDereferenceObject, GUIProcess);
				return STATUS_NOT_IMPLEMENTED;
			}
			
			BYTE OriginalInst[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x4C, 0x89, 0x48, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC };
			BYTE jmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			PVOID ShellcodeBuffer = IC(ExAllocatePoolWithTag, NonPagedPool, sizeof(OriginalInst) + sizeof(jmp), FOX_POOLTAG);
			if(!ShellcodeBuffer)
			{
				IC(ObfDereferenceObject, GUIProcess);
				return STATUS_MEMORY_NOT_ALLOCATED;
			}
			
			auto KState = FoxUtils::ki.Attach(GUIProcess);

			auto InstAddress = FoxUtils::FindPatternImage(mouclassBase, "\xB9\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00", "x????xxx????");
			if (!FoxUtils::GoodPtr((PVOID)InstAddress))
			{
				status = STATUS_NOT_FOUND;
				goto exit;
			}

			InstAddress = RVA(InstAddress + 0x5, 7);
			if (!FoxUtils::GoodPtr((PVOID)InstAddress))
			{
				status = STATUS_NOT_FOUND;
				goto exit;
			}

			memcpy(ShellcodeBuffer, OriginalInst, sizeof(OriginalInst));
			*(PVOID*)&jmp[6] = (PBYTE)InstAddress + sizeof(OriginalInst);
			memcpy((PBYTE)ShellcodeBuffer + sizeof(OriginalInst), jmp, sizeof(jmp));
			MouseClassServiceCallbackFn = reinterpret_cast<decltype(MouseClassServiceCallbackFn)>(ShellcodeBuffer);

			exit:
			FoxUtils::ki.Detach(&KState);
			IC(ObfDereferenceObject, GUIProcess);
			if (status != STATUS_SUCCESS)
				return status;
		}
		if (!MouseDevice)
		{
			PDRIVER_OBJECT MouClassDriverObj = {};
			UNICODE_STRING DeviceName{};
			IC(RtlInitUnicodeString, &DeviceName, (L"\\Driver\\MouClass"));
			status = IC(ObReferenceObjectByName, &DeviceName, OBJ_CASE_INSENSITIVE, nullptr, 0, FoxUtils::GetIoDriverObjectType(), KernelMode, 0, (PVOID*)&MouClassDriverObj);
			if (!NT_SUCCESS(status) || !MouClassDriverObj) {
				return STATUS_NOT_IMPLEMENTED;
			}

			PDEVICE_OBJECT target_device_object = MouClassDriverObj->DeviceObject;
			while (target_device_object)
			{
				if (!target_device_object->NextDevice)
				{
					MouseDevice = target_device_object;
					break;
				}
				target_device_object = target_device_object->NextDevice;
			}

			if (!MouseDevice)
			{
				return STATUS_NOT_FOUND;
			}
		}
	}

	MOUSE_INPUT_DATA InputDataStart{};
	InputDataStart.UnitId = args->UnitId;
	InputDataStart.Flags = args->MoveFlags;
	InputDataStart.ButtonFlags = args->ButtonFlags;
	InputDataStart.LastX = args->X;
	InputDataStart.LastY = args->Y;

	BYTE* InputDataEnd = ((BYTE*)(&InputDataStart) + sizeof(InputDataStart));
	ULONG InputDataConsumed = 0;
	MouseClassServiceCallbackFn(MouseDevice, &InputDataStart, InputDataEnd, &InputDataConsumed);
	return STATUS_SUCCESS;
}
