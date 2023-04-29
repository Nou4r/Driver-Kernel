#include "../includes.h"

DWORD FoxUtils::GetProcessPid(const wchar_t* name)
{
	DWORD Result = 0;
	ULONG CallBackLength = 0;
	PSYSTEM_PROCESS_INFO PSI = NULL;
	PSYSTEM_PROCESS_INFO pCurrent = NULL;
	PVOID BufferPid = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uImageNameR6;
	IC(RtlInitUnicodeString, &uImageNameR6, name);

	if (!NT_SUCCESS(IC(ZwQuerySystemInformation, SystemProcessInformation, NULL, NULL, &CallBackLength)))
	{
		BufferPid = IC(ExAllocatePoolWithTag, NonPagedPool, CallBackLength, FOX_POOLTAG);
		if (!BufferPid)
		{
			return Status;
		}

		PSI = (PSYSTEM_PROCESS_INFO)BufferPid;
		Status = IC(ZwQuerySystemInformation, SystemProcessInformation, PSI, CallBackLength, NULL);
		if (!NT_SUCCESS(Status))
		{
			IC(ExFreePoolWithTag, BufferPid, FOX_POOLTAG);
			return Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		do
		{
			if (PSI->NextEntryOffset == 0)
				break;

			if (IC(RtlEqualUnicodeString, &uImageNameR6, &PSI->ImageName, FALSE))
			{
				Result = (DWORD)PSI->ProcessId;
				Status = STATUS_SUCCESS;
				break;
			}

			PSI = (PSYSTEM_PROCESS_INFO)((unsigned char*)PSI + PSI->NextEntryOffset);

		} while (PSI->NextEntryOffset);

		// Free Allocated Memory
		IC(ExFreePoolWithTag, BufferPid, FOX_POOLTAG);
	}

	return Status == STATUS_SUCCESS ? Result : 0;
}

PEPROCESS FoxUtils::GetGUIAttachEProcess()
{
	DWORD ProcessId = GetProcessPid(L"winlogon.exe");
	if (!ProcessId)
	{
		return 0;
	}

	PEPROCESS Result = { 0 };
	if (!NT_SUCCESS(IC(PsLookupProcessByProcessId, (HANDLE)ProcessId, &Result)) || !Result)
	{
		return 0;
	}

	return Result;
}

UINT64 FoxUtils::GetKernelModule(const char* Name, size_t* SizeOut)
{
	UINT64 ResultBase = 0;
	UINT64 ResultSize = 0;

	DWORD size = 0x0;
	IC(ZwQuerySystemInformation, (0xB), nullptr, size, reinterpret_cast<PULONG>(&size));

	auto listHeader = IC(ExAllocatePoolWithTag, NonPagedPool, size, FOX_POOLTAG);
	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;

	if (const auto status = IC(ZwQuerySystemInformation, (0xB), listHeader, size, reinterpret_cast<PULONG>(&size))) {
		IC(ExFreePoolWithTag, listHeader, FOX_POOLTAG);
		return status;
	}

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Modules;
	for (size_t i = 0; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->NumberOfModules; ++i, ++currentModule) {
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (IC(strcmp, LowerStr((PCHAR)currentModuleName), LowerStr((PCHAR)Name)) == 0) {
			ResultBase = reinterpret_cast<uintptr_t>(currentModule->ImageBase);
			ResultSize = currentModule->ImageSize;
			break;
		}
	}
	IC(ExFreePoolWithTag, listHeader, FOX_POOLTAG);
	if (SizeOut)
		*SizeOut = ResultSize;

	return ResultBase;
}

POBJECT_TYPE FoxUtils::GetIoDriverObjectType()
{
	static POBJECT_TYPE* IoDriverObjectTypeAddr = 0;
	if (!IoDriverObjectTypeAddr)
		IoDriverObjectTypeAddr = (POBJECT_TYPE*)FoxUtils::EncryptPtr(FoxUtils::pe::GetProcAdress(KrlBase, ("IoDriverObjectType")));

	return *FoxUtils::EncryptPtr(IoDriverObjectTypeAddr);
}

inline bool CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}
	return TRUE;
}

UINT64 FindPattern(UINT64 base_, DWORD length, PCHAR pattern, PCHAR mask)
{
	auto base = reinterpret_cast<char*>(base_);
	length -= (DWORD)IC(strlen, mask);
	for (DWORD i = 0; i <= length; ++i) {
		auto addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return reinterpret_cast<UINT64>(addr);
		}
	}
	return 0;
}

UINT64 FoxUtils::FindPatternImage(UINT64 Base, const char* Pattern, const char* Mask)
{
	if (!Base)
		return 0;

	UINT64 match = 0;
	auto headers = pe::GetImageNtHeaders(Base);
	IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER* section = &sections[i];
		if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, (".text"), 5) == 0) {
			match = FindPattern(Base + section->VirtualAddress, section->Misc.VirtualSize, (char*)Pattern, (char*)Mask);
			if (match) {
				break;
			}
		}
	}
	return match;
}

NTSTATUS FoxUtils::GetDriverObject(const wchar_t* object_name, DRIVER_OBJECT** driver_object)
{
	auto status = STATUS_SUCCESS;
	if (!object_name)
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	if (!driver_object)
	{
		return STATUS_INVALID_PARAMETER_2;
	}

	UNICODE_STRING device_name = { };
	IC(RtlInitUnicodeString, &device_name, object_name);

	FILE_OBJECT* file_object = nullptr;
	DEVICE_OBJECT* device_object = nullptr;

	status = IC(IoGetDeviceObjectPointer, &device_name, FILE_READ_DATA, &file_object, &device_object);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (!device_object)
	{
		return STATUS_INVALID_ADDRESS;
	}
	*driver_object = device_object->DriverObject;
	if (!(*driver_object))
	{
		return STATUS_INVALID_ADDRESS;
	}
	return status;
}

bool FoxUtils::GoodPtr(PVOID ptr)
{
	return ptr && IC(MmIsAddressValid, ptr);
}

bool FoxUtils::SafeCopy(PVOID dest, PVOID src, SIZE_T size)
{
	memcpy(dest, src, size);
	return true;
}

IMAGE_NT_HEADERS* FoxUtils::pe::GetImageNtHeaders(UINT64 image)
{
	const auto image_dos_header = GetImageDosHeader(image);
	if (!image_dos_header)
	{
		return 0;
	}
	auto image_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(image + image_dos_header->e_lfanew);
	if (image_nt_headers->Signature != ImageNtSignature)
	{
		return 0;
	}
	return image_nt_headers;
}

UINT64 FoxUtils::pe::GetProcAdress(UINT64 ModBase, const char* Name)
{
	if (!ModBase)
		return 0;

	auto* NT_Head = GetImageNtHeaders((uintptr_t)ModBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((UINT64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

	for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
	{
		USHORT Ordinal = ((USHORT*)((UINT64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

		if (StrICmp(Name, ExpName, true))
			return (ModBase + ((ULONG*)(ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
	}
	return 0;
}

bool FoxUtils::KIStackProcess::InitKiStackUtils(UINT64 KrlBase_)
{
	if (!KrlBase_)
		return false;

	auto GUIProcess = FoxUtils::GetGUIAttachEProcess();
	if (!GUIProcess)
		return false;

	bool FoundAllKFunction = false;
	KAPC_STATE state;
	IC(KeStackAttachProcess, GUIProcess, &state);
	UINT64 ScanResult = 0;

	ScanResult = FindPatternImage(KrlBase_, ("\xE8\x00\x00\x00\x00\x44\x8A\xED"), ("x????xxx"));
	if (!ScanResult || !IC(MmIsAddressValid, (PVOID)ScanResult))
	{
		goto exit;
	}
	ScanResult = RVA(ScanResult, 5);
	if (!ScanResult || !IC(MmIsAddressValid, (PVOID)ScanResult))
	{
		goto exit;
	}
	*(UINT64*)&KiStackAttachProcess = ScanResult;
	ScanResult = 0;

	ScanResult = FindPatternImage(KrlBase_, ("\xE8\x00\x00\x00\x00\x89\x5F\x08\xE9\x00\x00\x00\x00"), ("x????xxxx????"));
	if (!ScanResult || !IC(MmIsAddressValid, (PVOID)ScanResult))
	{
		goto exit;
	}
	ScanResult = RVA(ScanResult, 5);
	if (!ScanResult || !IC(MmIsAddressValid, (PVOID)ScanResult))
	{
		goto exit;
	}
	*(UINT64*)&KiUnstackDetachProcess = ScanResult;
	FoundAllKFunction = true;
exit:
	IC(KeUnstackDetachProcess, &state);
	IC(ObfDereferenceObject, GUIProcess);
	return FoundAllKFunction;
}

KAPC_STATE FoxUtils::KIStackProcess::Attach(PEPROCESS TargetProc)
{
	KAPC_STATE state;
	KiStackAttachProcess(TargetProc, 1, &state);
	return state;
}

void FoxUtils::KIStackProcess::Detach(KAPC_STATE* kState)
{
	KiUnstackDetachProcess(kState, 1);
}

bool FoxUtils::secure::null_pfn(PMDL mdl)
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages) {
		return false;
	}

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));
	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		IC(MmCopyMemory, &mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	return true;
}
