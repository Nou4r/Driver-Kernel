#pragma once
#define ImpSet(a) a##Fn = (a##Def)FoxUtils::EncryptPtr(FoxUtils::pe::GetProcAdress(KrlBase, (#a)));
#define ImpDef(a) using a##Def = decltype(&a); inline a##Def a##Fn = nullptr;
#define IC(a, ...) ((a##Def)FoxUtils::EncryptPtr(a##Fn))(__VA_ARGS__)	

ImpDef(MmIsAddressValid);
ImpDef(RtlInitUnicodeString);
ImpDef(ZwQuerySystemInformation);
ImpDef(ExAllocatePoolWithTag);
ImpDef(ExFreePoolWithTag);
ImpDef(RtlEqualUnicodeString);
ImpDef(PsLookupProcessByProcessId);
ImpDef(strcmp);
ImpDef(strlen);
ImpDef(IoGetDeviceObjectPointer);
ImpDef(KeStackAttachProcess);
ImpDef(KeUnstackDetachProcess);
ImpDef(ObfDereferenceObject);
ImpDef(MmCopyMemory);
ImpDef(DbgPrintEx);
ImpDef(ZwSetSystemInformation);
ImpDef(PsGetProcessPeb);
ImpDef(RtlCompareUnicodeString);
ImpDef(IoGetCurrentProcess);
ImpDef(MmCopyVirtualMemory);
ImpDef(ObReferenceObjectByName);
