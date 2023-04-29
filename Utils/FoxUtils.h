#pragma once
#include "../TypesStructs/NtDefaults.h"
#define FOX_POOLTAG 'FOXX'
#define cToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define RVA(addr, size) ((uintptr_t)((uintptr_t)(addr) + *(PINT)((uintptr_t)(addr) + ((size) - sizeof(INT))) + (size)))

#define log(fmt, ...) IC(DbgPrintEx, (ULONG)0, (ULONG)0, fmt, ##__VA_ARGS__)

#define IMAGE_FIRST_SECTION( ImageNtHeaders )																						\
	( ( IMAGE_SECTION_HEADER* )( uintptr_t( ImageNtHeaders ) +	\
		FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +									\
		( ( ImageNtHeaders ) )->FileHeader.SizeOfOptionalHeader ) )
#define NT_HEADER(ModBase) (PIMAGE_NT_HEADERS)((ULONG64)(ModBase) + ((PIMAGE_DOS_HEADER)(ModBase))->e_lfanew)


extern "C"
{
	NTSTATUS NTAPI ZwSetSystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);
	NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
	NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection);
	NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	PEB* NTAPI PsGetProcessPeb(IN PEPROCESS Process);

	NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectPath, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* ObjectPtr);
};

namespace FoxUtils
{
	namespace direct_assembly
	{
		extern "C"
		{
			UINT64 GetKernelBase();
		}
	}

	DWORD GetProcessPid(const wchar_t* name);
	PEPROCESS GetGUIAttachEProcess();
	UINT64 GetKernelModule(const char* Name, size_t* SizeOut);
	POBJECT_TYPE GetIoDriverObjectType();

	UINT64 FindPatternImage(UINT64 Base, const char* Pattern, const char* Mask);

	NTSTATUS GetDriverObject(const wchar_t* object_name, DRIVER_OBJECT** driver_object);
	bool GoodPtr(PVOID ptr);
	bool SafeCopy(PVOID dest, PVOID src, SIZE_T size);

	template <typename Type>
	__forceinline Type EncryptPtr(Type Ptr) {
		return (Type)((UINT64)Ptr ^ (UINT64)(SharedUserData->Cookie));
	}

	template <typename StrType, typename StrType2>
	__forceinline bool StrICmp(StrType Str, StrType2 InStr, bool Two)
	{
		if (!Str || !InStr)
			return false;

		wchar_t c1, c2; do {
			c1 = *Str++; c2 = *InStr++;
			c1 = cToLower(c1); c2 = cToLower(c2);
			if (!c1 && (Two ? !c2 : 1))
				return true;
		} while (c1 == c2);

		return false;
	}

	__forceinline PCHAR LowerStr(PCHAR str) {
		for (PCHAR s = str; *s; ++s) {
			*s = (CHAR)cToLower(*s);
		}
		return str;
	}

	class KIStackProcess
	{
	public:
		bool InitKiStackUtils(UINT64 KrlBase_);

		KAPC_STATE Attach(PEPROCESS TargetProc);
		void Detach(KAPC_STATE* kState);

	private:
		char(__fastcall* KiStackAttachProcess)(_KPROCESS* khprocess, int allways_1, PRKAPC_STATE kapc_state) = nullptr;
		__int64(__fastcall* KiUnstackDetachProcess)(PRKAPC_STATE kapc_state, int allways_1) = nullptr;
	};
	inline KIStackProcess ki{};

	namespace pe
	{
		IMAGE_NT_HEADERS* GetImageNtHeaders(UINT64 image);
		UINT64 GetProcAdress(UINT64 ModBase, const char* Name);

		inline const IMAGE_DOS_HEADER* GetImageDosHeader(UINT64 image)
		{
			if (!image)
			{
				return 0;
			}
			const auto image_dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
			if (image_dos_header->e_magic != ImageDosSignature)
			{
				return 0;
			}
			return image_dos_header;
		}

		inline const size_t GetSizeOfModule(UINT64 Base)
		{
			auto headers = GetImageNtHeaders(Base);
			if (headers)
				return headers->OptionalHeader.SizeOfImage;
			return 0;
		}
	}
	namespace secure
	{
		bool null_pfn(PMDL mdl);
	}
}