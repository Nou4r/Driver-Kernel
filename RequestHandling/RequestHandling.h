#pragma once
#include <ntifs.h>
#include <windef.h>

namespace RequestHandling
{
	constexpr UINT64 ReqMagicKey = 0x9345897347583745;
	enum class RequestTypes
	{
		ReqDrvHandShake,
		ReqModuleBasicInfo,
		ReqMemcpy,
		ReqKernelMouseInput
	};

	typedef struct RequestBuild 
	{
		RequestTypes ReqType;
		void* args;
		UINT64 MagicKey;
		NTSTATUS* ResultStatus;
	};

	typedef struct DataModule 
	{
		DWORD proc_id;
		WCHAR module_name[155];
		PVOID dest;
		PDWORD size;
	}*pDataModule;

	typedef struct DataMemcopy 
	{
		DWORD proc_id;
		PVOID src;
		PVOID dest;
		SIZE_T size;
		BYTE bWrite;
	}*pDataMemcopy;

	enum MouseButtonFlags : SHORT {
		NONE = 0x0000,
		LEFT_BUTTON_DOWN = 0x0001,
		LEFT_BUTTON_UP = 0x0002,
		RIGHT_BUTTON_DOWN = 0x0004,
		RIGHT_BUTTON_UP = 0x0008,
	};
	enum MouseMoveFlags : SHORT {
		MOVE_RELATIVE = 0,
		MOVE_ABSOLUTE = 1,
		VIRTUAL_DESKTOP = 2,
		MOVE_NOCOALESCE = 8,
	};
	typedef struct DataKernelMouseInput
	{
		int X, Y;
		MouseButtonFlags ButtonFlags;
		MouseMoveFlags MoveFlags;
		SHORT UnitId;
	}*pDataKernelMouseInput;

	NTSTATUS HandleModule(pDataModule args);
	NTSTATUS HandleMemcopy(pDataMemcopy args);
	NTSTATUS HandleKernelMouseInput(pDataKernelMouseInput args);
}