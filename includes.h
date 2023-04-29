#pragma once
#include <ntifs.h>
#include <windef.h>
#include <cstdint>
#include <intrin.h>

inline UINT64 KrlBase = 0;
inline size_t KrlSize = 0;

#include "Utils/FoxUtils.h"
#include "Utils/HideIAT/IAT_Hide.h"