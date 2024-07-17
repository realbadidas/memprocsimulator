#pragma once
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <unordered_map>

typedef unsigned __int64                    QWORD, * PQWORD;

#define VMMDLL_PID_PROCESS_WITH_KERNELMEMORY        0x80000000      // Combine with dwPID to enable process kernel memory (NB! use with extreme care).
#define VMMDLL_FLAG_NOCACHE                         0x0001  // do not use the data cache (force reading from memory acquisition device)
#define VMMDLL_FLAG_ZEROPAD_ON_FAIL                 0x0002  // zero pad failed physical memory reads and report success if read within range of physical memory.
#define VMMDLL_FLAG_FORCECACHE_READ                 0x0008  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
#define VMMDLL_FLAG_NOPAGING                        0x0010  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
#define VMMDLL_FLAG_NOPAGING_IO                     0x0020  // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
#define VMMDLL_FLAG_NOCACHEPUT                      0x0100  // do not write back to the data cache upon successful read from memory acquisition device.
#define VMMDLL_FLAG_CACHE_RECENT_ONLY               0x0200  // only fetch from the most recent active cache region when reading.
#define VMMDLL_FLAG_NO_PREDICTIVE_READ              0x0400  // do not perform additional predictive page reads (default on smaller requests).
#define VMMDLL_FLAG_FORCECACHE_READ_DISABLE         0x0800  // disable/override any use of VMM_FLAG_FORCECACHE_READ. only recommended for local files. improves forensic artifact order.




typedef struct tdVMM_HANDLE {
	bool active = true;
	bool print = false;


	HANDLE handleToPid = 0;
	unsigned int lastPid = 0;


	~tdVMM_HANDLE() {
		CloseHandle(handleToPid);
	}
} * VMM_HANDLE;

struct ScatterRead_dontuse {
	QWORD addr = 0;
	DWORD size = 0;
	PBYTE out = 0;
	PDWORD pcbRead = 0;

};

typedef struct tdVMM_SCATTER_HANDLE {
	VMM_HANDLE hVMM = 0;
	bool active = true;
	DWORD dwPID = 0;
	DWORD flags = 0;
	std::unordered_map<QWORD, ScatterRead_dontuse> scatterMap;
	std::unordered_map<QWORD, PBYTE> scatterResults;

} * VMMDLL_SCATTER_HANDLE;





inline VMM_HANDLE VMMDLL_Initialize(DWORD argc, LPSTR argv[]) {
	VMM_HANDLE ret = new tdVMM_HANDLE{};

	for (int i = 0; i < argc; i++) {
		const char* arg = argv[i];

		if (arg == "-printf") {
			ret->print = true;
		}
	}
	return ret;
}

inline void VMMDLL_Close(VMM_HANDLE handle) {
	delete handle;
	handle = 0;
}

inline VMMDLL_SCATTER_HANDLE VMMDLL_Scatter_Initialize(VMM_HANDLE hVMM, DWORD dwPID, DWORD flags) {
	VMMDLL_SCATTER_HANDLE ret = new tdVMM_SCATTER_HANDLE{};
	ret->hVMM = hVMM;
	ret->dwPID = dwPID;
	ret->flags = flags;
	return ret;

}

inline void VMMDLL_Scatter_CloseHandle(VMMDLL_SCATTER_HANDLE handle) {
	delete handle;
	handle = 0;
}

inline BOOL VMMDLL_PidGetFromName(VMM_HANDLE hVMM, LPSTR szProcName, PDWORD pdwPID) {
	if (hVMM == nullptr) {
		std::cerr << "VMMDLL_PidGetFromName called with invalid handle." << std::endl;
		return false;
	}

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (strcmp(entry.szExeFile, szProcName) == 0) {
				CloseHandle(snapshot);
				*pdwPID = entry.th32ProcessID;
				return true;
			}
		}
	}

	CloseHandle(snapshot);
	return false;


}

inline ULONG64 VMMDLL_ProcessGetModuleBaseU(VMM_HANDLE hVMM, DWORD dwPID, LPSTR uszModuleName) {
	if (hVMM == nullptr) {
		std::cerr << "VMMDLL_ProcessGetModuleBaseU called with invalid handle." << std::endl;
		return 0;
	}


	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return 0;
	}

	do {
		std::cout << me32.szModule << std::endl;
		if (strcmp(me32.szModule, uszModuleName) == 0) {
			LPVOID baseAddr = me32.modBaseAddr;

			CloseHandle(hModuleSnap);
			if (!baseAddr)
				return 0;
			else
				return (ULONG64)baseAddr;
		}
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return 0;

}

inline HANDLE getHandleFromPid_dontuse(DWORD dwPID) {
	DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE;

	HANDLE hProcess = OpenProcess(access, FALSE, dwPID);
	if (hProcess == NULL) {
		return 0;
	}

	return hProcess;

}

inline HANDLE getHandleFromVMMHandle_dontuse(VMM_HANDLE hVMM, DWORD dwPID) {
	if (hVMM->lastPid != dwPID || hVMM->handleToPid == 0) {
		HANDLE handle = getHandleFromPid_dontuse(dwPID);
		if (handle == 0)
			return 0;

		hVMM->lastPid = dwPID;
		hVMM->handleToPid = handle;
	}
	return hVMM->handleToPid;
}

inline BOOL VMMDLL_MemReadEx(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb, PDWORD pcbReadOpt, ULONG64 flags) {
	if (hVMM == nullptr) {
		std::cerr << "VMMDLL_MemReadEx called with invalid handle." << std::endl;
		return false;
	}

	HANDLE handle = getHandleFromVMMHandle_dontuse(hVMM, dwPID);

	return ReadProcessMemory(handle, (LPCVOID)qwA, pb, cb, (SIZE_T*)pcbReadOpt);

}

inline BOOL VMMDLL_MemWrite(VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA, PBYTE pb, DWORD cb) {
	if (hVMM == nullptr) {
		std::cerr << "VMMDLL_MemWrite called with invalid handle." << std::endl;
		return false;
	}

	HANDLE handle = getHandleFromVMMHandle_dontuse(hVMM, dwPID);

	return WriteProcessMemory(handle, (LPVOID)qwA, pb, cb, NULL);
}

inline BOOL VMMDLL_Scatter_PrepareEx(VMMDLL_SCATTER_HANDLE hS, QWORD va, DWORD cb, PBYTE pb, PDWORD pcbRead) {
	if (hS == nullptr) {
		std::cerr << "VMMDLL_Scatter_PrepareEx called with invalid handle." << std::endl;
		return false;
	}

	ScatterRead_dontuse sr;
	sr.addr = va;
	sr.size = cb;
	sr.out = pb;
	sr.pcbRead = pcbRead;

	hS->scatterMap[sr.addr] = sr;

	return true;

}

inline BOOL VMMDLL_Scatter_Prepare(VMMDLL_SCATTER_HANDLE hS, QWORD va, DWORD cb) {
	if (hS == nullptr) {
		std::cerr << "VMMDLL_Scatter_Prepare called with invalid handle." << std::endl;
		return false;
	}

	ScatterRead_dontuse sr;
	sr.addr = va;
	sr.size = cb;

	hS->scatterMap[sr.addr] = sr;

	return true;
}

inline BOOL VMMDLL_Scatter_ExecuteRead(VMMDLL_SCATTER_HANDLE hS) {
	if (hS == nullptr) {
		std::cerr << "VMMDLL_Scatter_ExecuteRead called with invalid handle." << std::endl;
		return false;
	}
	HANDLE h = getHandleFromVMMHandle_dontuse(hS->hVMM, hS->dwPID);

	BOOL ret = true;

	for (auto& it : hS->scatterMap) {
		ScatterRead_dontuse sr = it.second;

		if (sr.out != 0)
			ret &= ReadProcessMemory(h, (LPCVOID)sr.addr, sr.out, sr.size, (SIZE_T*)sr.pcbRead);
		else ret = false;
		//TODO add normal scatter reads aswell and not only prepareex
	}

	return ret;
}


inline BOOL VMMDLL_Scatter_Execute(VMMDLL_SCATTER_HANDLE hS) {
	return VMMDLL_Scatter_ExecuteRead(hS);
}


inline BOOL VMMDLL_Scatter_Clear(VMMDLL_SCATTER_HANDLE hS, DWORD dwPID, DWORD flags) {
	if (hS == nullptr) {
		std::cerr << "VMMDLL_Scatter_Clear called with invalid handle." << std::endl;
		return false;
	}

	hS->dwPID = dwPID;
	hS->scatterResults.clear();
	hS->scatterMap.clear();

	return true;
}
