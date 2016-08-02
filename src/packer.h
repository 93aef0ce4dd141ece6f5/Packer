#define BUFFER_RSRC_ID 10
#define FILE_SIZE_RSRC_ID 20
#define KEY_RSRC_ID 30

#define KEY_LEN 128

typedef struct _FileStruct {
	PBYTE pBuffer;
	DWORD dwBufSize;
	DWORD dwFileSize;
	PBYTE pKey;
} FileStruct, *pFileStruct;