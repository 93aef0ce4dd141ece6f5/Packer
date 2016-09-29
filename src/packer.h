#include "rc4.h"

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

void rc4_setup(struct rc4_state *s, unsigned char *key, int length);
void rc4_crypt(struct rc4_state *s, unsigned char *data, int length);