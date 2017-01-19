#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <errno.h>

#define BYTES_TO_HASH 440

BOOL calcMD5(byte* data, LPSTR md5)
{
	HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
		printf("ERROR: Couldn't acquire crypto context!\n");
		return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
		CryptReleaseContext(hProv, 0);
        printf("ERROR: Couldn't create crypto stream!\n");
		return FALSE;
    }

    if (!CryptHashData(hHash, data, BYTES_TO_HASH, 0))
    {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
		printf("ERROR: CryptHashData failed!\n");
		return FALSE;
    }
    
    cbHash = 16;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
		for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf(md5 + (i*2), "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        }
		
		CryptDestroyHash(hHash);
  		CryptReleaseContext(hProv, 0);
		return TRUE;
    }
    else
    {
        printf("ERROR: CryptHashData failed!\n");
		CryptDestroyHash(hHash);
  		CryptReleaseContext(hProv, 0);
		return FALSE;
    }
}

void dumpMBR(char *drive, BOOL reportNoDrive)
{
	HANDLE hDrive = NULL;

	hDrive = CreateFile(drive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	if (hDrive == INVALID_HANDLE_VALUE)
	{
		if (reportNoDrive)
		{
			printf("ERROR: Could not open '%s'!\n", drive);
		}
		return;
	}

	printf("Drv: %s\n", drive);

	DWORD offset = SetFilePointer(hDrive, 0, NULL, FILE_BEGIN);
	if(offset == INVALID_SET_FILE_POINTER)
	{
		printf("ERROR: SetFilePointer(%u)\n", GetLastError());
		CloseHandle(hDrive);
		return;
	}

	BYTE buff[512];
	DWORD bytesRead;
	if(!ReadFile(hDrive, buff, 512, &bytesRead, NULL))
	{
		printf("ERROR: ReadFile(%u)\n", GetLastError());
		CloseHandle(hDrive);
		return;
	}

	CloseHandle(hDrive);

	for (int i=0; i<4; i++)
	{
		printf("PE%d: ", i+1);
		for (int j=0; j<16; j++)
		{
			printf("%02x ", buff[446+(i*16+j)]);
		}
		printf("\n");
	}
	printf("Sig: %02x%02x\n", buff[510], buff[511]);

	char md5[32];
	if(calcMD5(buff, md5))
	{
		printf("MD5: %s\n", md5);

		char outFile[37];
		memcpy(outFile, md5, sizeof(md5));
		memcpy(outFile + (sizeof(wchar_t) * 16), ".bin", sizeof(wchar_t) * 5);

		FILE *hOutFile = fopen(outFile, "wb");
		if(!hOutFile)
		{
			printf("Couldn't open '%s' for writing!", outFile);
		}
		else
		{
			printf("Dmp: %s\n", outFile);
			size_t written = fwrite(buff, 1, BYTES_TO_HASH, hOutFile);
			if (written != BYTES_TO_HASH)
			{
				printf("ERROR: Only wrote %llu of %d bytes to file!\n", written, BYTES_TO_HASH);
			}
			fclose(hOutFile);
		}
	}
	else
	{
		printf("MD5 calculation failed.\n");
	}
}

int main(int argc, char *argv[])
{
	char drive[20];

	if (argc > 1)
	{
		for(int i=1; i<argc; i++)
		{
			errno = 0;
			char *r = NULL;
			int d = strtol(argv[i], &r, 0);
			if (errno != 0 || r == argv[i] || r-argv[i] != strlen(argv[i]))
			{
				printf("'%s' is an invalid drive number - ignored\n", argv[i]);
			}
			else
			{				
				sprintf(drive, "\\\\.\\PhysicalDrive%d", d);
				dumpMBR(drive, TRUE);
			}
		}
	}
	else
	{
		for (int i=0; i<16; i++)
		{
			sprintf(drive, "\\\\.\\PhysicalDrive%d", i);
			dumpMBR(drive, FALSE);
		}
	}

	return 0;
}
