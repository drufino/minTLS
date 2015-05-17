#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <windows.h>
#endif

// Read from /dev/urandom
void
mintls_random(
unsigned char *     data,        // (O) Random bytes
size_t const        len         // (I) Number of bytes
)
{
#ifdef _MSC_VER
	static HCRYPTPROV   hCryptProv = 0;

	if (hCryptProv == 0)
	{
		if (!CryptAcquireContextW(&hCryptProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		{
			fprintf(stderr, "Unable to acquire cryptographic context");
			exit(-1);
		}
	}

	if (!CryptGenRandom(hCryptProv, len, data))
	{
		fprintf(stderr, "FATAL ERROR: Unable to read random data");
		exit(-1);
	}
#else
    static FILE *urandom_file = NULL;
    if (urandom_file == NULL)
    {
        urandom_file = fopen("/dev/urandom","rb");
        if (urandom_file == NULL)
        {
            fprintf(stderr, "FATAL ERROR: Unable to open /dev/urandom");
            exit(-1);
        }
    }
    size_t read = fread((void *)data, 1, len, urandom_file);
    if (read < len)
    {
        fprintf(stderr, "FATAL ERROR: Failed to read random data");
        fclose(urandom_file);
        exit(-1);
    }
#endif
}