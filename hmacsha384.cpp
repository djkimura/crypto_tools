// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2  of the License, or
// (at your option) any later version.
//
// See the GNU General Public License for more details.
//*****************************************************************************
//
// Program to perform a HMACSHA384 on provided data
//
//*****************************************************************************

/**************************************************************************/
/*********************  S Y S T E M   I N C L U D E S   *******************/
/**************************************************************************/
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <climits>

#include <openssl/hmac.h>
#include <openssl/evp.h>

/**************************************************************************/
/**************************   I N C L U D E S   ***************************/
/**************************************************************************/

/**************************************************************************/
/***********************  D E F I N E S & M A C R O S  ********************/
/**************************************************************************/

/**************************************************************************/
/**************************  D A T A  T Y P E S  **************************/
/**************************************************************************/
const int hmacKeyLen = 256/8;
const int hmacResultLen = 384/8;

typedef struct ioOptionsType
{
    bool hmacKeyArg;
    bool hmacDataArg;
    uint8_t hmacKey[hmacKeyLen];
    uint8_t *hmacData;
    int hmacDataLen;
} ioOptionType;

/**************************************************************************/
/****************************  G L O B A L S  *****************************/
/**************************************************************************/

/**************************************************************************/
/******************  F U N C T I O N  P R O T O T Y P E S  ****************/
/**************************************************************************/

/**************************************************************************/
/*******************************  C O D E  ********************************/
/**************************************************************************/

/*
 * @brief   Print command line help.
 *
 * @param[in]   cmdName
 */
static void showHelp(const char *cmdName)
{
    printf("  %s - HMAC SHA384.\n", cmdName);
    printf("  Options:\n");
    printf("    -h, --help              : Print help message.\n");
    printf("        --version           : Print program version.\n");
    printf("    -k, --key               : Hex value representing the 48 byte HMAC Key.\n");
    printf("    -d, --data              : Hex value representing the data to be authenticated.\n");
    printf("  \n");
}

/*
 * @brief   Parse arguments setting the options in the ioOpt structure.
 *
 * @param[in]   argc Number of arguments passed into the program.
 * @param[in]   argv Array of C strings representing the command line arguments.
 * @param[out]  ioOpt Options to pass to the program.
 *
 * @retval  0 Success
 * @retval  1 Exit program with error
 * @retval  2 Exit program without error
 */
static int processArgs(int argc, char *argv[], ioOptionType *ioOpt)
{
    int i;

    i = 1;
    while ( i < argc )
    {
        /* Option to print help */
        if ((strcmp(argv[i], "-h") == 0) ||
            (strcmp(argv[i], "--help") == 0))
        {
            showHelp(argv[0]);
            return 2;
        }
        /* Option to print the command version */
        else if (strncmp(argv[i], "--version", 9) == 0)
        {
            printf("  VER: version=1.0\n");
            return 2;
        }
        /* Option to enter HMAC Key  */
        else if ((strcmp(argv[i], "-k") == 0) ||
                 (strcmp(argv[i], "--key") == 0))
        {
            if (((i + 1) < argc) && (argv[i+1][0] != '-'))
            {
                i++;
                if (strlen(argv[i]) != (hmacKeyLen*2))
                {
                    printf( "Error: Invalid HMAC Key parameter length\n" );
                    return 1;
                }
                for (int idx=0; idx<hmacKeyLen; idx++)
                {
                    char byteStr[3] = {0};
                    byteStr[0] = argv[i][idx*2];
                    byteStr[1] = argv[i][idx*2+1];

                    unsigned long binVal = strtoul(byteStr, NULL, 16);
                    if (binVal != ULONG_MAX)
                    {
                        ioOpt->hmacKey[idx] = static_cast<uint8_t>(binVal);
                    }
                    else
                    {
                        printf( "Error: Invalid HMAC Key parameter not Hex Value\n" );
                        return 1;
                    }

                    ioOpt->hmacKeyArg = true;
                }
            }
            else
            {
                printf( "Error: Missing HMAC Key parameter\n" );
                return 1;
            }
        }
        /* Option to enter HMAC Data  */
        else if ((strcmp(argv[i], "-d") == 0) ||
                 (strcmp(argv[i], "--data") == 0))
        {
            if (((i + 1) < argc) && (argv[i+1][0] != '-'))
            {
                i++;
                ioOpt->hmacDataLen = strlen(argv[i]) / 2;

                if (ioOpt->hmacData == NULL)
                {
                    ioOpt->hmacData = new uint8_t[ioOpt->hmacDataLen];
                }

                for (int idx=0; idx<ioOpt->hmacDataLen; idx++)
                {
                    char byteStr[3] = {0};
                    byteStr[0] = argv[i][idx*2];
                    byteStr[1] = argv[i][idx*2+1];

                    unsigned long binVal = strtoul(byteStr, NULL, 16);
                    if (binVal != ULONG_MAX)
                    {
                        ioOpt->hmacData[idx] = static_cast<uint8_t>(binVal);
                    }
                    else
                    {
                        printf( "Error: Invalid HMAC Data parameter not Hex Value\n" );
                        return 1;
                    }
                }

                ioOpt->hmacDataArg = true;
            }
            else
            {
                printf("Error: Missing HMAC Data parameter\n");
                return 1;
            }
        }
        else
        {
            printf("Unknown option: '%s'\n", argv[i]);
            return 1;
        }

        i++;
    }

    return 0;
}

/*
 * @brief   Main function to perform SHA384 HMAC on provided data
 *
 * @param[in]   argc Number of arguments passed into the program.
 * @param[in]   argv Array of C strings representing the command line arguments.
 *
 * @retval 0 Success
 * @retval 1 Exit program with error.
 */
int main(int argc, char *argv[])
{
    ioOptionsType ioOpt;
    int rc;

    unsigned int hmacSha384ResultLen = hmacResultLen;
    uint8_t hmacSha384Result[hmacResultLen];

    ioOpt.hmacKeyArg = false;
    ioOpt.hmacDataArg = false;
    ioOpt.hmacData = NULL;

    rc = processArgs(argc, argv, &ioOpt);
    if (rc == 1)
    {
        if (ioOpt.hmacData)
        {
            delete[] ioOpt.hmacData;
        }
        return EXIT_FAILURE;
    }
    if (rc == 2)
    {
        if (ioOpt.hmacData)
        {
            delete[] ioOpt.hmacData;
        }
        return EXIT_SUCCESS;
    }

    if (!ioOpt.hmacDataArg)
    {
        printf("Error HMAC Data Option Not Supplied\n");
        return EXIT_FAILURE;
    }

    if (!ioOpt.hmacKeyArg)
    {
        printf("Error HMAC Key Option Not Supplied\n");
        delete[] ioOpt.hmacData;
        return EXIT_FAILURE;
    }

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) /* OpenSSL 1.01.xx protects struct HMAC_CTX */
    /* Instantiate */
    HMAC_CTX *ctxPtr = HMAC_CTX_new();
#else
    /* Instantiate */
    HMAC_CTX ctx, *ctxPtr = &ctx;

    /* Init context */
    HMAC_CTX_init(ctxPtr);
#endif

    /* Add HMAC Key and set to use SHA384 */
    HMAC_Init_ex(ctxPtr, ioOpt.hmacKey, hmacKeyLen, EVP_sha384(), NULL);

    /* Provide HMAC data */
    HMAC_Update(ctxPtr, ioOpt.hmacData, ioOpt.hmacDataLen);

    /* Obtain result */
    HMAC_Final(ctxPtr, reinterpret_cast<unsigned char*>(&hmacSha384Result), &hmacSha384ResultLen);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) /* OpenSSL 1.01.xx protects struct HMAC_CTX */
    /* Cleanup and get message digest */
    HMAC_CTX_get_md(ctxPtr);

    /* Free */
    HMAC_CTX_free(ctxPtr);
#else
    /* Cleanup */
    HMAC_CTX_cleanup(ctxPtr);
#endif

    printf("HMACKEY=");
    for (int idx=0; idx<hmacKeyLen; idx++)
    {
        printf("%02hhx", ioOpt.hmacKey[idx]);
    }
    printf("\n");

    printf("HMACDATA=");
    for (int idx=0; idx<ioOpt.hmacDataLen; idx++)
    {
        printf("%02hhx", ioOpt.hmacData[idx]);
    }
    printf("\n");

    printf("HMACSHA384=");
    for (int idx=0; idx<hmacResultLen; idx++)
    {
        printf("%02hhx", hmacSha384Result[idx]);
    }
    printf("\n");

    delete[] ioOpt.hmacData;

    return EXIT_SUCCESS;
}
