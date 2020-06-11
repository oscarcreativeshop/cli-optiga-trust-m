/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

const uint8_t optiga_platform_binding_shared_secret [] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40
};


static uint8_t label [] = "Firmware update";

/**
 * Preshared Secret metadata
 */
static uint8_t metadata [] = {
    //Metadata tag in the data object
    0x20, 0x06,
        //Data object type set to PRESSEC
        0xE8, 0x01, 0x21,
        0xD3, 0x01, 0x00,
};

typedef struct _OPTFLAG {
    uint16_t    derive      : 1;
    uint16_t    seed        : 1;
    uint16_t    secret      : 1;
    uint16_t    outfile     : 1;
    uint16_t    bypass      : 1;
    uint16_t    dummy5      : 1;
    uint16_t    dummy6      : 1;
    uint16_t    dummy7      : 1;
    uint16_t    dummy8      : 1;
    uint16_t    dummy9      : 1;
    uint16_t    dummy10     : 1;
    uint16_t    dummy11     : 1;
    uint16_t    dummy12     : 1;
    uint16_t    dummy13     : 1;
    uint16_t    dummy14     : 1;
    uint16_t    dummy15     : 1;
}OPTFLAG;

union _uOptFlag {
    OPTFLAG    flags;
    uint16_t    all;
} uOptFlag;

static void _helpmenu(void)
{
    printf("\nHelp menu: trustm_derive_secret <option> ...<option>\n");
    printf("option:- \n");
    printf("-d <OID>         : Derive secret OID 0xNNNN \n");
    printf("-s <random-seed> : Input file random seed\n");
    printf("-k <secret>      : Input file global secret\n");
    printf("-o <filename>    : Output derived secret \n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h               : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    uint16_t offset = 0;
    uint32_t bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[2048];
    uint8_t mode = OPTIGA_UTIL_ERASE_AND_WRITE;
    uint8_t skip_flag;
    FILE *fp = NULL;

    uint8_t seed_buff[100] = {};
    uint8_t seed_len = 0;
    uint8_t secret_buff[100] = {};
    uint8_t secret_len = 0;
    uint8_t derive_buf[100] = {};
    uint8_t derive_len = 0;
    uint8_t derive_key_buff[100] = {};
    uint8_t derive_key_len = 32;
 
    char *outFile = NULL;
    char *rand_seed = NULL;
    char *global_secret = NULL;

 
    int option = 0;                    // Command line option.

/***************************************************************
 * Getting Input from CLI
 **************************************************************/
    uOptFlag.all = 0;
    printf("\n");
    do // Begin of DO WHILE(FALSE) for error handling.
    {
        
// ---------- Check for command line parameters ----------
        if (argc < 2)
        {
            _helpmenu();
            exit(0);
        }

 // ---------- Command line parsing with getopt ----------
        opterr = 0; // Disable getopt error messages in case of unknown parameters

// Loop through parameters with getopt.
        while (-1 != (option = getopt(argc, argv, "d:s:k:o:Xh")))
        {
            switch (option)
            {
                case 'd': // Derive OID
                    uOptFlag.flags.derive = 1;
                    optiga_oid = trustmHexorDec(optarg);                 
                    break;
                case 's': // Global Secret
                    uOptFlag.flags.seed = 1;    
                    rand_seed = optarg;  
                                                      
                    break;
                case 'k': // Input filename
                    uOptFlag.flags.secret = 1;
                    global_secret = optarg;    
                    break;
                case 'o': // output filename
                    uOptFlag.flags.outfile = 1;
                    outFile = optarg;                 
                    break; 
                case 'X': // Bypass Shielded Communication
                    uOptFlag.flags.bypass = 1;
                    printf("Bypass Shielded Communication. \n");
                    break;                            
                case 'h': // Print Help Menu
                default:  // Any other command Print Help Menu
                    _helpmenu();
                    exit(0);
                    break;
            }
        }
     }while(0);

/***************************************************************
 * Example 
 **************************************************************/
    do{
	if((uOptFlag.flags.seed != 1) && (uOptFlag.flags.secret != 1))
	{
	 printf("-s <Random Seed> and -k <global secret> are required\n");
	 exit(1);
	}
    
	//Reading Binary File
	fp = fopen((const char *)rand_seed, "rb");
	if(!fp)
	{
	 printf("error opening file %s\n", rand_seed); 
	}

	
	fseek(fp, 0, SEEK_END);
	seed_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fread(seed_buff,1,seed_len,fp);


	fclose(fp);

	//Reading Binary File
	fp = fopen((const char *)global_secret, "rb");
	if(!fp)
	{
	 printf("error opening file %s\n", global_secret); 
	}


	fseek(fp, 0, SEEK_END);
	secret_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fread(secret_buff,1,secret_len,fp);

	fclose(fp);

	return_status = trustm_Open();
	if (return_status != OPTIGA_LIB_SUCCESS)
	exit(1);

	printf("========================================================\n");    

	skip_flag = 0;
	switch (optiga_oid)
	{         
	case 0xF1D0:
	case 0xF1D1:
	case 0xF1D2:
	case 0xF1D3:
	case 0xF1D4:
	case 0xF1D5:
	case 0xF1D6:
	case 0xF1D7:
	case 0xF1D8:
	case 0xF1D9:
	case 0xF1DA:
	case 0xF1DB:
	    printf("App DataStrucObj type 1     [0x%.4X] ", optiga_oid);
	    skip_flag = 1;
	    break;                                           
	default:
	    printf("Only arbitrary Objctes 0xF1D0 - 0xF1DB are set to be used for Key-Derivation\n");
	    skip_flag = 2;
	    break;
	}

	printf("\nWriting Platform Binding Secret\n");
        printf("\nTHIS IS DONE DURING ONBORDING AT FAB AND LOCKED\n");
        optiga_lib_status = OPTIGA_LIB_BUSY;
	return_status = optiga_util_write_data(me_util,
		                            0xe140,
		                            mode,
		                            offset,
		                            optiga_platform_binding_shared_secret,
		                            sizeof(optiga_platform_binding_shared_secret));
	if (OPTIGA_LIB_SUCCESS != return_status)
	 break;
	//Wait until the optiga_util_read_metadata operation is completed
	while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
	return_status = optiga_lib_status;
	if (return_status != OPTIGA_LIB_SUCCESS)
	 break;
	else
	{
         trustmHexDump(optiga_platform_binding_shared_secret,sizeof(optiga_platform_binding_shared_secret));
	 printf("success\n");
        }

	printf("Global Secret\n");
	trustmHexDump(secret_buff,secret_len);

	if(uOptFlag.flags.bypass != 1)
	{
	 // OPTIGA Comms Shielded connection settings to enable the protection
	 OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
	 OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION|OPTIGA_COMMS_RE_ESTABLISH);
	}

	optiga_lib_status = OPTIGA_LIB_BUSY;
	return_status = optiga_util_write_data(me_util,
		                            optiga_oid,
		                            mode,
		                            offset,
		                            secret_buff,
		                            secret_len);
	if (OPTIGA_LIB_SUCCESS != return_status)
	 break;
	//Wait until the optiga_util_read_metadata operation is completed
	while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
	return_status = optiga_lib_status;
	if (return_status != OPTIGA_LIB_SUCCESS)
	 break;
	else
	printf("Write Secret Success.\n");


	if(uOptFlag.flags.bypass != 1)
    	{
         // OPTIGA Comms Shielded connection settings to enable the protection
         OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
         OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION|OPTIGA_COMMS_RE_ESTABLISH);
    	}

    	optiga_lib_status = OPTIGA_LIB_BUSY;
    	return_status = optiga_util_write_metadata(me_util,
                                                optiga_oid,
                                                metadata,
                                                sizeof(metadata));
    	if (OPTIGA_LIB_SUCCESS != return_status)
	 break;
    	//Wait until the optiga_util_read_metadata operation is completed
    	while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
    	return_status = optiga_lib_status;
    	if (return_status != OPTIGA_LIB_SUCCESS)
	 break;
    	else
	 printf("Set Object Type to PRESSEC: Success.\n");


        if(uOptFlag.flags.bypass != 1)
    	{
         // OPTIGA Comms Shielded connection settings to enable the protection
         OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
         OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION|OPTIGA_COMMS_RE_ESTABLISH);
    	}
	 printf("Derive Key Compute\n");
         printf("Random Seed:\n");
	 trustmHexDump(seed_buff, seed_len);

    	optiga_lib_status = OPTIGA_LIB_BUSY;
	return_status = optiga_crypt_tls_prf_sha256(me_crypt,
                                                    optiga_oid, /* Input secret OID */
                                                    label,
                                                    sizeof(label),
                                                    seed_buff,
                                                    seed_len,
                                                    derive_key_len,
                                                    TRUE,
                                                    derive_key_buff);
        if (OPTIGA_LIB_SUCCESS != return_status)
	 break;
    	//Wait until the optiga_util_read_metadata operation is completed
    	while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
    	return_status = optiga_lib_status;
    	if (return_status != OPTIGA_LIB_SUCCESS)
	 break;
    	else
        {    
	 printf("Derive Key:\n");
	 trustmHexDump(derive_key_buff, derive_key_len);
         
        }  

	
	}while(0);

 	// Capture OPTIGA Trust M error
    	if (return_status != OPTIGA_LIB_SUCCESS)
         trustmPrintErrorCode(return_status);

	printf("\n");
	printf("========================================================\n");
	trustm_Close();
    return 0;
}

