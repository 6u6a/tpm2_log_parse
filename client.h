#include <string.h>
#include<stdio.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>


#include "tss2/tss.h"
#include "tss2/tssutils.h"
#include "tss2/tssfile.h"
#include "tss2/tssresponsecode.h"
#include "tss2/tssprint.h"
#include "tss2/tssmarshal.h"
#include "tss2/Unmarshal_fp.h"

#define TCG_EVENT_LEN_MAX	4096

typedef struct tdTCG_PCR_EVENT2 {
    uint32_t 		pcrIndex;
    uint32_t 		eventType;
    TPML_DIGEST_VALUES	digests;
    uint32_t 		eventSize; 
    uint8_t 		event[TCG_EVENT_LEN_MAX];				
} TCG_PCR_EVENT2;

typedef struct tdTCG_PCR_EVENT {
    uint32_t pcrIndex;
    uint32_t eventType;	
    uint8_t digest[SHA1_DIGEST_SIZE];
    uint32_t eventDataSize;
    uint8_t event[TCG_EVENT_LEN_MAX];				
} TCG_PCR_EVENT;

int TSS_EVENT_Line_Read(TCG_PCR_EVENT *event,
			int *endOfFile,
			FILE *inFile);


int TSS_EVENT2_Line_Read(TCG_PCR_EVENT2 *event2,
			 int *endOfFile,
			 FILE *inFile);
			 
#define ERR_STRUCTURE		1	/* FIXME need better error codes */
#define EV_PREBOOT_CERT	  			0x00
#define EV_POST_CODE				0x01
#define	EV_UNUSED				0x02
#define EV_NO_ACTION				0x03
#define EV_SEPARATOR				0x04
#define EV_ACTION				0x05
#define EV_EVENT_TAG				0x06
#define EV_S_CRTM_CONTENTS			0x07
#define EV_S_CRTM_VERSION			0x08
#define EV_CPU_MICROCODE			0x09
#define EV_PLATFORM_CONFIG_FLAGS		0x0A
#define EV_TABLE_OF_DEVICES			0x0B
#define EV_COMPACT_HASH				0x0C
#define EV_IPL					0x0D
#define EV_IPL_PARTITION_DATA			0x0E
#define EV_NONHOST_CODE				0x0F
#define EV_NONHOST_CONFIG			0x10
#define EV_NONHOST_INFO				0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS		0x12
#define EV_EFI_EVENT_BASE			0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG		0x80000001
#define EV_EFI_VARIABLE_BOOT			0x80000002
#define EV_EFI_BOOT_SERVICES_APPLICATION	0x80000003
#define EV_EFI_BOOT_SERVICES_DRIVER		0x80000004
#define EV_EFI_RUNTIME_SERVICES_DRIVER		0x80000005
#define EV_EFI_GPT_EVENT			0x80000006
#define EV_EFI_ACTION				0x80000007
#define EV_EFI_PLATFORM_FIRMWARE_BLOB		0x80000008
#define EV_EFI_HANDOFF_TABLES			0x80000009
#define EV_EFI_HCRTM_EVENT			0x80000010 
#define EV_EFI_VARIABLE_AUTHORITY		0x800000E0
