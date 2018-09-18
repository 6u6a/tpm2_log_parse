#include "client.h"

/* Uint32_Convert() converts a little endian uint32_t (from an input stream) to host byte order
 */

static uint32_t Uint32_Convert(uint32_t in)
{
    uint32_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8) |
	  (inb[2] << 16) |
	  (inb[3] << 24);
    return out;
}

/* Uint16_Convert() converts a little endian uint16_t (from an input stream) to host byte order
 */

static uint16_t Uint16_Convert(uint16_t in)
{
    uint16_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8);
    return out;
}

/* sendBiosMeasurements() sends BIOS events from the event log file 'biosInputFilename'.

   {
   "command":"biosentry",
   "hostname":"cainl.watson.ibm.com",
   "nonce":"1298d83cdd8c50adb58648d051b1a596b66698758b8d0605013329d0b45ded0c",
   "event1":"hexascii",
   }
   {
   "response":"biosentry"
   "imaentry":"00000000"
   }

*/

static uint32_t sendBiosMeasurements(const char *biosInputFilename)
{
    uint32_t 	rc = 0;
    const int vverbose = 1;
    if (vverbose) printf("sendBiosMeasurements: Entry\n");

    /* open the BIOS event log file */
    FILE *infile = NULL;
    if (rc == 0) {
		infile = fopen(biosInputFilename,"rb");	/* closed @2 */
		if (infile == NULL) {
			printf("ERROR: sendBiosMeasurements: Unable to open event log file '%s'\n",
			   biosInputFilename);
			rc = 1;
		}
    }
    TCG_PCR_EVENT2 		event2;		/* hash agile TPM 2.0 events */
    TCG_PCR_EVENT 		event;		/* TPM 1.2 format header event */
    int endOfFile = FALSE;
    /* the first event is a TPM 1.2 format event */
    /* NOTE This informational event can be sent to the server to describe digest algorithms, event
       log version, etc. */
    /* read a TCG_PCR_EVENT event line */
    if (rc == 0) {
		memset(&event, 0x0, sizeof(TCG_PCR_EVENT));
		rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
    }
    /* trace the measurement log line */
    if (vverbose && !endOfFile && (rc == 0)) {
		if (vverbose) printf("sendBiosMeasurements: line 0\n");
    }

    /* scan each measurement 'line' in the binary */
    unsigned int 	lineNum;
    for (lineNum = 1 ; !endOfFile && (rc == 0) ; lineNum++) {
		/* read a TCG_PCR_EVENT2 event line */
		if (rc == 0) {
			memset(&event2, 0x0, sizeof(TCG_PCR_EVENT2));
			rc = TSS_EVENT2_Line_Read(&event2, &endOfFile, infile);
		}
		/* debug tracing */
		if (vverbose && !endOfFile && (rc == 0)) {
			printf("sendBiosMeasurements: line %u, current pos is 0x%x\n", lineNum, ftell(infile));
		}
		/* don't send no action events */
		if (!endOfFile && (rc == 0)) {
			if (event2.eventType == EV_NO_ACTION) {
				continue;
			}
		}
    }
    if (infile != NULL) {
		fclose(infile);		/* @2 */
    }
    return rc;
}


/* TSS_EVENT_Line_Read() reads a TPM 1.2 SHA-1 event line from a binary file inFile.

 */

int TSS_EVENT_Line_Read(TCG_PCR_EVENT *event,
			int *endOfFile,
			FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the PCR index */
    if (rc == 0) {
		readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT *)NULL)->pcrIndex), 1, inFile);
		if (readSize != 1) {
			if (feof(inFile)) {
			*endOfFile = TRUE;;
			}
			else {
			printf("TSS_EVENT_Line_Read: Error, could not read pcrIndex, returned %lu\n",
				   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
			}
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
		readSize = fread(&(event->eventType),
				 sizeof(((TCG_PCR_EVENT *)NULL)->eventType), 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT_Line_Read: Error, could not read eventType, returned %lu\n",
			   (unsigned long) readSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the digest */
    if (!*endOfFile && (rc == 0)) {
		readSize = fread(&(event->digest),
				 sizeof(((TCG_PCR_EVENT *)NULL)->digest), 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT_Line_Read: Error, could not read digest, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* read the event data size */
    if (!*endOfFile && (rc == 0)) {
		readSize = fread(&(event->eventDataSize),
				 sizeof(((TCG_PCR_EVENT *)NULL)->eventDataSize), 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT_Line_Read: Error, could not read event data size, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->eventDataSize = Uint32_Convert(event->eventDataSize);
    }
    /* bounds check the event data length */
    if (!*endOfFile && (rc == 0)) {
		if (event->eventDataSize > sizeof(((TCG_PCR_EVENT *)NULL)->event)) {
			printf("TSS_EVENT_Line_Read: Error, event data length too big: %u\n",
			   event->eventDataSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* read the event */
    if (!*endOfFile && (rc == 0) && event->eventDataSize > 0) {
		memset(event->event , 0, sizeof(((TCG_PCR_EVENT *)NULL)->event));
		readSize = fread(&(event->event),
				 event->eventDataSize, 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT_Line_Read: Error, could not read event, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    return rc;
}

/* TSS_EVENT2_Line_Read() reads a TPM2 event line from a binary file inFile.

*/

int TSS_EVENT2_Line_Read(TCG_PCR_EVENT2 *event,
			 int *endOfFile,
			 FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the PCR index */
    if (rc == 0) {
		readSize = fread(&(event->pcrIndex),
				 sizeof(((TCG_PCR_EVENT2 *)NULL)->pcrIndex), 1, inFile);
		if (readSize != 1) {
			if (feof(inFile)) {
			*endOfFile = TRUE;
			}
			else {
			printf("TSS_EVENT2_Line_Read: Error, could not read pcrIndex, returned %lu\n",
				   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
			}
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
		readSize = fread(&(event->eventType),
				 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventType), 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT2_Line_Read: Error, could not read eventType, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the TPML_DIGEST_VALUES count */
    uint32_t maxCount; 
    if (!*endOfFile && (rc == 0)) {
		maxCount = sizeof((TPML_DIGEST_VALUES *)NULL)->digests / sizeof(TPMT_HA);
		readSize = fread(&(event->digests.count),
				 sizeof(((TPML_DIGEST_VALUES *)NULL)->count), 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT2_Line_Read: Error, could not read digest count, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->digests.count = Uint32_Convert(event->digests.count);
    }
    /* range check the digest count */
    if (!*endOfFile && (rc == 0)) {
		if (event->digests.count > maxCount) {
			printf("TSS_EVENT2_Line_Read: Error, digest count %u is greater than structure %u\n",
			   event->digests.count, maxCount);
			rc = ERR_STRUCTURE;
		}
		else if (event->digests.count == 0) {
			printf("TSS_EVENT2_Line_Read: Error, digest count is zero\n");
			rc = ERR_STRUCTURE;
		}
    }
    uint32_t count;
    /* read all the TPMT_HA, loop through all the digest algorithms */
    for (count = 0 ; !*endOfFile && (count < event->digests.count) ; count++) {
		/* read the digest algorithm */
		if (rc == 0) {
			readSize = fread(&(event->digests.digests[count].hashAlg),
					 sizeof((TPMT_HA *)NULL)->hashAlg, 1, inFile);
			if (readSize != 1) {
			printf("TSS_EVENT2_Line_Read: "
				   "Error, could not read digest algorithm, returned %lu\n",
				   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
			}
		}
		/* do the endian conversion of the hash algorithm from stream to uint16_t */
		if (rc == 0) {
			event->digests.digests[count].hashAlg =
			Uint16_Convert(event->digests.digests[count].hashAlg);
		}
		/* map from the digest algorithm to the digest length */
		uint16_t digestSize;
		if (rc == 0) {
			digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
			if (digestSize == 0) {
			printf("TSS_EVENT2_Line_Read: Error, unknown digest algorithm %04x*\n",
				   event->digests.digests[count].hashAlg);
			rc = ERR_STRUCTURE;
			}
		}
		/* read the digest */
		if (rc == 0) {
			readSize = fread((uint8_t *)&(event->digests.digests[count].digest),
					 digestSize, 1, inFile);
			if (readSize != 1) {
			printf("TSS_EVENT2_Line_Read: Error, could not read digest, returned %lu\n",
				   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
			}
		}
    }
    /* read the event size */
    if (!*endOfFile && (rc == 0)) {
		readSize = fread(&(event->eventSize),
				 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventSize), 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT2_Line_Read: Error, could not read event size, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
		event->eventSize = Uint32_Convert(event->eventSize);
    }
    /* bounds check the event size */
    if (!*endOfFile && (rc == 0)) {
		if (event->eventSize > sizeof(((TCG_PCR_EVENT2 *)NULL)->event)) {
			printf("TSS_EVENT2_Line_Read: Error, event size too big: %u\n",
			   event->eventSize);
			rc = ERR_STRUCTURE;
		}
    }
    /* read the event */
    if (!*endOfFile && (rc == 0) && event->eventSize > 0) {
		memset(event->event , 0, sizeof(((TCG_PCR_EVENT2 *)NULL)->event));
		readSize = fread(&(event->event),
				 event->eventSize, 1, inFile);
		if (readSize != 1) {
			printf("TSS_EVENT2_Line_Read: Error, could not read event, returned %lu\n",
			   (unsigned long)readSize);
			rc = ERR_STRUCTURE;
		}
    }
    return rc;
}

int main(int argc, char *argv[]){
	if(argc > 1){
		sendBiosMeasurements(argv[1]);
	}
	return 0;
}
