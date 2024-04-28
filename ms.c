#define _UNICODE
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#include <strsafe.h>
#include <stdio.h>

// #pragma comment(lib, "advapi32.lib")
// #pragma comment(lib, "shlwapi.lib")

// Contains the elements required to calculate a counter value.
typedef struct _rawdata
{
    DWORD CounterType;
    ULONGLONG Data;          // Raw counter data
    LONGLONG Time;           // Is a time value or a base value
    DWORD MultiCounterData;  // Second raw counter value for multi-valued counters
    LONGLONG Frequency;
}RAW_DATA, *PRAW_DATA;

#define INIT_OBJECT_BUFFER_SIZE (256 * 1024) // Initial buffer size to use when querying specific objects.

// -----------------------------------------------------------------

typedef struct HashTableEntry {
    DWORD id;
    char *key;
    char *help;
} HashTableEntry;

#define HASH_TABLE_SIZE 100000
HashTableEntry* idArray[HASH_TABLE_SIZE] = { 0 };

void insertHashTable(DWORD id, const char *key, const char *help) {
    if(id >= HASH_TABLE_SIZE) {
        printf(" > Too big hash table id %u\n", id);
        abort();
    }

    HashTableEntry *entry = idArray[id];
    if(entry) {
        if(key && entry->key) {
            printf(" > key %u already has a key\n", id);
            abort();
        }
        if(help && entry->help) {
            printf(" > key %u already has a key\n", id);
            abort();
        }
    }
    else
        entry = idArray[id] = (HashTableEntry *)calloc(1, sizeof(*entry));

    if(key && !entry->key)
        entry->key = strdup(key);

    if(help && !entry->help)
        entry->help = strdup(help);

    entry->id = id;
}

const char *findNameByID(DWORD id) {
    if(id < HASH_TABLE_SIZE) {
        HashTableEntry *titleEntry = idArray[id];
        if(titleEntry && titleEntry->key)
            return titleEntry->key;
    }
    return "";
}

const char *findHelpByID(DWORD id) {
    if(id < HASH_TABLE_SIZE) {
        HashTableEntry *titleEntry = idArray[id];
        if(titleEntry && titleEntry->help)
            return titleEntry->help;
    }
    return "";
}

// ----------------------------------------------------------

void readRegistryKeys(BOOL helps) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize = 0;
    LONG lStatus;

    LPCSTR valueName;
    if(helps)
        valueName = TEXT("help");
    else
        valueName = TEXT("CounterDefinition");

    // Open the key for the English counters
    lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009"), 0, KEY_READ, &hKey);
    if (lStatus != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to open registry key: %ld\n", (long)lStatus);
        return;
    }

    // Get the size of the 'Counters' data
    lStatus = RegQueryValueEx(hKey, valueName, NULL, &dwType, NULL, &dwSize);
    if (lStatus != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get size of 'Counters' data: %ld\n", (long)lStatus);
        RegCloseKey(hKey);
        return;
    }

    // Allocate memory for the data
    TCHAR *pData = malloc(dwSize);
    if (pData == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        RegCloseKey(hKey);
        return;
    }

    // Read the 'Counters' data
    lStatus = RegQueryValueEx(hKey, valueName, NULL, &dwType, (LPBYTE)pData, &dwSize);
    if (lStatus != ERROR_SUCCESS || dwType != REG_MULTI_SZ) {
        fprintf(stderr, "Failed to read 'Counters' data or unexpected data type: %ld\n", (long)lStatus);
        free(pData);
        RegCloseKey(hKey);
        return;
    }

    // Process the counter data
    TCHAR *ptr = pData;
    while (*ptr) {
        TCHAR *sid = ptr;  // First string is the ID
        ptr += lstrlen(ptr) + 1; // Move to the next string
        TCHAR *name = ptr;  // Second string is the name
        ptr += lstrlen(ptr) + 1; // Move to the next pair

        DWORD id = strtoul(sid, NULL, 10);

        // Output the id and name for demonstration
        printf("ID: %u, %s: %s\n", id, helps ? "help" : "name", name);

        if(helps)
            insertHashTable(id, NULL, name);
        else
            insertHashTable(id, name, NULL);
    }

    free(pData);
    RegCloseKey(hKey);
}

// --------------------------------------------------------------------------------

// Retrieve a buffer that contains the specified performance data.
// The pwszSource parameter determines the data that GetRegistryBuffer returns.
//
// Typically, when calling RegQueryValueEx, you can specify zero for the size of the buffer
// and the RegQueryValueEx will set your size variable to the required buffer size. However, 
// if the source is "Global" or one or more object index values, you will need to increment
// the buffer size in a loop until RegQueryValueEx does not return ERROR_MORE_DATA. 
LPBYTE GetPerformanceData(LPCSTR pwszSource, DWORD dwInitialBufferSize)
{
    LPBYTE pBuffer = NULL;
    DWORD dwBufferSize = 0;        //Size of buffer, used to increment buffer size
    DWORD dwSize = 0;              //Size of buffer, used when calling RegQueryValueEx
    LPBYTE pTemp = NULL;           //Temp variable for realloc() in case it fails
    LONG status = ERROR_SUCCESS; 

    dwBufferSize = dwSize = dwInitialBufferSize;
    pBuffer = (LPBYTE)malloc(dwBufferSize);
    if (pBuffer) {
        while (ERROR_MORE_DATA == (status = RegQueryValueEx(HKEY_PERFORMANCE_DATA, pwszSource, NULL, NULL, pBuffer, &dwSize)))
        {
            //Contents of dwSize is unpredictable if RegQueryValueEx fails, which is why
            //you need to increment dwBufferSize and use it to set dwSize.
            dwBufferSize *= 2;

            pTemp = (LPBYTE)realloc(pBuffer, dwBufferSize);
            if (pTemp) {
                pBuffer = pTemp;
                dwSize = dwBufferSize;
            }
            else {
                printf("Reallocation error.\n");
                free(pBuffer);
                pBuffer = NULL;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != status) {
            printf("RegQueryValueEx failed with 0x%x.\n", status);
            free(pBuffer);
            pBuffer = NULL;
        }
    }
    else {
        printf("malloc failed to allocate initial memory request.\n");
    }

cleanup:
    RegCloseKey(HKEY_PERFORMANCE_DATA);
    return pBuffer;
}

// --------------------------------------------------------------------------------------------------------------------

// Retrieve the raw counter value and any supporting data needed to calculate
// a displayable counter value. Use the counter type to determine the information
// needed to calculate the value.
BOOL GetValue(
        PERF_DATA_BLOCK *pDataBlock,
        PERF_OBJECT_TYPE* pObject,
        PERF_COUNTER_DEFINITION* pCounter,
        PERF_COUNTER_BLOCK* pCounterDataBlock,
        PRAW_DATA pRawData)
{
    PVOID pData = NULL;
    UNALIGNED ULONGLONG* pullData = NULL;
    PERF_COUNTER_DEFINITION* pBaseCounter = NULL;
    BOOL fSuccess = TRUE;

    //Point to the raw counter data.
    pData = (PVOID)((LPBYTE)pCounterDataBlock + pCounter->CounterOffset);

    //Now use the PERF_COUNTER_DEFINITION.CounterType value to figure out what
    //other information you need to calculate a displayable value.
    switch (pCounter->CounterType) {

    case PERF_COUNTER_COUNTER:
    case PERF_COUNTER_QUEUELEN_TYPE:
    case PERF_SAMPLE_COUNTER:
        pRawData->Data = (ULONGLONG)(*(DWORD*)pData);
        pRawData->Time = pDataBlock->PerfTime.QuadPart;
        if (PERF_COUNTER_COUNTER == pCounter->CounterType || PERF_SAMPLE_COUNTER == pCounter->CounterType)
            pRawData->Frequency = pDataBlock->PerfFreq.QuadPart;
        break;

    case PERF_OBJ_TIME_TIMER:
        pRawData->Data = (ULONGLONG)(*(DWORD*)pData);
        pRawData->Time = pObject->PerfTime.QuadPart;
        break;

    case PERF_COUNTER_100NS_QUEUELEN_TYPE:
        pRawData->Data = *(UNALIGNED ULONGLONG *)pData;
        pRawData->Time = pDataBlock->PerfTime100nSec.QuadPart;
        break;

    case PERF_COUNTER_OBJ_TIME_QUEUELEN_TYPE:
        pRawData->Data = *(UNALIGNED ULONGLONG *)pData;
        pRawData->Time = pObject->PerfTime.QuadPart;
        break;

    case PERF_COUNTER_TIMER:
    case PERF_COUNTER_TIMER_INV:
    case PERF_COUNTER_BULK_COUNT:
    case PERF_COUNTER_LARGE_QUEUELEN_TYPE:
        pullData = (UNALIGNED ULONGLONG *)pData;
        pRawData->Data = *pullData;
        pRawData->Time = pDataBlock->PerfTime.QuadPart;
        if (pCounter->CounterType == PERF_COUNTER_BULK_COUNT)
            pRawData->Frequency = pDataBlock->PerfFreq.QuadPart;
        break;

    case PERF_COUNTER_MULTI_TIMER:
    case PERF_COUNTER_MULTI_TIMER_INV:
        pullData = (UNALIGNED ULONGLONG *)pData;
        pRawData->Data = *pullData;
        pRawData->Frequency = pDataBlock->PerfFreq.QuadPart;
        pRawData->Time = pDataBlock->PerfTime.QuadPart;

        //These counter types have a second counter value that is adjacent to
        //this counter value in the counter data block. The value is needed for
        //the calculation.
        if ((pCounter->CounterType & PERF_MULTI_COUNTER) == PERF_MULTI_COUNTER) {
            ++pullData;
            pRawData->MultiCounterData = *(DWORD*)pullData;
        }
        break;

    //These counters do not use any time reference.
    case PERF_COUNTER_RAWCOUNT:
    case PERF_COUNTER_RAWCOUNT_HEX:
    case PERF_COUNTER_DELTA:
        pRawData->Data = (ULONGLONG)(*(DWORD*)pData);
        pRawData->Time = 0;
        break;

    case PERF_COUNTER_LARGE_RAWCOUNT:
    case PERF_COUNTER_LARGE_RAWCOUNT_HEX:
    case PERF_COUNTER_LARGE_DELTA:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pRawData->Time = 0;
        break;
    
    //These counters use the 100ns time base in their calculation.
    case PERF_100NSEC_TIMER:
    case PERF_100NSEC_TIMER_INV:
    case PERF_100NSEC_MULTI_TIMER:
    case PERF_100NSEC_MULTI_TIMER_INV:
        pullData = (UNALIGNED ULONGLONG*)pData;
        pRawData->Data = *pullData;
        pRawData->Time = pDataBlock->PerfTime100nSec.QuadPart;

        //These counter types have a second counter value that is adjacent to
        //this counter value in the counter data block. The value is needed for
        //the calculation.
        if ((pCounter->CounterType & PERF_MULTI_COUNTER) == PERF_MULTI_COUNTER) {
            ++pullData;
            pRawData->MultiCounterData = *(DWORD*)pullData;
        }
        break;

    //These counters use two data points, this value and one from this counter's
    //base counter. The base counter should be the next counter in the object's 
    //list of counters.
    case PERF_SAMPLE_FRACTION:
    case PERF_RAW_FRACTION:
        pRawData->Data = (ULONGLONG)(*(DWORD*)pData);
        pBaseCounter = pCounter + 1;  //Get base counter
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE) {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = (LONGLONG)(*(DWORD*)pData);
        }
        else
            fSuccess = FALSE;
        break;

    case PERF_LARGE_RAW_FRACTION:
    case PERF_PRECISION_SYSTEM_TIMER:
    case PERF_PRECISION_100NS_TIMER:
    case PERF_PRECISION_OBJECT_TIMER:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pBaseCounter = pCounter + 1;
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE) {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = *(LONGLONG*)pData;
        }
        else
            fSuccess = FALSE;
        break;

    case PERF_AVERAGE_TIMER:
    case PERF_AVERAGE_BULK:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pBaseCounter = pCounter+1;
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE) {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = *(DWORD*)pData;
        }
        else
            fSuccess = FALSE;

        if (pCounter->CounterType == PERF_AVERAGE_TIMER)
            pRawData->Frequency = pDataBlock->PerfFreq.QuadPart;
        break;

    //These are base counters and are used in calculations for other counters.
    //This case should never be entered.
    case PERF_SAMPLE_BASE:
    case PERF_AVERAGE_BASE:
    case PERF_COUNTER_MULTI_BASE:
    case PERF_RAW_BASE:
    case PERF_LARGE_RAW_BASE:
        printf(" > Ignored base counter type: 0x%08x\n", pCounter->CounterType);
        pRawData->Data = 0;
        pRawData->Time = 0;
        fSuccess = FALSE;
        break;

    case PERF_ELAPSED_TIME:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pRawData->Time = pObject->PerfTime.QuadPart;
        pRawData->Frequency = pObject->PerfFreq.QuadPart;
        break;

    //These counters are currently not supported.
    case PERF_COUNTER_TEXT:
    case PERF_COUNTER_NODATA:
    case PERF_COUNTER_HISTOGRAM_TYPE:
        printf(" > Unsupported counter type: 0x%08x\n", pCounter->CounterType);
        pRawData->Data = 0;
        pRawData->Time = 0;
        fSuccess = FALSE;
        break;

    //Encountered an unidentified counter.
    default:
        printf(" > Unrecognized counter type: 0x%08x\n", pCounter->CounterType);
        pRawData->Data = 0;
        pRawData->Time = 0;
        fSuccess = FALSE;
        break;
    }

    return fSuccess;
}

// Use the CounterType to determine how to calculate the displayable
// value. The case statement includes the formula used to calculate
// the value.
BOOL DisplayCalculatedValue(RAW_DATA* pSample0, RAW_DATA* pSample1)
{
    BOOL fSuccess = TRUE;
    ULONGLONG numerator = 0;
    LONGLONG denominator = 0;
    double doubleValue = 0;
    DWORD dwordValue = 0;

    if (NULL == pSample1)
    {
        // Return error if the counter type requires two samples to calculate the value.
        switch (pSample0->CounterType)
        {
        default:
            if (PERF_DELTA_COUNTER != (pSample0->CounterType & PERF_DELTA_COUNTER))
            {
                break;
            }
            __fallthrough;
        case PERF_AVERAGE_TIMER: // Special case.
        case PERF_AVERAGE_BULK:  // Special case.
            printf(" > The counter type requires two samples but only one sample was provided.\n");
            fSuccess = FALSE;
            goto cleanup;
        }
    }
    else
    {
        if (pSample0->CounterType != pSample1->CounterType)
        {
            printf(" > The samples have inconsistent counter types.\n");
            fSuccess = FALSE;
            goto cleanup;
        }

        // Check for integer overflow or bad data from provider (the data from
        // sample 2 must be greater than the data from sample 1).
        if (pSample0->Data > pSample1->Data)
        {
            // Can happen for various reasons. Commonly occurs with the Process counterset when
            // multiple processes have the same name and one of them starts or stops.
            // Normally you'll just drop the older sample and continue.
            printf("> Sample0 (%llu) is larger than sample1 (%llu).\n", pSample0->Data, pSample1->Data);
            fSuccess = FALSE;
            goto cleanup;
        }
    }

    switch (pSample0->CounterType)
    {
    case PERF_COUNTER_COUNTER:
    case PERF_SAMPLE_COUNTER:
    case PERF_COUNTER_BULK_COUNT:
        // (N1 - N0) / ((D1 - D0) / F)
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        dwordValue = (DWORD)(numerator / ((double)denominator / pSample1->Frequency));
        printf("Display value is (counter): %lu%s\n", (unsigned long)dwordValue,
            (pSample0->CounterType == PERF_SAMPLE_COUNTER) ? "" : "/sec");
        break;

    case PERF_COUNTER_QUEUELEN_TYPE:
    case PERF_COUNTER_100NS_QUEUELEN_TYPE:
    case PERF_COUNTER_OBJ_TIME_QUEUELEN_TYPE:
    case PERF_COUNTER_LARGE_QUEUELEN_TYPE:
    case PERF_AVERAGE_BULK:  // normally not displayed
        // (N1 - N0) / (D1 - D0)
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = (double)numerator / denominator;
        if (pSample0->CounterType != PERF_AVERAGE_BULK)
            printf("Display value is (queuelen): %f\n", doubleValue);
        break;

    case PERF_OBJ_TIME_TIMER:
    case PERF_COUNTER_TIMER:
    case PERF_100NSEC_TIMER:
    case PERF_PRECISION_SYSTEM_TIMER:
    case PERF_PRECISION_100NS_TIMER:
    case PERF_PRECISION_OBJECT_TIMER:
    case PERF_SAMPLE_FRACTION:
        // 100 * (N1 - N0) / (D1 - D0)
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = (double)(100 * numerator) / denominator;
        printf("Display value is (timer): %f%%\n", doubleValue);
        break;

    case PERF_COUNTER_TIMER_INV:
        // 100 * (1 - ((N1 - N0) / (D1 - D0)))
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = 100 * (1 - ((double)numerator / denominator));
        printf("Display value is (timer-inv): %f%%\n", doubleValue);
        break;

    case PERF_100NSEC_TIMER_INV:
        // 100 * (1- (N1 - N0) / (D1 - D0))
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = 100 * (1 - (double)numerator / denominator);
        printf("Display value is (100ns-timer-inv): %f%%\n", doubleValue);
        break;

    case PERF_COUNTER_MULTI_TIMER:
        // 100 * ((N1 - N0) / ((D1 - D0) / TB)) / B1
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        denominator /= pSample1->Frequency;
        doubleValue = 100 * ((double)numerator / denominator) / pSample1->MultiCounterData;
        printf("Display value is (multi-timer): %f%%\n", doubleValue);
        break;

    case PERF_100NSEC_MULTI_TIMER:
        // 100 * ((N1 - N0) / (D1 - D0)) / B1
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = 100 * ((double)numerator / denominator) / pSample1->MultiCounterData;
        printf("Display value is (100ns multi-timer): %f%%\n", doubleValue);
        break;

    case PERF_COUNTER_MULTI_TIMER_INV:
    case PERF_100NSEC_MULTI_TIMER_INV:
        // 100 * (B1 - ((N1 - N0) / (D1 - D0)))
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = 100 * (pSample1->MultiCounterData - ((double)numerator / denominator));
        printf("Display value is (multi-timer-inv): %f%%\n", doubleValue);
        break;

    case PERF_COUNTER_RAWCOUNT:
    case PERF_COUNTER_LARGE_RAWCOUNT:
        // N as decimal
        printf("Display value is (rawcount): %llu\n", pSample0->Data);
        break;

    case PERF_COUNTER_RAWCOUNT_HEX:
    case PERF_COUNTER_LARGE_RAWCOUNT_HEX:
        // N as hexadecimal
        printf("Display value is (hex): 0x%llx\n", pSample0->Data);
        break;

    case PERF_COUNTER_DELTA:
    case PERF_COUNTER_LARGE_DELTA:
        // N1 - N0
        printf("Display value is (delta): %llu\n", pSample1->Data - pSample0->Data);
        break;

    case PERF_RAW_FRACTION:
    case PERF_LARGE_RAW_FRACTION:
        // 100 * N / B
        doubleValue = (double)100 * pSample0->Data / pSample0->Time;
        printf("Display value is (fraction): %f%%\n", doubleValue);
        break;

    case PERF_AVERAGE_TIMER:
        // ((N1 - N0) / TB) / (B1 - B0)
        numerator = pSample1->Data - pSample0->Data;
        denominator = pSample1->Time - pSample0->Time;
        doubleValue = (double)numerator / pSample1->Frequency / denominator;
        printf("Display value is (average timer): %f seconds\n", doubleValue);
        break;

    case PERF_ELAPSED_TIME:
        // (D0 - N0) / F
        doubleValue = (double)(pSample0->Time - pSample0->Data) / pSample0->Frequency;
        printf("Display value is (elapsed time): %f seconds\n", doubleValue);
        break;

    case PERF_COUNTER_TEXT:
    case PERF_SAMPLE_BASE:
    case PERF_AVERAGE_BASE:
    case PERF_COUNTER_MULTI_BASE:
    case PERF_RAW_BASE:
    case PERF_COUNTER_NODATA:
    case PERF_PRECISION_TIMESTAMP:
        printf(" > Non-printing counter type: 0x%08x\n", pSample0->CounterType);
        break;

    default:
        printf(" > Unrecognized counter type: 0x%08x\n", pSample0->CounterType);
        fSuccess = FALSE;
        break;
    }

cleanup:

    return fSuccess;
}

// --------------------------------------------------------------------------------------------------------------------

BOOL isValidPointer(PERF_DATA_BLOCK *pDataBlock, void *ptr) {
    return (PBYTE)ptr >= (PBYTE)pDataBlock + pDataBlock->TotalByteLength ? FALSE : TRUE;
}

BOOL isValidStructure(PERF_DATA_BLOCK *pDataBlock, void *ptr, size_t length) {
    return (PBYTE)ptr + length > (PBYTE)pDataBlock + pDataBlock->TotalByteLength ? FALSE : TRUE;
}

PERF_DATA_BLOCK *getDataBlock(BYTE *pBuffer) {
    PERF_DATA_BLOCK *pDataBlock = (PERF_DATA_BLOCK *)pBuffer;

    static WCHAR signature[] = { 'P', 'E', 'R', 'F' };

    if(memcmp(pDataBlock->Signature, signature, sizeof(signature)) != 0) {
        printf("> Invalid data block signature.\n");
        return NULL;
    }

    if(!isValidPointer(pDataBlock, (PBYTE)pDataBlock + pDataBlock->SystemNameOffset) ||
        !isValidStructure(pDataBlock, (PBYTE)pDataBlock + pDataBlock->SystemNameOffset, pDataBlock->SystemNameLength)) {
        printf(" > Invalid system name array\n");
        return NULL;
    }

    return pDataBlock;
}

PERF_OBJECT_TYPE *getObjectType(PERF_DATA_BLOCK* pDataBlock, PERF_OBJECT_TYPE *lastObjectType) {
    PERF_OBJECT_TYPE* pObjectType = NULL;
    
    if(!lastObjectType)
        pObjectType = (PERF_OBJECT_TYPE *)((PBYTE)pDataBlock + pDataBlock->HeaderLength);
    else if (lastObjectType->TotalByteLength != 0)
        pObjectType = (PERF_OBJECT_TYPE *)((PBYTE)lastObjectType + lastObjectType->TotalByteLength);

    if(pObjectType && (!isValidPointer(pDataBlock, pObjectType) || !isValidStructure(pDataBlock, pObjectType, pObjectType->TotalByteLength))) {
        printf(" > Invalid ObjectType!\n");
        pObjectType = NULL;
        abort();
    }

    return pObjectType;
}

PERF_OBJECT_TYPE *getObjectTypeByIndex(PERF_DATA_BLOCK *pDataBlock, DWORD ObjectNameTitleIndex) {
    PERF_OBJECT_TYPE *po = NULL;
    for(DWORD o = 0; o < pDataBlock->NumObjectTypes ; o++) {
         po = getObjectType(pDataBlock, po);
         if(po->ObjectNameTitleIndex == ObjectNameTitleIndex)
             return po;
    }

    return NULL;
}

PERF_INSTANCE_DEFINITION *getInstance(
    PERF_DATA_BLOCK *pDataBlock,
    PERF_OBJECT_TYPE *pObjectType,
    PERF_COUNTER_BLOCK *lastCounterBlock
) {
    PERF_INSTANCE_DEFINITION *pInstance;

    if(!lastCounterBlock)
        pInstance = (PERF_INSTANCE_DEFINITION *)((PBYTE)pObjectType + pObjectType->DefinitionLength);
    else
        pInstance = (PERF_INSTANCE_DEFINITION *)((PBYTE)lastCounterBlock + lastCounterBlock->ByteLength);

    if(pInstance && (!isValidPointer(pDataBlock, pInstance) || !isValidStructure(pDataBlock, pInstance, pInstance->ByteLength))) {
        printf("> Invalid Instance Definition!\n");
        pInstance = NULL;
    }

    return pInstance;
}

PERF_COUNTER_BLOCK *getObjectTypeCounterBlock(
    PERF_DATA_BLOCK *pDataBlock,
    PERF_OBJECT_TYPE *pObjectType
) {
    PERF_COUNTER_BLOCK *pCounterBlock = (PERF_COUNTER_BLOCK *)((PBYTE)pObjectType + pObjectType->DefinitionLength);

    if(pCounterBlock && (!isValidPointer(pDataBlock, pCounterBlock) || !isValidStructure(pDataBlock, pCounterBlock, pCounterBlock->ByteLength))) {
        printf("> Invalid ObjectType CounterBlock!\n");
        pCounterBlock = NULL;
    }

    return pCounterBlock;
}

PERF_COUNTER_BLOCK *getInstanceCounterBlock(
    PERF_DATA_BLOCK *pDataBlock,
    PERF_OBJECT_TYPE *pObjectType,
    PERF_INSTANCE_DEFINITION *pInstance
) {
    (void)pObjectType;
    PERF_COUNTER_BLOCK *pCounterBlock = (PERF_COUNTER_BLOCK *)((PBYTE)pInstance + pInstance->ByteLength);

    if(pCounterBlock && (!isValidPointer(pDataBlock, pCounterBlock) || !isValidStructure(pDataBlock, pCounterBlock, pCounterBlock->ByteLength))) {
        printf("> Invalid Instance CounterBlock!\n");
        pCounterBlock = NULL;
    }

    return pCounterBlock;
}

PERF_INSTANCE_DEFINITION *getInstanceByPosition(
        PERF_DATA_BLOCK *pDataBlock,
        PERF_OBJECT_TYPE *pObjectType,
        DWORD instancePosition
) {
    PERF_INSTANCE_DEFINITION *pi = NULL;
    PERF_COUNTER_BLOCK *pc = NULL;
    for(DWORD i = 0; i <= instancePosition ;i++) {
        pi = getInstance(pDataBlock, pObjectType, pc);
        pc = getInstanceCounterBlock(pDataBlock, pObjectType, pi);
    }
    return pi;
}

PERF_COUNTER_DEFINITION *getCounterDefinition(
    PERF_DATA_BLOCK *pDataBlock,
    PERF_OBJECT_TYPE *pObjectType,
    PERF_COUNTER_DEFINITION *lastCounterDefinition
) {
    PERF_COUNTER_DEFINITION *pCounterDefinition = NULL;

    if(!lastCounterDefinition)
        pCounterDefinition = (PERF_COUNTER_DEFINITION *)((PBYTE)pObjectType + pObjectType->HeaderLength);
    else
        pCounterDefinition = (PERF_COUNTER_DEFINITION *)((PBYTE)lastCounterDefinition +	lastCounterDefinition->ByteLength);

    if(pCounterDefinition && (!isValidPointer(pDataBlock, pCounterDefinition) || !isValidStructure(pDataBlock, pCounterDefinition, pCounterDefinition->ByteLength))) {
        printf("> Invalid Counter Definition!\n");
        pCounterDefinition = NULL;
    }

    return pCounterDefinition;
}

// --------------------------------------------------------------------------------------------------------------------

void printDataBlock(PERF_DATA_BLOCK *pDataBlock) {
    char systemName[4096] = "";
    // txtCopy(systemName, (char *)((PBYTE)pDataBlock + pDataBlock->SystemNameOffset), sizeof(systemName), pDataBlock->SystemNameLength);

    printf("\n--------------------------------------------------------------\n");
    printf("Data Block\n");
    printf("System name: %s\n", systemName);
    printf("Number of ObjectTypes: %d\n", pDataBlock->NumObjectTypes);
    printf("Total Bytes Length: %d\n", pDataBlock->TotalByteLength);
    printf("Revision: %d\n", pDataBlock->Revision);
    printf("Frequency: %lld\n", pDataBlock->PerfFreq.QuadPart);
}

void printObjectType(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType) {
    (void)pDataBlock;

    printf("\n   --------------------------------------------------------------\n");
    printf("   Object Type\n");
    printf("   Number of Instances: %d\n", pObjectType->NumInstances);
    printf("   Number of Counters: %d\n", pObjectType->NumCounters);
    printf("   Title: %s\n", findNameByID(pObjectType->ObjectNameTitleIndex));
    printf("   Help: %s\n", findHelpByID(pObjectType->ObjectHelpTitleIndex));
}

BOOL getEncodedStringToUTF8(char *dst, size_t dst_len, DWORD CodePage, char *start, DWORD length) {
    WCHAR *tempBuffer;  // Temporary buffer for Unicode data
    DWORD charsCopied = 0;
    BOOL free_tempBuffer;

    if (CodePage == 0) {
        // Input is already Unicode (UTF-16)
        tempBuffer = (WCHAR *)start;
        charsCopied = length / sizeof(WCHAR);  // Convert byte length to number of WCHARs
        free_tempBuffer = FALSE;
    }
    else {
        // Convert the multi-byte instance name to Unicode (UTF-16)
        // Calculate maximum possible characters in UTF-16

        int charCount = MultiByteToWideChar(CodePage, 0, start, (int)length, NULL, 0);
        tempBuffer = (WCHAR *)malloc(charCount * sizeof(WCHAR));
        if (!tempBuffer) return FALSE;

        charsCopied = MultiByteToWideChar(CodePage, 0, start, (int)length, tempBuffer, charCount);
        if (charsCopied == 0) {
            free(tempBuffer);
            dst[0] = '\0';
            return FALSE;
        }

        free_tempBuffer = TRUE;
    }

    // Now convert from Unicode (UTF-16) to UTF-8
    int bytesCopied = WideCharToMultiByte(CP_UTF8, 0, tempBuffer, (int)charsCopied, dst, (int)dst_len, NULL, NULL);
    if (bytesCopied == 0) {
        if (free_tempBuffer) free(tempBuffer);
        dst[0] = '\0'; // Ensure the buffer is null-terminated even on failure
        return FALSE;
    }

    dst[bytesCopied] = '\0'; // Ensure buffer is null-terminated
    if (free_tempBuffer) free(tempBuffer); // Free temporary buffer if used
    return TRUE;
}

BOOL getInstanceName(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType, PERF_INSTANCE_DEFINITION *pInstance,
                     char *buffer, size_t bufferLen) {
    (void)pDataBlock;

    if (!pInstance || !buffer || !bufferLen) return FALSE;

    return getEncodedStringToUTF8(buffer, bufferLen, pObjectType->CodePage,
                                  ((char *) pInstance + pInstance->NameOffset), pInstance->NameLength);
}

void printInstance(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType, PERF_INSTANCE_DEFINITION *pInstance) {
    char name[4096];
    if(!getInstanceName(pDataBlock, pObjectType, pInstance, name, sizeof(name)))
        strncpy(name, "[failed]", sizeof(name));

    printf("\n      --------------------------------------------------------------\n");
    printf("      Instance Definition\n");
    printf("      Unique ID %d\n", pInstance->UniqueID);
    printf("      LABEL: '%s' = '%s'\n", findNameByID(pObjectType->ObjectNameTitleIndex), name);

    if(pInstance->ParentObjectTitleIndex) {
        PERF_INSTANCE_DEFINITION *pi = pInstance;
        while(pi->ParentObjectTitleIndex) {
            PERF_OBJECT_TYPE *po = getObjectTypeByIndex(pDataBlock, pInstance->ParentObjectTitleIndex);
            pi = getInstanceByPosition(pDataBlock, po, pi->ParentObjectInstance);

            if(!getInstanceName(pDataBlock, po, pi, name, sizeof(name)))
                strncpy(name, "[failed]", sizeof(name));

            printf("      PARENT LABEL: '%s' = '%s'\n", findNameByID(po->ObjectNameTitleIndex), name);
        }
    }
}

void printInstanceCounterDefinition(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType, PERF_INSTANCE_DEFINITION *pInstance, PERF_COUNTER_DEFINITION *pCounterDefinition) {
    (void)pDataBlock;
    (void)pObjectType;
    (void)pInstance;

    printf("         Instance Counter Definition\n");
    printf("         Title: %s\n", findNameByID(pCounterDefinition->CounterNameTitleIndex));
    printf("         Help: %s\n", findHelpByID(pCounterDefinition->CounterHelpTitleIndex));
}

void printCounterDefinition(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType, PERF_COUNTER_DEFINITION *pCounterDefinition) {
    (void)pDataBlock;
    (void)pObjectType;

    printf("         Counter Definition\n");
    printf("         Title: %s\n", findNameByID(pCounterDefinition->CounterNameTitleIndex));
    printf("         Help: %s\n", findHelpByID(pCounterDefinition->CounterHelpTitleIndex));
}

int main(void) {
    readRegistryKeys(FALSE);
    readRegistryKeys(TRUE);

    // Retrieve counter data for the Processor object.
    LPBYTE g_pPerfDataHead = (LPBYTE)GetPerformanceData(NULL, INIT_OBJECT_BUFFER_SIZE);
    if (NULL == g_pPerfDataHead)
    {
        printf(" > GetPerformanceData failed.\n");
        goto cleanup;
    }

    PERF_DATA_BLOCK *pDataBlock = getDataBlock(g_pPerfDataHead);
    if(!pDataBlock)
        goto cleanup;

    printDataBlock(pDataBlock);

    PERF_OBJECT_TYPE* pObjectType = NULL;
    for(DWORD d = 0; d < pDataBlock->NumObjectTypes; d++) {
        pObjectType = getObjectType(pDataBlock, pObjectType);
        if(!pObjectType) {
            printf("> Cannot read object type No %d (out of %d)\n", d, pDataBlock->NumObjectTypes);
            break;
        }

        printObjectType(pDataBlock, pObjectType);

        if(pObjectType->NumInstances != PERF_NO_INSTANCES && pObjectType->NumInstances > 0) {
            PERF_INSTANCE_DEFINITION *pInstance = NULL;
            PERF_COUNTER_BLOCK *pCounterBlock = NULL;
            for(int i = 0; i < pObjectType->NumInstances ;i++) {
                pInstance = getInstance(pDataBlock, pObjectType, pCounterBlock);
                if(!pInstance) {
                    printf(" > Cannot read Instance No %d (out of %d)\n", i, pObjectType->NumInstances);
                    break;
                }

                printInstance(pDataBlock, pObjectType, pInstance);

                pCounterBlock = getInstanceCounterBlock(pDataBlock, pObjectType, pInstance);
                if(!pCounterBlock) {
                    printf("> Cannot read CounterBlock of instance No %d (out of %d)\n", i, pObjectType->NumInstances);
                    break;
                }

                PERF_COUNTER_DEFINITION *pCounterDefinition = NULL;
                for(DWORD c = 0; c < pObjectType->NumCounters ;c++) {
                    pCounterDefinition = getCounterDefinition(pDataBlock, pObjectType, pCounterDefinition);
                    if(!pCounterDefinition) {
                        printf("> Cannot read counter definition No %u (out of %u)\n", c, pObjectType->NumCounters);
                        break;
                    }

                    printInstanceCounterDefinition(pDataBlock, pObjectType, pInstance, pCounterDefinition);

                    RAW_DATA sample = {
                            .CounterType = pCounterDefinition->CounterType,
                            .Frequency = pDataBlock->PerfFreq.QuadPart,
                    };
                    if(GetValue(pDataBlock, pObjectType, pCounterDefinition, pCounterBlock, &sample))
                        DisplayCalculatedValue(&sample, &sample);
                    else
                        printf("> Cannot get Value of object %d, instance %d, counter %d", d, i, c);
                }
            }
        }
        else {
            PERF_COUNTER_BLOCK *pCounterBlock = getObjectTypeCounterBlock(pDataBlock, pObjectType);
            PERF_COUNTER_DEFINITION *pCounterDefinition = NULL;
            for(unsigned c = 0; c < pObjectType->NumCounters ;c++) {
                pCounterDefinition = getCounterDefinition(pDataBlock, pObjectType, pCounterDefinition);
                if(!pCounterDefinition) {
                    printf("> Cannot read counter definition No %d (out of %d)\n", c, pObjectType->NumCounters);
                    break;
                }

                printCounterDefinition(pDataBlock, pObjectType, pCounterDefinition);

                RAW_DATA sample = {
                        .CounterType = pCounterDefinition->CounterType,
                        .Frequency = pDataBlock->PerfFreq.QuadPart,
                };
                if(GetValue(pDataBlock, pObjectType, pCounterDefinition, pCounterBlock, &sample))
                    DisplayCalculatedValue(&sample, &sample);
                else
                    printf("> Cannot get Value of object %d, counter %d", d, c);
            }
        }
    }

cleanup:

    if (g_pPerfDataHead)
        free(g_pPerfDataHead);
}

