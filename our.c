#include <windows.h>
#include <winperf.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>
#pragma comment(lib, "advapi32.lib")

#define MAX_INSTANCE_NAME_LEN 4096

typedef struct _rawdata
{
    DWORD CounterType;
    ULONGLONG Data;          // Raw counter data
    LONGLONG Time;           // Is a time value or a base value
    DWORD MultiCounterData;  // Second raw counter value for multi-valued counters
    LONGLONG Frequency;
} RAW_DATA, *PRAW_DATA;

// -----------------------------------------------------------------

typedef struct HashTableEntry {
    char* key;
    DWORD id;
    struct HashTableEntry* next;
} HashTableEntry;

#define HASH_TABLE_SIZE 100000
HashTableEntry* hashTable[HASH_TABLE_SIZE] = { 0 };
HashTableEntry* idArray[HASH_TABLE_SIZE] = { 0 };

unsigned int hashFunction(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    return hash % HASH_TABLE_SIZE;
}

void insertHashTable(const char* key, DWORD id) {
    unsigned int index = hashFunction(key);
    HashTableEntry* entry = malloc(sizeof(HashTableEntry));
    entry->key = strdup(key);
    entry->id = id;
    entry->next = hashTable[index];
    hashTable[index] = entry;

    if(id < HASH_TABLE_SIZE)
        idArray[id] = entry;
}

DWORD findIDByName(const char* key) {
    unsigned int index = hashFunction(key);
    HashTableEntry* entry = hashTable[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0)
            return entry->id;
        entry = entry->next;
    }
    return -1;  // Not found
}

// ----------------------------------------------------------

void readCounterIDs() {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize = 0;
    LONG lStatus;

    // Open the key for the English counters
    lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009"), 0, KEY_READ, &hKey);
    if (lStatus != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to open registry key: %ld\n", lStatus);
        return;
    }

    // Get the size of the 'Counters' data
    lStatus = RegQueryValueEx(hKey, TEXT("Counters"), NULL, &dwType, NULL, &dwSize);
    if (lStatus != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get size of 'Counters' data: %ld\n", lStatus);
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
    lStatus = RegQueryValueEx(hKey, TEXT("Counters"), NULL, &dwType, (LPBYTE)pData, &dwSize);
    if (lStatus != ERROR_SUCCESS || dwType != REG_MULTI_SZ) {
        fprintf(stderr, "Failed to read 'Counters' data or unexpected data type: %ld\n", lStatus);
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
        printf("ID: %u, Name: %s\n", id, name);

        insertHashTable(name, id);

        if(findIDByName(name) != id)
            fprintf(stderr, "Failed to find the name '%s'", name);
    }

    free(pData);
    RegCloseKey(hKey);
}

// --------------------------------------------------------------------------------

struct {
    DWORD bit;
    const char *name;
} types[] = {
    { PERF_SIZE_DWORD, "SIZE_DWORD" },
    { PERF_SIZE_LARGE, "SIZE_LARGE" },
    { PERF_SIZE_ZERO, "SIZE_ZERO" },
    { PERF_SIZE_VARIABLE_LEN, "SIZE_VARIABLE_LEN" },
    { PERF_TYPE_NUMBER, "TYPE_NUMBER" },
    { PERF_TYPE_COUNTER, "TYPE_COUNTER" },
    { PERF_TYPE_TEXT, "TYPE_TEXT" },
    { PERF_TYPE_ZERO, "TYPE_ZERO" },
    { PERF_NUMBER_HEX, "NUMBER_HEX" },
    { PERF_NUMBER_DECIMAL, "NUMBER_DECIMAL" },
    { PERF_NUMBER_DEC_1000, "NUMBER_DEC_1000" },
    { PERF_COUNTER_VALUE, "COUNTER_VALUE" },
    { PERF_COUNTER_RATE, "COUNTER_RATE" },
    { PERF_COUNTER_FRACTION, "COUNTER_FRACTION" },
    { PERF_COUNTER_BASE, "COUNTER_BASE" },
    { PERF_COUNTER_ELAPSED, "COUNTER_ELAPSED" },
    { PERF_COUNTER_QUEUELEN, "COUNTER_QUEUELEN" },
    { PERF_COUNTER_HISTOGRAM, "COUNTER_HISTOGRAM" },
    { PERF_COUNTER_PRECISION, "COUNTER_PRECISION" },
    { PERF_TEXT_UNICODE, "TEXT_UNICODE" },
    { PERF_TEXT_ASCII, "TEXT_ASCII" },
    { PERF_TIMER_TICK, "TIMER_TICK" },
    { PERF_TIMER_100NS, "TIMER_100NS" },
    { PERF_OBJECT_TIMER, "OBJECT_TIMER" },
    { PERF_DELTA_COUNTER, "DELTA_COUNTER" },
    { PERF_DELTA_BASE, "DELTA_BASE" },
    { PERF_INVERSE_COUNTER, "INVERSE_COUNTER" },
    { PERF_MULTI_COUNTER, "MULTI_COUNTER" },
    { PERF_DISPLAY_NO_SUFFIX, "DISPLAY_NO_SUFFIX" },
    { PERF_DISPLAY_PER_SEC, "DISPLAY_PER_SEC" },
    { PERF_DISPLAY_PERCENT, "DISPLAY_PERCENT" },
    { PERF_DISPLAY_SECONDS, "DISPLAY_SECONDS" },
    { PERF_DISPLAY_NOSHOW, "DISPLAY_NOSHOW" },
    { 0, NULL },
};

void printCounterType(DWORD type) {
    for(int i = 0; types[i].name ;i++)
        if(type & types[i].bit)
            printf("%s ", types[i].name);

    printf("\n");
}

void ReadCounterValue(BYTE* pBaseAddress, DWORD dwOffset, DWORD dwCounterType, DWORD dwSize) {
    BYTE* pCounterValue = pBaseAddress + dwOffset;

    // Interpret the value based on the counter size and type
    if (dwCounterType & PERF_TYPE_NUMBER) {
        if (dwCounterType & PERF_NUMBER_DECIMAL) {
            if (dwSize == sizeof(DWORD)) {
                DWORD dwValue = *(DWORD*)pCounterValue;
                printf("Counter Value (Decimal DWORD): %lu\n", dwValue);
            } else if (dwSize == sizeof(ULONGLONG)) {
                ULONGLONG ullValue = *(ULONGLONG*)pCounterValue;
                printf("Counter Value (Decimal ULONGLONG): %llu\n", ullValue);
            }
        } else if (dwCounterType & PERF_NUMBER_HEX) {
            if (dwSize == sizeof(DWORD)) {
                DWORD dwValue = *(DWORD*)pCounterValue;
                printf("Counter Value (Hex DWORD): 0x%X\n", dwValue);
            } else if (dwSize == sizeof(ULONGLONG)) {
                ULONGLONG ullValue = *(ULONGLONG*)pCounterValue;
                printf("Counter Value (Hex ULONGLONG): 0x%llX\n", ullValue);
            }
        }
    } else if (dwCounterType & PERF_TYPE_COUNTER) {
        if (dwCounterType & PERF_COUNTER_RATE) {
            // Assuming rate counters are typically ULONGLONG
            ULONGLONG ullValue = *(ULONGLONG*)pCounterValue;
            printf("Counter Rate: %llu\n", ullValue);
        }
        // Add more specific types as needed, like PERF_COUNTER_FRACTION, PERF_COUNTER_BASE, etc.
    } else {
        printf("Counter ValueX: Unsupported type or size %u\n", dwSize);
    }
}

// Converts a multi-byte string to a Unicode string. If the input string is longer than 
// MAX_INSTANCE_NAME_LEN, the input string is truncated.
BOOL ConvertNameToUnicode(UINT CodePage, LPCSTR pNameToConvert, DWORD dwNameToConvertLen, LPWSTR pConvertedName)
{
    BOOL fSuccess = FALSE;
    int CharsConverted = 0;
    DWORD dwLength = 0;

    // dwNameToConvertLen is in bytes, so convert MAX_INSTANCE_NAME_LEN to bytes.
    dwLength = (MAX_INSTANCE_NAME_LEN*sizeof(WCHAR) < (dwNameToConvertLen)) ? MAX_INSTANCE_NAME_LEN*sizeof(WCHAR) : dwNameToConvertLen;

    CharsConverted = MultiByteToWideChar((UINT)CodePage, 0, pNameToConvert, dwLength, pConvertedName, MAX_INSTANCE_NAME_LEN);
    if (CharsConverted)
    {
        pConvertedName[dwLength] = '\0';
        fSuccess = TRUE;
    }

    return fSuccess;
}

// Retrieve the full name of the instance. The full name of the instance includes
// the name of this instance and its parent instance, if this instance is a 
// child instance. The full name is in the form, "parent name/child name".
// For example, a thread instance is a child of a process instance. 
//
// Providers are encouraged to use Unicode strings for instance names. If 
// PERF_INSTANCE_DEFINITION.CodePage is zero, the name is in Unicode; otherwise,
// use the CodePage value to convert the string to Unicode.
BOOL GetFullInstanceName(PERF_INSTANCE_DEFINITION* pInstance, DWORD CodePage, WCHAR* pName)
{
    BOOL fSuccess = TRUE;
    PERF_INSTANCE_DEFINITION *pParentInstance = NULL;
    PERF_OBJECT_TYPE *pParentObject = NULL;
    DWORD dwLength = 0;
    WCHAR wszInstanceName[MAX_INSTANCE_NAME_LEN+1];
    WCHAR wszParentInstanceName[MAX_INSTANCE_NAME_LEN+1];

    if (CodePage == 0)  // Instance name is a Unicode string
    {
        // PERF_INSTANCE_DEFINITION->NameLength is in bytes, so convert to characters.
        dwLength = (MAX_INSTANCE_NAME_LEN < (pInstance->NameLength/2)) ? MAX_INSTANCE_NAME_LEN : pInstance->NameLength/2;
        StringCchCopyN(wszInstanceName, MAX_INSTANCE_NAME_LEN+1, (LPWSTR)(((LPBYTE)pInstance)+pInstance->NameOffset), dwLength);
        wszInstanceName[dwLength] = '\0';
    }
    else  // Convert the multi-byte instance name to Unicode
    {
        fSuccess = ConvertNameToUnicode(CodePage, 
            (LPCSTR)(((LPBYTE)pInstance)+pInstance->NameOffset),  // Points to string
            pInstance->NameLength,
            wszInstanceName);

        if (FALSE == fSuccess)
        {
            wprintf(L"ConvertNameToUnicode for instance failed.\n");
            goto cleanup;
        }
    }

    if (pInstance->ParentObjectTitleIndex)
    {
        // Use the index to find the parent object. The pInstance->ParentObjectInstance
        // member tells you that the parent instance is the nth instance of the 
        // parent object.
        pParentObject = GetObject(pInstance->ParentObjectTitleIndex);
        pParentInstance = GetParentInstance(pParentObject, pInstance->ParentObjectInstance);

        if (CodePage == 0)  // Instance name is a Unicode string
        {
            dwLength = (MAX_INSTANCE_NAME_LEN < pParentInstance->NameLength/2) ? MAX_INSTANCE_NAME_LEN : pParentInstance->NameLength/2;
            StringCchCopyN(wszParentInstanceName, MAX_INSTANCE_NAME_LEN+1, (LPWSTR)(((LPBYTE)pParentInstance)+pParentInstance->NameOffset), dwLength);
            wszParentInstanceName[dwLength] = '\0';
        }
        else  // Convert the multi-byte instance name to Unicode
        {
            fSuccess = ConvertNameToUnicode(CodePage, 
                (LPCSTR)(((LPBYTE)pParentInstance)+pParentInstance->NameOffset),  //Points to string.
                pInstance->NameLength,
                wszParentInstanceName);

            if (FALSE == fSuccess)
            {
                wprintf(L"ConvertNameToUnicode for parent instance failed.\n");
                goto cleanup;
            }
        }

        StringCchPrintf(pName, MAX_FULL_INSTANCE_NAME_LEN+1, L"%s/%s", wszParentInstanceName, wszInstanceName);
    }
    else
    {
        StringCchPrintf(pName, MAX_INSTANCE_NAME_LEN+1, L"%s", wszInstanceName);
    }

cleanup:

    return fSuccess;
}

void ParsePerformanceData(BYTE* pBuffer) {
    PERF_DATA_BLOCK* pDataBlock = (PERF_DATA_BLOCK*) pBuffer;
    DWORD dwTotalByteLength = pDataBlock->TotalByteLength;

    printf("Total Byte Length: %lu\n", dwTotalByteLength);

    PERF_OBJECT_TYPE* pObjectType = (PERF_OBJECT_TYPE*)((PBYTE)pDataBlock + pDataBlock->HeaderLength);
    while ((PBYTE)pObjectType < pBuffer + dwTotalByteLength) {
        printf("\n--------------------------------------------------------------\n");
        printf("Object Name Title Index: %lu\n", pObjectType->ObjectNameTitleIndex);
        printf("Number of Counters: %lu\n", pObjectType->NumCounters);
        printf("Default Counter: %lu\n", pObjectType->DefaultCounter);

        if(pObjectType->ObjectNameTitleIndex < HASH_TABLE_SIZE) {
            HashTableEntry *titleEntry = idArray[pObjectType->ObjectNameTitleIndex];
            if(titleEntry)
                printf("Object Name: %s\n", titleEntry->key);
        }

        if(pObjectType->NumInstances != PERF_NO_INSTANCES) {
            PERF_INSTANCE_DEFINITION* pInstance = (PERF_INSTANCE_DEFINITION*)((LPBYTE)pObjectType + pObjectType->DefinitionLength);
            for (DWORD i = 0; i < pObjectType->NumInstances; i++) {
                WCHAR *iname[MAX_INSTANCE_NAME_LEN];
                
                if(!GetFullInstanceName(pInstance, pObjectType->CodePage, iname))
                    iname[0] = 0;

                // find the instance name
                printf("Instance Id: %u\n", i);
                printf("Instance Name: %s\n", iname);

                // advance to the next instance
                PERF_COUNTER_BLOCK* pCounterBlock = (PERF_COUNTER_BLOCK*)((LPBYTE)pInstance + pInstance->ByteLength);
                pInstance = (PERF_INSTANCE_DEFINITION*)((LPBYTE)pInstance + pInstance->ByteLength + pCounterBlock->ByteLength);
            }
        }

        // Counter definitions follow the object type
        PERF_COUNTER_DEFINITION* pCounterDef = (PERF_COUNTER_DEFINITION*)((PBYTE)pObjectType + pObjectType->HeaderLength);
        for (DWORD i = 0; i < pObjectType->NumCounters; i++) {
            printf("\n");
            printf("Counter Name Title Index: %lu\n", pCounterDef->CounterNameTitleIndex);
            printf("Counter Help Title Index: %lu\n", pCounterDef->CounterHelpTitleIndex);
            printf("Counter Type: 0x%08x ", pCounterDef->CounterType); printCounterType(pCounterDef->CounterType);
            printf("Counter Size: %lu\n", pCounterDef->CounterSize);
            printf("Counter Offset: %lu\n", pCounterDef->CounterOffset);

            if(pCounterDef->CounterNameTitleIndex < HASH_TABLE_SIZE) {
                HashTableEntry *titleEntry = idArray[pCounterDef->CounterNameTitleIndex];
                if(titleEntry)
                    printf("Counter Name: %s\n", titleEntry->key);
            }

            if(pCounterDef->CounterHelpTitleIndex < HASH_TABLE_SIZE) {
                HashTableEntry *titleEntry = idArray[pCounterDef->CounterHelpTitleIndex];
                if(titleEntry)
                    printf("Counter Help: %s\n", titleEntry->key);
            }

            ReadCounterValue((BYTE *)pObjectType, pCounterDef->CounterOffset, pCounterDef->CounterType, pCounterDef->CounterSize);

            // Move to the next counter definition
            pCounterDef = (PERF_COUNTER_DEFINITION*)((PBYTE)pCounterDef + pCounterDef->ByteLength);
        }

        // Move to the next object type
        if (pObjectType->TotalByteLength != 0) {
            pObjectType = (PERF_OBJECT_TYPE*)((PBYTE)pObjectType + pObjectType->TotalByteLength);
        } else {
            break; // No more objects
        }
    }
}

void QueryPerformanceData(DWORD counterID) {
    LONG lStatus;
    DWORD dwType = REG_BINARY;
    DWORD dwSize = 10*1024*1024;
    BYTE* pBuffer = malloc(dwSize);

    // Convert the numeric ID to a string because registry functions expect LPCTSTR
    TCHAR szCounterID[16];
    sprintf(szCounterID, TEXT("%lu"), counterID);

    // Now query the data itself
    lStatus = RegQueryValueEx(HKEY_PERFORMANCE_DATA, szCounterID, NULL, &dwType, pBuffer, &dwSize);
    if (lStatus != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to query performance data: %ld\n", lStatus);
        free(pBuffer);
        return;
    }

    // Here you would need to parse the binary data format
    // This part is complex and requires understanding the format deeply
    // The parsing logic would go here
    ParsePerformanceData(pBuffer);

    free(pBuffer);
}

int main() {
    readCounterIDs();
    QueryPerformanceData(510);
    return 0;
}

