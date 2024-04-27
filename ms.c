#define _UNICODE 1
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define _wcsnicmp_compat(str1, str2, num) wcsncasecmp(str1, str2, num)
#define _wtoi_compat(wstr) (int)wcstol(wstr, NULL, 10)
#define StringCchCopyN_compat(dst, dst_len, src, src_len)  do { \
    size_t _len = (dst_len) < (src_len) ? (dst_len) : (src_len); \
    memcpy(dst, src, _len); \
    if(_len < dst_len) \
        dst[_len] = '\0'; \
    else \
        dst[(dst_len) - 1] = '\0'; \
} while(0)

// Contains the elements required to calculate a counter value.
typedef struct _rawdata
{
    DWORD CounterType;
    ULONGLONG Data;          // Raw counter data
    LONGLONG Time;           // Is a time value or a base value
    DWORD MultiCounterData;  // Second raw counter value for multi-valued counters
    LONGLONG Frequency;
}RAW_DATA, *PRAW_DATA;

#define INIT_OBJECT_BUFFER_SIZE 48928   // Initial buffer size to use when querying specific objects.
#define INIT_GLOBAL_BUFFER_SIZE 122880  // Initial buffer size to use when using "Global" to query all objects.
#define BUFFER_INCREMENT 16384          // Increment buffer size in 16K chunks.
#define MAX_INSTANCE_NAME_LEN      255  // Max length of an instance name.
#define MAX_FULL_INSTANCE_NAME_LEN 511  // Form is parentinstancename/instancename#nnn.

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

const char *findNameByID(DWORD id) {
    if(id < HASH_TABLE_SIZE) {
        HashTableEntry *titleEntry = idArray[id];
        if(titleEntry)
            return titleEntry->key;
    }
    return "";
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


LPBYTE GetPerformanceData(LPCSTR pwszSource, DWORD dwInitialBufferSize);
BOOL GetCounterValues(DWORD dwObjectIndex, DWORD dwCounterIndex, LPWSTR pInstanceName, RAW_DATA* pRawData);
BOOL GetValue(PERF_OBJECT_TYPE* pObject, PERF_COUNTER_DEFINITION* pCounter, PERF_COUNTER_BLOCK* pCounterDataBlock, PRAW_DATA pRawData);
PERF_COUNTER_BLOCK* GetCounterBlock(PERF_OBJECT_TYPE* pObject, LPWSTR pInstanceName);
PERF_COUNTER_DEFINITION* GetCounter(PERF_OBJECT_TYPE* pObject, DWORD dwCounterToFind);
PERF_OBJECT_TYPE* getObject(DWORD dwObjectToFind);
PERF_INSTANCE_DEFINITION* getObjectInstance(PERF_OBJECT_TYPE* pObject, LPWSTR pInstanceName);
DWORD GetSerialNo(LPWSTR pInstanceName);
BOOL GetFullInstanceName(PERF_INSTANCE_DEFINITION* pInstance, DWORD CodePage, WCHAR* pName);
BOOL ConvertNameToUnicode(UINT CodePage, LPCSTR pNameToConvert, DWORD dwNameToConvertLen, LPWSTR pConvertedName);
PERF_INSTANCE_DEFINITION* GetParentInstance(PERF_OBJECT_TYPE* pObject, DWORD dwInstancePosition);
BOOL DisplayCalculatedValue(RAW_DATA* pSample1, RAW_DATA* pSample2);

//Global variables
LPBYTE g_pPerfDataHead = NULL;   // Head of the performance data.

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
    if (pBuffer)
    {
        while (ERROR_MORE_DATA == (status = RegQueryValueEx(HKEY_PERFORMANCE_DATA, pwszSource, NULL, NULL, pBuffer, &dwSize)))
        {
            //Contents of dwSize is unpredictable if RegQueryValueEx fails, which is why
            //you need to increment dwBufferSize and use it to set dwSize.
            dwBufferSize += BUFFER_INCREMENT;

            pTemp = (LPBYTE)realloc(pBuffer, dwBufferSize);
            if (pTemp)
            {
                pBuffer = pTemp;
                dwSize = dwBufferSize;
            }
            else
            {
                wprintf(L"Reallocation error.\n");
                free(pBuffer);
                pBuffer = NULL;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"RegQueryValueEx failed with 0x%x.\n", status);
            free(pBuffer);
            pBuffer = NULL;
        }
    }
    else
    {
        wprintf(L"malloc failed to allocate initial memory request.\n");
    }

cleanup:

    RegCloseKey(HKEY_PERFORMANCE_DATA);

    return pBuffer;
}


// Use the object index to find the object in the performance data. Then, use the
// counter index to find the counter definition. The definition contains the offset
// to the counter data in the counter block. The location of the counter block 
// depends on whether the counter is a single instance counter or multiple instance counter.
// After finding the counter block, retrieve the counter data.
BOOL GetCounterValues(DWORD dwObjectIndex, DWORD dwCounterIndex, LPWSTR pInstanceName, RAW_DATA* pRawData)
{
    PERF_OBJECT_TYPE* pObject = NULL;
    PERF_COUNTER_DEFINITION* pCounter = NULL;
    PERF_COUNTER_BLOCK* pCounterDataBlock = NULL;
    BOOL fSuccess = FALSE;

    pObject = getObject(dwObjectIndex);
    if (NULL == pObject)
    {
        wprintf(L"Object  %d not found.\n", dwObjectIndex);
        goto cleanup;
    }

    pCounter = GetCounter(pObject, dwCounterIndex);
    if (NULL == pCounter)
    {
        wprintf(L"Counter %d not found.\n", dwCounterIndex);
        goto cleanup;
    }

    // Retrieve a pointer to the beginning of the counter data block. The counter data
    // block contains all the counter data for the object.
    pCounterDataBlock = GetCounterBlock(pObject, pInstanceName);
    if (NULL == pCounterDataBlock)
    {
        wprintf(L"Instance %s not found.\n", pInstanceName);
        goto cleanup;
    }

    ZeroMemory(pRawData, sizeof(RAW_DATA));
    pRawData->CounterType = pCounter->CounterType;
    fSuccess = GetValue(pObject, pCounter, pCounterDataBlock, pRawData);

cleanup:

    return fSuccess;
}


// Use the object index to find the object in the performance data.
PERF_OBJECT_TYPE* getObject(DWORD dwObjectToFind)
{
    LPBYTE pObject = g_pPerfDataHead + ((PERF_DATA_BLOCK*)g_pPerfDataHead)->HeaderLength;
    DWORD dwNumberOfObjects = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->NumObjectTypes;
    BOOL fFoundObject = FALSE;

    for (DWORD i = 0; i < dwNumberOfObjects; i++)
    {
        if (dwObjectToFind == ((PERF_OBJECT_TYPE*)pObject)->ObjectNameTitleIndex)
        {
            fFoundObject = TRUE;
            break;
        }

        pObject += ((PERF_OBJECT_TYPE*)pObject)->TotalByteLength;
    }

    return (fFoundObject) ? (PERF_OBJECT_TYPE*)pObject : NULL;  
}

// Use the counter index to find the object in the performance data.
PERF_COUNTER_DEFINITION* GetCounter(PERF_OBJECT_TYPE* pObject, DWORD dwCounterToFind)
{
    PERF_COUNTER_DEFINITION* pCounter = (PERF_COUNTER_DEFINITION*)((LPBYTE)pObject + pObject->HeaderLength);
    DWORD dwNumberOfCounters = pObject->NumCounters;
    BOOL fFoundCounter = FALSE;

    for (DWORD i = 0; i < dwNumberOfCounters; i++)
    {
        if (pCounter->CounterNameTitleIndex == dwCounterToFind)
        {
            fFoundCounter = TRUE;
            break;
        }

        pCounter++;
    }

    return (fFoundCounter) ? pCounter : NULL;
}


// Returns a pointer to the beginning of the PERF_COUNTER_BLOCK. The location of the 
// of the counter data block depends on whether the object contains single instance
// counters or multiple instance counters (see PERF_OBJECT_TYPE.NumInstances).
PERF_COUNTER_BLOCK* GetCounterBlock(PERF_OBJECT_TYPE* pObject, LPWSTR pInstanceName)
{
    PERF_COUNTER_BLOCK* pBlock = NULL;
    PERF_INSTANCE_DEFINITION* pInstance = NULL;

    // If there are no instances, the block follows the object and counter structures.
    if (0 == pObject->NumInstances || PERF_NO_INSTANCES == pObject->NumInstances) 
    {                                
        pBlock = (PERF_COUNTER_BLOCK*)((LPBYTE)pObject + pObject->DefinitionLength);
    }
    else if (pObject->NumInstances > 0 && pInstanceName)  // Find the instance. The block follows the instance
    {                                                     // structure and instance name.
        pInstance = getObjectInstance(pObject, pInstanceName);
        if (pInstance)
        {
            pBlock = (PERF_COUNTER_BLOCK*)((LPBYTE)pInstance + pInstance->ByteLength);
        }
    }

    return pBlock;
}


// If the instance names are unique (there will never be more than one instance
// with the same name), then finding the same instance is not an issue. However, 
// if the instance names are not unique, there is no guarantee that the instance 
// whose counter value you are retrieving is the same instance from which you previously
// retrieved data. This function expects the instance name to be well formed. For 
// example, a process object could have four instances with each having svchost as its name.
// Since service hosts come and go, there is no way to determine if you are dealing with 
// the same instance.
// Starting in Windows 11, use the "Process V2" counterset to avoid this issue.
//
// The convention for specifying an instance is parentinstancename/instancename#nnn.
// If only instancename is specified, the first instance found that matches the name is used.
// Specify parentinstancename if the instance is the child of a parent instance.
PERF_INSTANCE_DEFINITION* getObjectInstance(PERF_OBJECT_TYPE* pObject, LPWSTR pInstanceName)
{
    PERF_INSTANCE_DEFINITION* pInstance = (PERF_INSTANCE_DEFINITION*)((LPBYTE)pObject + pObject->DefinitionLength);
    BOOL fSuccess = FALSE;
    WCHAR szName[MAX_FULL_INSTANCE_NAME_LEN + 1];
    PERF_COUNTER_BLOCK* pCounterBlock = NULL;
    DWORD dwSerialNo = GetSerialNo(pInstanceName);
    DWORD dwOccurrencesFound = 0;
    DWORD dwNameLen = 0;
    DWORD dwInputNameLen = (DWORD)wcslen(pInstanceName);

    for (LONG i = 0; i < pObject->NumInstances; i++)
    {
        GetFullInstanceName(pInstance, pObject->CodePage, szName);
        if ((dwNameLen = (DWORD)wcslen(szName)) <= dwInputNameLen)
        {
            if (0 == _wcsnicmp_compat(szName, pInstanceName, dwNameLen))  // The name matches
            {
                dwOccurrencesFound++;

                // If the input name does not specify an nth instance or
                // the nth instance has been found, return the instance.
                // It is 'dwSerialNo+1' because cmd#3 is the fourth occurrence.
                if (0 == dwSerialNo || dwOccurrencesFound == (dwSerialNo+1))
                {
                    return pInstance;
                }
            }
        }

        pCounterBlock = (PERF_COUNTER_BLOCK*)((LPBYTE)pInstance + pInstance->ByteLength);
        pInstance = (PERF_INSTANCE_DEFINITION*)((LPBYTE)pInstance + pInstance->ByteLength + pCounterBlock->ByteLength);
    }

    return NULL;
}


// Parses the instance name for the serial number. The convention is to use
// a serial number appended to the instance name to identify a specific
// instance when the instance names are not unique. For example, to specify
// the fourth instance of svchost, use svchost#3 (the first occurrence does
// not include a serial number).
DWORD GetSerialNo(LPWSTR pInstanceName)
{
    LPWSTR pSerialNo = NULL;
    DWORD dwLength = 0;
    DWORD value = 0;

    pSerialNo = wcschr(pInstanceName, '#');
    if (pSerialNo)
    {
        pSerialNo++;
        value = _wtoi_compat(pSerialNo);
    }

    return value;
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
        StringCchCopyN_compat(wszInstanceName, MAX_INSTANCE_NAME_LEN+1, (LPWSTR)(((LPBYTE)pInstance)+pInstance->NameOffset), dwLength);
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
            printf("ConvertNameToUnicode() for instance failed.\n");
            goto cleanup;
        }
    }

    if (pInstance->ParentObjectTitleIndex)
    {
        // Use the index to find the parent object. The pInstance->ParentObjectInstance
        // member tells you that the parent instance is the nth instance of the 
        // parent object.
        pParentObject = getObject(pInstance->ParentObjectTitleIndex);
        pParentInstance = GetParentInstance(pParentObject, pInstance->ParentObjectInstance);

        if (CodePage == 0)  // Instance name is a Unicode string
        {
            dwLength = (MAX_INSTANCE_NAME_LEN < pParentInstance->NameLength/2) ? MAX_INSTANCE_NAME_LEN : pParentInstance->NameLength/2;
            StringCchCopyN_compat(wszParentInstanceName, MAX_INSTANCE_NAME_LEN+1, (LPWSTR)(((LPBYTE)pParentInstance)+pParentInstance->NameOffset), dwLength);
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
                printf("ConvertNameToUnicode for parent instance failed.\n");
                goto cleanup;
            }
        }

        snprintf(pName, MAX_FULL_INSTANCE_NAME_LEN+1, "%ls/%ls", wszParentInstanceName, wszInstanceName);
    }
    else
    {
        snprintf(pName, MAX_INSTANCE_NAME_LEN+1, "%ls", wszInstanceName);
    }

cleanup:

    return fSuccess;
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


// Find the nth instance of an object.
PERF_INSTANCE_DEFINITION* GetParentInstance(PERF_OBJECT_TYPE* pObject, DWORD dwInstancePosition)
{
    LPBYTE pInstance = (LPBYTE)pObject + pObject->DefinitionLength;
    PERF_COUNTER_BLOCK* pCounter = NULL;

    for (DWORD i = 0; i < dwInstancePosition; i++)
    {
        pCounter = (PERF_COUNTER_BLOCK*)(pInstance + ((PERF_INSTANCE_DEFINITION*)pInstance)->ByteLength);
        pInstance += ((PERF_INSTANCE_DEFINITION*)pInstance)->ByteLength + pCounter->ByteLength;
    }

    return (PERF_INSTANCE_DEFINITION*)pInstance;
}

// --------------------------------------------------------------------------------------------------------------------

// Retrieve the raw counter value and any supporting data needed to calculate
// a displayable counter value. Use the counter type to determine the information
// needed to calculate the value.
BOOL GetValue(PERF_OBJECT_TYPE* pObject, 
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
        pRawData->Time = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfTime.QuadPart;
        if (PERF_COUNTER_COUNTER == pCounter->CounterType || PERF_SAMPLE_COUNTER == pCounter->CounterType)
        {
            pRawData->Frequency = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfFreq.QuadPart;
        }
        break;

    case PERF_OBJ_TIME_TIMER:
        pRawData->Data = (ULONGLONG)(*(DWORD*)pData);
        pRawData->Time = pObject->PerfTime.QuadPart;
        break;

    case PERF_COUNTER_100NS_QUEUELEN_TYPE:
        pRawData->Data = *(UNALIGNED ULONGLONG *)pData;
        pRawData->Time = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfTime100nSec.QuadPart;
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
        pRawData->Time = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfTime.QuadPart;
        if (pCounter->CounterType == PERF_COUNTER_BULK_COUNT)
        {
            pRawData->Frequency = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfFreq.QuadPart;
        }
        break;

    case PERF_COUNTER_MULTI_TIMER:
    case PERF_COUNTER_MULTI_TIMER_INV:
        pullData = (UNALIGNED ULONGLONG *)pData;
        pRawData->Data = *pullData;
        pRawData->Frequency = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfFreq.QuadPart;
        pRawData->Time = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfTime.QuadPart;

        //These counter types have a second counter value that is adjacent to
        //this counter value in the counter data block. The value is needed for
        //the calculation.
        if ((pCounter->CounterType & PERF_MULTI_COUNTER) == PERF_MULTI_COUNTER)
        {
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
        pRawData->Time = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfTime100nSec.QuadPart;

        //These counter types have a second counter value that is adjacent to
        //this counter value in the counter data block. The value is needed for
        //the calculation.
        if ((pCounter->CounterType & PERF_MULTI_COUNTER) == PERF_MULTI_COUNTER)
        {
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
        pBaseCounter = pCounter+1;  //Get base counter
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE)
        {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = (LONGLONG)(*(DWORD*)pData);
        }
        else
        {
            fSuccess = FALSE;
        }
        break;

    case PERF_LARGE_RAW_FRACTION:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pBaseCounter = pCounter+1;
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE)
        {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = *(LONGLONG*)pData;
        }
        else
        {
            fSuccess = FALSE;
        }
        break;

    case PERF_PRECISION_SYSTEM_TIMER:
    case PERF_PRECISION_100NS_TIMER:
    case PERF_PRECISION_OBJECT_TIMER:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pBaseCounter = pCounter+1;
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE)
        {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = *(LONGLONG*)pData;
        }
        else
        {
            fSuccess = FALSE;
        }
        break;

    case PERF_AVERAGE_TIMER:
    case PERF_AVERAGE_BULK:
        pRawData->Data = *(UNALIGNED ULONGLONG*)pData;
        pBaseCounter = pCounter+1;
        if ((pBaseCounter->CounterType & PERF_COUNTER_BASE) == PERF_COUNTER_BASE)
        {
            pData = (PVOID)((LPBYTE)pCounterDataBlock + pBaseCounter->CounterOffset);
            pRawData->Time = *(DWORD*)pData;
        }
        else
        {
            fSuccess = FALSE;
        }

        if (pCounter->CounterType == PERF_AVERAGE_TIMER)
        {
            pRawData->Frequency = ((PERF_DATA_BLOCK*)g_pPerfDataHead)->PerfFreq.QuadPart;
        }
        break;

    //These are base counters and are used in calculations for other counters.
    //This case should never be entered.
    case PERF_SAMPLE_BASE:
    case PERF_AVERAGE_BASE:
    case PERF_COUNTER_MULTI_BASE:
    case PERF_RAW_BASE:
    case PERF_LARGE_RAW_BASE:
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
        pRawData->Data = 0;
        pRawData->Time = 0;
        fSuccess = FALSE;
        break;

    //Encountered an unidentified counter.
    default:
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
        printf("Display value is (counter): %lu%s\n", dwordValue,
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

// -------------------------------------------------------------------------------------------------------------------

void txtCopy(char *dst, size_t dst_len, char *src, size_t src_len) {
    size_t len = dst_len - 1 < src_len ? dst_len - 1: src_len;
    memcpy(dst, src, len);
    dst[len] = '\0';
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
        printf("> Invalid ObjectType!\n");
        pObjectType = NULL;
    }

    return pObjectType;
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
    PERF_COUNTER_BLOCK *pCounterBlock = (PERF_COUNTER_BLOCK *)((PBYTE)pInstance + pInstance->ByteLength);

    if(pCounterBlock && (!isValidPointer(pDataBlock, pCounterBlock) || !isValidStructure(pDataBlock, pCounterBlock, pCounterBlock->ByteLength))) {
        printf("> Invalid Instance CounterBlock!\n");
        pCounterBlock = NULL;
    }

    return pCounterBlock;
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
}

void printObjectType(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType) {
    (void)pDataBlock;

    printf("\n   --------------------------------------------------------------\n");
    printf("   Object Type\n");
    printf("   Number of Instances: %d\n", pObjectType->NumInstances);
    printf("   Number of Counters: %d\n", pObjectType->NumCounters);
    printf("   Title: %s\n", findNameByID(pObjectType->ObjectNameTitleIndex));
    printf("   Help: %s\n", findNameByID(pObjectType->ObjectHelpTitleIndex));
}

BOOL getInstanceName(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType, PERF_INSTANCE_DEFINITION *pInstance,
                     char *buffer, size_t bufferLen) {
    if (!pInstance || !buffer || !bufferLen) return FALSE;

    // Convert WCHAR to CHAR
    WCHAR *uniName = (WCHAR *)((char*)pInstance + pInstance->NameOffset);
    int nameLen = pInstance->NameLength / sizeof(WCHAR);  // Number of WCHARs

    // Use WideCharToMultiByte to convert Unicode to ANSI
    int bytesCopied = WideCharToMultiByte(CP_ACP, 0, uniName, nameLen, buffer, (int)bufferLen, NULL, NULL);

    if (bytesCopied == 0) {
        // Handle the error, perhaps buffer is too small or an invalid character was encountered
        buffer[0] = '\0'; // Ensure the buffer is null-terminated even on failure
        return FALSE;
    }

    // Ensure buffer is null-terminated
    buffer[bytesCopied] = '\0';

    return TRUE;
}

void printInstance(PERF_DATA_BLOCK *pDataBlock, PERF_OBJECT_TYPE *pObjectType, PERF_INSTANCE_DEFINITION *pInstance) {
    char name[4096];
    if(!getInstanceName(pDataBlock, pObjectType, pInstance, name, sizeof(name)))
        strncpy(name, "[failed]", sizeof(name));

    printf("\n      --------------------------------------------------------------\n");
    printf("      Instance Definition\n");
    printf("      Unique ID %d\n", pInstance->UniqueID);
    printf("      Object Title: %s\n", findNameByID(pObjectType->ObjectNameTitleIndex));
    printf("      Object Help: %s\n", findNameByID(pObjectType->ObjectHelpTitleIndex));
    printf("      Name: %s\n", name);
}

int main(void)
{
    readCounterIDs();

    // Retrieve counter data for the Processor object.
    g_pPerfDataHead = (LPBYTE)GetPerformanceData("510", INIT_OBJECT_BUFFER_SIZE);
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
    for(int d = 0; d < pDataBlock->NumObjectTypes; d++) {
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
                for(int c = 0; c < pObjectType->NumCounters ;c++) {
                    pCounterDefinition = getCounterDefinition(pDataBlock, pObjectType, pCounterDefinition);
                    if(!pCounterDefinition) {
                        printf("> Cannot read counter definition No %u (out of %u)\n", c, pObjectType->NumCounters);
                        break;
                    }

                    RAW_DATA sample = {
                            .CounterType = pCounterDefinition->CounterType,
                    };
                    if(GetValue(pObjectType, pCounterDefinition, pCounterBlock, &sample))
                        DisplayCalculatedValue(&sample, NULL);
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

                RAW_DATA sample = {
                        .CounterType = pCounterDefinition->CounterType,
                };
                if(GetValue(pObjectType, pCounterDefinition, pCounterBlock, &sample))
                    DisplayCalculatedValue(&sample, NULL);
                else
                    printf("> Cannot get Value of object %d, counter %d", d, c);
            }
        }
    }

cleanup:

    if (g_pPerfDataHead)
        free(g_pPerfDataHead);
}

