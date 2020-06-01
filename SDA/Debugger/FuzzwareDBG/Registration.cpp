
#include "Registration.h"
#include <strsafe.h>

HANDLE g_hEventShutdown;
void LockModule()
{
	CoAddRefServerProcess();
}

void UnlockModule()
{
	if(0 == CoReleaseServerProcess())
	{
		// Let any other threads finish what they are doing
		Sleep(2000);
		SetEvent(g_hEventShutdown);
	}
}

const TCHAR* FUZZWAREDBG_CLSID = _T("{8C9991FE-3D7A-4f0b-A62A-0EBD08B0725F}");
const TCHAR* FUZZWAREDBG_NAME = _T("FuzzwareDBG");
const TCHAR* FUZZWAREDBG_PROGID = _T("Fuzzware.FuzzwareDBG.1");

//#define STRING_CONCAT(a, b, c) _T("##a##b##c")

const TCHAR* g_RegTable[][3] = {
	// format is { key, value name, value }
	{ _T("CLSID\\{8C9991FE-3D7A-4f0b-A62A-0EBD08B0725F}"), 0, FUZZWAREDBG_NAME },
	{ _T("CLSID\\{8C9991FE-3D7A-4f0b-A62A-0EBD08B0725F}\\LocalServer32"), 0, (const TCHAR*)-1 }, //rogue value indicating file name
	{ _T("CLSID\\{8C9991FE-3D7A-4f0b-A62A-0EBD08B0725F}\\ProgId"), 0, _T("Fuzzware.FuzzwareDBG.1") },
	{ FUZZWAREDBG_PROGID, 0, FUZZWAREDBG_NAME },
	{ _T("Fuzzware.FuzzwareDBG.1\\CLSID"), 0, FUZZWAREDBG_CLSID },
};

STDAPI DllUnregisterServer(void)
{
	HRESULT hr = S_OK;
	int nEntries = sizeof(g_RegTable)/sizeof(*g_RegTable);

	// We delete in reverse order, as RegDeleteKey cannot delete keys with sub keys
	for(int i = nEntries - 1; i >= 0; i--)
	{
		const TCHAR* pszKeyName		= g_RegTable[i][0];
		
		long err = RegDeleteKey(HKEY_CLASSES_ROOT, pszKeyName);
		if(ERROR_SUCCESS != err)
			hr = S_FALSE;
	}
	return hr;
}

/*
* Reads the value of string registry key, caller needs to free returned string.
* Returns NULL on failure.
*/
TCHAR* ReadRegKeyString(HKEY hKey, const TCHAR* pszKeyName)
{
	long err;
	TCHAR* pcRegKeyValue = NULL;
	DWORD cbRegKeyValue = 0;
	
	// Read the value
	err = RegQueryValueEx(hKey, pszKeyName, NULL, NULL, NULL, &cbRegKeyValue);
	if(ERROR_SUCCESS == err)
	{
		// cbRegKeyValue contains the size of the string in bytes
		pcRegKeyValue = (TCHAR*)malloc( cbRegKeyValue );
		if(NULL != pcRegKeyValue)
		{
			err = RegQueryValueEx(hKey, pszKeyName, NULL, NULL, (LPBYTE)pcRegKeyValue, &cbRegKeyValue);
			if(ERROR_SUCCESS == err)
				return pcRegKeyValue;
		}
	}

	return NULL;
}

/*
* Returns true if the specified registry key already exists and has the specified value
*/
bool RegKeyAlreadyExists(HKEY hRootKey, const TCHAR* pszKeyName, const TCHAR* pszValueName, const TCHAR* pszValue)
{
	HKEY hKey;
	long err;
	TCHAR* pcRegKeyValue = NULL;
	bool bRegKeyExists = false;

	err = RegOpenKeyEx(hRootKey, pszKeyName, 0, KEY_QUERY_VALUE, &hKey);
	if(ERROR_SUCCESS == err)
	{
		// Read the value
		pcRegKeyValue = ReadRegKeyString(hKey, pszValueName);
		if(NULL != pcRegKeyValue)
		{
			// Compare values
			if(_tcslen(pcRegKeyValue) == _tcslen(pszValue))
				if(0 == _tcsncicmp(pcRegKeyValue, pszValue, _tcslen(pcRegKeyValue)))
					bRegKeyExists = true;
			
			free(pcRegKeyValue);
		}
		
		RegCloseKey(hKey);
	}

	return bRegKeyExists;
}

STDAPI DllRegisterServer(void)
{
	HRESULT hr = S_OK;
	
	// Look up servers file name
	TCHAR szFilename[MAX_PATH];
	GetModuleFileName(NULL, szFilename, MAX_PATH);
	
	// Register entries from table
	int nEntries = sizeof(g_RegTable)/sizeof(*g_RegTable);
	for(int i = 0; SUCCEEDED(hr) && i < nEntries; i++)
	{
		const TCHAR* pszKeyName		= g_RegTable[i][0];
		const TCHAR* pszValueName	= g_RegTable[i][1];
		const TCHAR* pszValue		= g_RegTable[i][2];

		// Map rogue value to module file name
		if((const TCHAR*)-1 == pszValue)
			pszValue = szFilename;

		HKEY hKey;

		// Check if the key and its correct value already exist.  We do this as on Vista
		// we will need to elevate to create or change a key in HKEY_CLASSES_ROOT, and
		// since this function might be called often, we want to avoid UAC.
		if(!RegKeyAlreadyExists(HKEY_CLASSES_ROOT, pszKeyName, pszValueName, pszValue))
		{
			// Create the key
			long err = RegCreateKeyEx(HKEY_CLASSES_ROOT, pszKeyName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
			if(ERROR_SUCCESS == err)
			{
				err = RegSetValueEx(hKey, pszValueName, 0, REG_SZ, (const BYTE*)pszValue, (DWORD)(_tcslen(pszValue) + 1));
				RegCloseKey(hKey);
			}
			if(ERROR_SUCCESS != err)
			{
				// If cannot add key or value, back out and fail
				DllUnregisterServer();
				hr = SELFREG_E_CLASS;
			}
		}
	}
	return hr;
}

//STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
//{
//	// Define a singleton class object for each class
//	static FuzzwareDBGClass s_FuzzwareDBGClass;
//
//	// Return interface pointers to known class
//	if(rclsid == CLSID_FuzzwareDBG)
//		return s_FuzzwareDBGClass.QueryInterface(riid, ppv);
//
//	// If we get here, rclsid is a class we don't implement,
//	// so fail with well-known error code
//	*ppv = 0;
//	return CLASS_E_CLASSNOTAVAILABLE;
//}

STDAPI RegisterClassObject()
{
	// For de-registration purposes
	DWORD dwReg;
	// CoRegisterClassObject settings
	const DWORD dwClsCtx = CLSCTX_LOCAL_SERVER;
	const DWORD dwRegCls = REGCLS_MULTIPLEUSE;

	// Define a singleton class object for each class
	static FuzzwareDBGClass s_FuzzwareDBGClass;

	HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	//HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	if(!SUCCEEDED(hr))
		return hr;

	hr = CoRegisterClassObject(CLSID_FuzzwareDBG, static_cast<IUnknown*>(&s_FuzzwareDBGClass), dwClsCtx, dwRegCls, &dwReg);
	if(!SUCCEEDED(hr))
		return hr;

	g_hEventShutdown = CreateEvent(0, TRUE, FALSE, 0);
	WaitForSingleObject(g_hEventShutdown, INFINITE);

	CoRevokeClassObject(dwReg);

	CoUninitialize();

	return S_OK;
}

const TCHAR* pszKeyAeDebug = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug");
const TCHAR* pszSubKeyDebugger = TEXT("Debugger");
const TCHAR* pszSubKeyAuto = TEXT("Auto");
const TCHAR* pszSubKeyDebuggerOld = TEXT("Debugger.preFuzzwareDBG");
const TCHAR* pszSubKeyAutoOld = TEXT("Auto.preFuzzwareDBG");

/*
* The desire here is to
* - Read the current value, if it is already what we are going to set it to, do nothing
* - See if an old value has already been saved ("Debugger.preFuzzwareDBG"), if it has don't overwrite it
* - If no old value, write the current value to the old value
* - Write the new value
*/
HRESULT RegisterPostMortem(TCHAR* pszCommandLine)
{
	HKEY hKey;

	// Check if the key and its correct value already exist.  We do this as on Vista
	// we will need to elevate to create or change a key in HKEY_LOCAL_MACHINE, and
	// since this function might be called often, we want to avoid UAC.
	if(!RegKeyAlreadyExists(HKEY_LOCAL_MACHINE, pszKeyAeDebug, pszSubKeyDebugger, pszCommandLine))
	{
		DWORD dwDisposition;

		// Create the key
		long err = RegCreateKeyEx(HKEY_LOCAL_MACHINE, pszKeyAeDebug, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
		if(ERROR_SUCCESS == err)
		{
			// Get any existing old value ("Debugger.preFuzzwareDBG")
			TCHAR* pszRegKeyOldValue = ReadRegKeyString(hKey, pszSubKeyDebuggerOld);
			// Get any existing current value ("Debugger")
			TCHAR* pszRegKeyCurrentValue = ReadRegKeyString(hKey, pszSubKeyDebugger);
			if((NULL == pszRegKeyOldValue) && (NULL != pszRegKeyCurrentValue))
			{
				// No old value exists so create old key value and set it to the current value
				err = RegSetValueEx(hKey, pszSubKeyDebuggerOld, 0, REG_SZ, (const BYTE*)pszRegKeyCurrentValue, (DWORD)(_tcslen(pszRegKeyCurrentValue) + 1) * sizeof(TCHAR));
				// Ignore return value, we tried ...
			}
			free(pszRegKeyOldValue);		// free can handle NULL pointers
			free(pszRegKeyCurrentValue);

			// We have stored any old values, so lets write our new value
			err = RegSetValueEx(hKey, pszSubKeyDebugger, 0, REG_SZ, (const BYTE*)pszCommandLine, (DWORD)(_tcslen(pszCommandLine) + 1) * sizeof(TCHAR));
			
			RegCloseKey(hKey);
		}
		if(ERROR_SUCCESS != err)
		{
			// If cannot add key or value, back out and fail
			UnregisterPostMortem();
			return E_FAIL;
		}
	}

	// Do the same for the 'Auto' key
	if(!RegKeyAlreadyExists(HKEY_LOCAL_MACHINE, pszKeyAeDebug, pszSubKeyAuto, TEXT("1")))
	{
		DWORD dwDisposition;

		// Create the key
		long err = RegCreateKeyEx(HKEY_LOCAL_MACHINE, pszKeyAeDebug, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
		if(ERROR_SUCCESS == err)
		{
			// Get any existing old value ("Auto.preFuzzwareDBG")
			TCHAR* pszRegKeyOldValue = ReadRegKeyString(hKey, pszSubKeyAutoOld);
			// Get any existing current value ("Auto")
			TCHAR* pszRegKeyCurrentValue = ReadRegKeyString(hKey, pszSubKeyAuto);
			if((NULL == pszRegKeyOldValue) && (NULL != pszRegKeyCurrentValue))
			{
				// No old value exists so create old key value and set it to the current value
				err = RegSetValueEx(hKey, pszSubKeyAutoOld, 0, REG_SZ, (const BYTE*)pszRegKeyCurrentValue, (DWORD)(_tcslen(pszRegKeyCurrentValue) + 1) * sizeof(TCHAR));
				// Ignore return value, we tried ...
			}
			free(pszRegKeyOldValue);		// free can handle NULL pointers
			free(pszRegKeyCurrentValue);

			// We have stored any old values, so lets write our new value
			err = RegSetValueEx(hKey, pszSubKeyAuto, 0, REG_SZ, (const BYTE*)TEXT("1"), (DWORD)(_tcslen(TEXT("1")) + 1) * sizeof(TCHAR));
			
			RegCloseKey(hKey);
		}
		if(ERROR_SUCCESS != err)
		{
			// If cannot add key or value, back out and fail
			UnregisterPostMortem();
			return E_FAIL;
		}
	}

	return S_OK;
}

/*
* The desire here is to
* - Assume we only unreg if we successfully reg, so always delete current value, if there is one
* - Restore any old value if there is one
*/
HRESULT UnregisterPostMortem()
{
	HKEY hKey;
	
	// Open the 'AeDebug' key
	long err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, pszKeyAeDebug, 0, KEY_QUERY_VALUE, &hKey);
	if(ERROR_SUCCESS == err)
	{
		// Get any existing old value ("Debugger.preFuzzwareDBG")
		TCHAR* pszRegKeyOldValue = ReadRegKeyString(hKey, pszSubKeyDebuggerOld);
		// Get any existing current value ("Debugger")
		TCHAR* pszRegKeyCurrentValue = ReadRegKeyString(hKey, pszSubKeyDebugger);
		
		if( (NULL != pszRegKeyOldValue) || (NULL != pszRegKeyCurrentValue))
		{
			// There is either an old value we need to restore or a current value we need to delete.
			// Either way open the registry key for editting
			RegCloseKey(hKey);
			err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, pszKeyAeDebug, 0, KEY_ALL_ACCESS, &hKey);
			if(ERROR_SUCCESS != err)
				return E_FAIL;	
		}

		// If there is a current value, delete it
		if(NULL != pszRegKeyCurrentValue)
		{
			err = RegDeleteValue(hKey, pszSubKeyDebugger);
		}

		// If there is an old value, restore its value, and delete the old value
		if(NULL != pszRegKeyOldValue)
		{
			err = RegSetValueEx(hKey, pszSubKeyDebugger, 0, REG_SZ, (BYTE*)pszRegKeyOldValue, (DWORD)(_tcslen(pszRegKeyOldValue) + 1) * sizeof(TCHAR));
			err = RegDeleteValue(hKey, pszSubKeyDebuggerOld);
		}
		free(pszRegKeyOldValue);
		free(pszRegKeyCurrentValue);

		// Get any existing old value ("Auto.preFuzzwareDBG")
		pszRegKeyOldValue = ReadRegKeyString(hKey, pszSubKeyAutoOld);
		// Get any existing current value ("Auto")
		pszRegKeyCurrentValue = ReadRegKeyString(hKey, pszSubKeyAuto);
		
		if( (NULL != pszRegKeyOldValue) || (NULL != pszRegKeyCurrentValue))
		{
			// There is either an old value we need to restore or a current value we need to delete.
			// Either way open the registry key for editting
			RegCloseKey(hKey);
			err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, pszKeyAeDebug, 0, KEY_ALL_ACCESS, &hKey);
			if(ERROR_SUCCESS != err)
				return E_FAIL;	
		}

		// If there is a current value, delete it
		if(NULL != pszRegKeyCurrentValue)
		{
			err = RegDeleteValue(hKey, pszSubKeyAuto);
		}

		// If there is an old value, restore its value, and delete the old value
		if(NULL != pszRegKeyOldValue)
		{
			err = RegSetValueEx(hKey, pszSubKeyAuto, 0, REG_SZ, (BYTE*)pszRegKeyOldValue, (DWORD)(_tcslen(pszRegKeyOldValue) + 1) * sizeof(TCHAR));
			err = RegDeleteValue(hKey, pszSubKeyAutoOld);
		}
		free(pszRegKeyOldValue);
		free(pszRegKeyCurrentValue);
	}
	else
		return E_FAIL;

	return S_OK;
}
