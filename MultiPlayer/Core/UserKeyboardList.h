#pragma once

#include "main.h"

class KeyboardLayout
{
public:
	KeyboardLayout(std::string name, HKL handle)
		: m_name(name), m_handle(handle)
	{}

	std::string getEngName() {
		return m_name;
	}

	HKL getHandle() {
		return m_handle;
	}

	void makeCurrent() {
		ActivateKeyboardLayout(getHandle(), KLF_ACTIVATE);
	}
private:
	std::string m_name;
	HKL m_handle;
};

class UserKeyboardList
{
public:
	static void init()
	{
		UINT uLayouts;
		HKL* lpList = NULL;
		char szBuf[256];

		uLayouts = GetKeyboardLayoutList(0, NULL);
		lpList = (HKL*)LocalAlloc(LPTR, (uLayouts * sizeof(HKL)));
		uLayouts = GetKeyboardLayoutList(uLayouts, lpList);

		for (UINT i = 0; i < uLayouts; ++i) {
			GetLocaleInfoA(
				MAKELCID((DWORD)(std::uintptr_t)lpList[i], SORT_DEFAULT),
				LOCALE_SENGLANGUAGE,
				szBuf, 256
			);

			m_keyboards.push_back(new KeyboardLayout(
				szBuf,
				lpList[i]
			));
			memset(szBuf, 0, 256);
		}

		if (lpList)
			LocalFree(lpList);
	}

	static auto& getItems() {
		return m_keyboards;
	}

	static int getCount() {
		return (int)getItems().size();
	}

	static KeyboardLayout& getCurrent(DWORD thread = 0) {
		for (auto it : getItems()) {
			if (it->getHandle() == GetKeyboardLayout(thread)) {
				return *it;
			}
		}
	}

	static int getCurrentId(DWORD thread = 0) {
		int i = 0;
		for (auto it : getItems()) {
			if (it->getHandle() == GetKeyboardLayout(thread)) {
				return i;
			}
			i++;
		}
		return -1;
	}

	static void switchToNext() {
		//ActivateKeyboardLayout((HKL)HKL_NEXT, 0);
		int curId = getCurrentId();
		if (curId != -1) {
			curId++;
			if (curId == getCount())
				curId = 0;
			getItems()[curId]->makeCurrent();
		}
	}
private:
	inline static std::vector<KeyboardLayout*> m_keyboards;
};