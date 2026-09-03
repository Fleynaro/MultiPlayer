#pragma once
#include "AddressRange.h"
#include <DB/DomainObject.h>
#include <Utils/Description.h>
#include <Utility/FileWrapper.h>

namespace CE
{
	int GetModuleSize(HMODULE module);

	class ProcessModuleManager;

	class ProcessModule : public AddressRange, public DB::DomainObject, public Descrtiption
	{
	public:
		ProcessModule(ProcessModuleManager* manager, HMODULE module, const std::string& name = "", const std::string& comment = "");

		std::uintptr_t getBaseAddr();

		void* toAbsAddr(int offset);

		int toRelAddr(void* addr);

		FS::File getFile();

		HMODULE getHModule();

		ProcessModuleManager* getManager();

		std::list<std::pair<std::string, void*>> getExportedFunctions();

	private:
		ProcessModuleManager* m_manager;
	};

	std::list<std::pair<std::string, void*>> GetProcessModuleExportedFunctions(HMODULE hModule);
};