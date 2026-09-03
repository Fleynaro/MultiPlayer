#pragma once
#include "AbstractManager.h"
#include <Address/ProcessModule.h>

namespace DB {
	class ProcessModuleMapper;
};

namespace CE
{
	class ProcessModuleManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<ProcessModule>;

		ProcessModuleManager(ProgramModule* module);

		~ProcessModuleManager();

		void loadProcessModules();

		ProcessModule* createProcessModule(HMODULE hModule, const std::string& comment = "");

		ProcessModule* createProcessModule(FS::File file, const std::string& comment = "");

		ProcessModule* getProcessModuleById(DB::Id id);

		ProcessModule* getProcessModuleByName(const std::string& name);

		ProcessModule* findProcessModule(HMODULE hModule);

		ProcessModule* getMainModule();

		std::list<HMODULE> getCurrentlyLoadedModules();
	private:
		ProcessModule* m_mainModule;
		DB::ProcessModuleMapper* m_processModuleMapper;
	};
};