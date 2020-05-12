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
		using Iterator = AbstractIterator<ProccessModule>;

		ProcessModuleManager(ProgramModule* module);

		~ProcessModuleManager();

		void loadProcessModules();

		ProccessModule* createProcessModule(const std::string& name, const std::string& comment = "");

		ProccessModule* getProcessModuleById(DB::Id id);

		ProccessModule* getProcessModuleByName(const std::string& name);

		ProccessModule* getMainModule();
	private:
		ProccessModule* m_mainModule;
		DB::ProcessModuleMapper* m_proccessModuleMapper;
	};
};