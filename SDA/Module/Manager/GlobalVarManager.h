#pragma once
#include "AbstractManager.h"
#include <Code/Variable/GlobalVar.h>

namespace DB {
	class GlobalVarMapper;
};

namespace CE::Ghidra {
	class GlobalVarMapper;
};

namespace CE
{
	class GlobalVarManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Variable::GlobalVar>;
		Ghidra::GlobalVarMapper* m_ghidraGlobalVarMapper;

		GlobalVarManager(ProgramModule* module);

		void loadGlobalVars();

		void loadGlobalVarsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket);

		Variable::GlobalVar* createGlobalVar(ProcessModule* module, void* addr, const std::string& name, const std::string& comment = "");

		Variable::GlobalVar* getGlobalVarById(DB::Id id);

	private:
		DB::GlobalVarMapper* m_globalVarMapper;
	};
};