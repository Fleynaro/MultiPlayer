#pragma once
#include <GhidraSync/GhidraAbstractMapper.h>
#include <Code/Variable/GlobalVar.h>

namespace CE {
	class GlobalVarManager;
};

namespace CE::Ghidra
{
	using namespace ghidra;
	using namespace ghidra::variable;

	class DataTypeMapper;

	class GlobalVarMapper : public IMapper
	{
	public:
		GlobalVarMapper(CE::GlobalVarManager* globalVarManager, DataTypeMapper* dataTypeMapper);

		void load(packet::SDataFullSyncPacket* dataPacket) override;

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

	private:
		CE::GlobalVarManager* m_globalVarManager;
		DataTypeMapper* m_dataTypeMapper;

		void changeGvarByDesc(Variable::GlobalVar* gvar, const variable::SGlobalVar& gvarDesc);

		variable::SGlobalVar buildDesc(Variable::GlobalVar* gvar);
	};
};