#pragma once
#include <GhidraSync/GhidraAbstractMapper.h>
#include <Code/Function/FunctionDefinition.h>

namespace CE {
	class FunctionManager;
};

namespace CE::Ghidra
{
	using namespace ghidra;
	using namespace ghidra::function;

	class DataTypeMapper;

	class FunctionDefMapper : public IMapper
	{
	public:
		FunctionDefMapper(CE::FunctionManager* functionManager, DataTypeMapper* dataTypeMapper);

		void load(packet::SDataFullSyncPacket* dataPacket) override;

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

	private:
		CE::FunctionManager* m_functionManager;
		DataTypeMapper* m_dataTypeMapper;
		
		AddressRangeList getRangesFromDesc(const std::vector<function::SFunctionRange>& rangeDescs);

		void changeFunctionByDesc(Function::Function* function, const function::SFunction& funcDesc);

		function::SFunction buildDescToRemove(Function::Function* function);

		function::SFunction buildDesc(Function::Function* function);
	};
};