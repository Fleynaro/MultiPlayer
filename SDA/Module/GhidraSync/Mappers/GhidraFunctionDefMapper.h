#pragma once
#include <GhidraSync/GhidraAbstractMapper.h>
#include "FunctionManagerService.h"

namespace CE {
	class FunctionManager;

	namespace Function {
		class Function;
	};
};

namespace CE::Ghidra
{
	using namespace ghidra;
	using namespace ghidra::function;

	class FunctionDefMapper : public IMapper
	{
	public:
		FunctionDefMapper(CE::FunctionManager* functionManager);

		void load(DataPacket* dataPacket) override;

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

	private:
		CE::FunctionManager* m_functionManager;
		
		AddressRangeList getRangesFromDesc(const std::vector<function::SFunctionRange>& rangeDescs);

		void changeFunctionByDesc(Function::Function* function, const function::SFunction& funcDesc);

		function::SFunction buildDescToRemove(Function::Function* function);

		function::SFunction buildDesc(Function::Function* function);
	};
};