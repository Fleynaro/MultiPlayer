#pragma once
#include "../SdaCodeGraph.h"
#include "../../Optimization/DecGraphOptimization.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>
#include <Manager/ProgramModule.h>
#include <Manager/TypeManager.h>

namespace CE::Decompiler::Symbolization
{
	using namespace Optimization;
	using namespace DataType;

	struct UserSymbolDef {
		CE::ProgramModule* m_programModule;
		Signature* m_signature = nullptr;
		CE::Symbol::MemoryArea* m_globalMemoryArea = nullptr;
		CE::Symbol::MemoryArea* m_stackMemoryArea = nullptr;
		CE::Symbol::MemoryArea* m_funcBodyMemoryArea = nullptr;
		int64_t m_offset = 0x0;

		UserSymbolDef(CE::ProgramModule* programModule = nullptr)
			: m_programModule(programModule)
		{}
	};

	class DataTypeFactory
	{
	public:
		DataTypeFactory(CE::ProgramModule* programModule)
			: m_programModule(programModule)
		{}

		DataTypePtr getType(DB::Id id) {
			return DataType::GetUnit(m_programModule->getTypeManager()->getTypeById(id));
		}

		DataTypePtr getDefaultType(int size, bool sign = false) {
			if (size == 0x1)
				return getType(sign ? SystemType::Char : SystemType::Byte);
			if (size == 0x2)
				return getType(sign ? SystemType::Int16 : SystemType::UInt16);
			if (size == 0x4)
				return getType(sign ? SystemType::Int32 : SystemType::UInt32);
			if (size == 0x8)
				return getType(sign ? SystemType::Int64 : SystemType::UInt64);
			return nullptr;
		}

		DataTypePtr getDataTypeByNumber(uint64_t value) {
			uint64_t valueMask = value | uint64_t(0xFFFFFFFF);
			if ((valueMask & ~0xFFFFFFFF) == 0x0)
				return  getType(SystemType::Int32);
			return  getType(SystemType::Int64);
		}
	private:
		CE::ProgramModule* m_programModule;
	};
};