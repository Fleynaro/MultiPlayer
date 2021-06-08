#pragma once
#include "SdaCodeGraph.h"
#include "../Optimization/DecGraphOptimization.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>
#include <Manager/ProgramModule.h>
#include <Manager/TypeManager.h>

namespace CE::Decompiler::Symbolization
{
	using namespace Optimization;
	using namespace DataType;

	struct UserSymbolDef {
		CE::ProgramModule* m_programModule;
		ISignature* m_signature = nullptr;
		CE::Symbol::SymbolTable* m_globalSymbolTable = nullptr;
		CE::Symbol::SymbolTable* m_stackSymbolTable = nullptr;
		CE::Symbol::SymbolTable* m_funcBodySymbolTable = nullptr;
		int64_t m_startOffset = 0x0;

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

		DataTypePtr getDefaultType(int size, bool sign = false, bool floating = false) {
			if (floating) {
				if (size == 0x4)
					return getType(SystemType::Float);
				if (size == 0x8)
					return getType(SystemType::Double);
			}
			if (size == 0x0)
				return getType(SystemType::Void);
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

		DataTypePtr calcDataTypeForNumber(uint64_t value) {
			if ((value & ~uint64_t(0xFFFFFFFF)) == (uint64_t)0x0)
				return getType(SystemType::Int32);
			return getType(SystemType::Int64);
		}
	private:
		CE::ProgramModule* m_programModule;
	};
};