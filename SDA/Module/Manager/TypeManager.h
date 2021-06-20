#pragma once
#include "AbstractManager.h"
#include <Code/Type/Type.h>

namespace DB {
	class DataTypeMapper;
};

namespace CE::Ghidra {
	class DataTypeMapper;
};

namespace CE
{
	namespace Ghidra
	{
		class DataTypeManager;
	};

	class TypeManager : public AbstractItemManager
	{
	public:
		class Factory : public AbstractFactory
		{
			TypeManager* m_typeManager;
			Ghidra::DataTypeMapper* m_ghidraDataTypeMapper;
			DB::DataTypeMapper* m_dataTypeMapper;
		public:
			Factory(TypeManager* typeManager, Ghidra::DataTypeMapper* ghidraDataTypeMapper, DB::DataTypeMapper* dataTypeMapper, bool generateId)
				: m_typeManager(typeManager), m_ghidraDataTypeMapper(ghidraDataTypeMapper), m_dataTypeMapper(dataTypeMapper), AbstractFactory(generateId)
			{}

			DataType::Typedef* createTypedef(const std::string& name, const std::string& desc = "");

			DataType::Enum* createEnum(const std::string& name, const std::string& desc = "");

			DataType::Structure* createStructure(const std::string& name, const std::string& desc);

			DataType::Class* createClass(const std::string& name, const std::string& desc = "");

			DataType::FunctionSignature* createSignature(DataType::FunctionSignature::CallingConvetion callingConvetion, const std::string& name, const std::string& desc = "");

			DataType::IType* getDefaultType();

			DataType::IType* getDefaultReturnType();
		};

		using Iterator = AbstractIterator<DataType::AbstractType>;
		Ghidra::DataTypeMapper* m_ghidraDataTypeMapper;

		TypeManager(Project* module);

		~TypeManager();

		Factory getFactory(bool generateId = true);

		void addSystemTypes();

		void addGhidraTypedefs();

		void loadBefore();

		void loadAfter();

		void loadTypesFrom(ghidra::packet::SDataFullSyncPacket* dataPacket);

		DataTypePtr getType(DB::Id id) {
			return DataType::GetUnit(findTypeById(id));
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

		DataType::IType* findTypeById(DB::Id id);

		DataType::IType* findTypeByName(const std::string& typeName);

		DataType::IType* findTypeByGhidraId(Ghidra::Id id);

		Ghidra::Id getGhidraId(DataType::IType* type);
	private:
		DB::DataTypeMapper* m_dataTypeMapper;
	};
};