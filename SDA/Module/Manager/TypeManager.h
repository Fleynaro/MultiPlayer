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

			DataType::FunctionSignature* createSignature(const std::string& name, const std::string& desc = "");

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

		DataTypePtr getType(DB::Id id);

		DataTypePtr getDefaultType(int size, bool sign = false, bool floating = false);

		DataTypePtr calcDataTypeForNumber(uint64_t value);

		DataType::IType* findTypeById(DB::Id id);

		DataType::IType* findTypeByName(const std::string& typeName);

		DataType::IType* findTypeByGhidraId(Ghidra::Id id);

		Ghidra::Id getGhidraId(DataType::IType* type);
	private:
		DB::DataTypeMapper* m_dataTypeMapper;
	};
};