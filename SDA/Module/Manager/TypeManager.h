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
		using Iterator = AbstractIterator<DataType::Type>;
		Ghidra::DataTypeMapper* m_ghidraDataTypeMapper;

		TypeManager(ProgramModule* module);

		~TypeManager();

		void addSystemTypes();

		void addGhidraTypedefs();

		void loadTypes();

		void loadClasses();

		void loadTypesFrom(ghidra::packet::SDataFullSyncPacket* dataPacket);

		DataType::Typedef* createTypedef(const std::string& name, const std::string& desc = "");

		DataType::Enum* createEnum(const std::string& name, const std::string& desc = "");

		DataType::Structure* createStructure(const std::string& name, const std::string& desc);

		DataType::Class* createClass(const std::string& name, const std::string& desc = "");

		DataType::Type* getDefaultType();

		DataType::Type* getDefaultReturnType();

		DataType::Type* getTypeById(DB::Id id);

		DataType::Type* getTypeByName(const std::string& typeName);

		DataType::Type* getTypeByGhidraId(Ghidra::Id id);

		Ghidra::Id getGhidraId(DataType::Type* type);
	private:
		DB::DataTypeMapper* m_dataTypeMapper;
	};
};