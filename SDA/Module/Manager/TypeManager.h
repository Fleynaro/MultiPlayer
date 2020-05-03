#pragma once
#include "AbstractManager.h"
#include <Code/Type/Type.h>

namespace DB {
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

		TypeManager(ProgramModule* module);

		void addSystemTypes();

		inline static std::vector<std::pair<std::string, DataType::SystemType*>> ghidraTypes = {
			std::make_pair("void", new CE::DataType::Void),
			std::make_pair("unicode", new CE::DataType::Void),
			std::make_pair("string", new CE::DataType::Void),

			std::make_pair("uchar", new CE::DataType::Byte),
			std::make_pair("uint8_t", new CE::DataType::Byte),
			std::make_pair("undefined1", new CE::DataType::Int8),

			std::make_pair("short", new CE::DataType::Int16),
			std::make_pair("ushort", new CE::DataType::UInt16),
			std::make_pair("word", new CE::DataType::Int16),
			std::make_pair("undefined2", new CE::DataType::Int16),

			std::make_pair("int", new CE::DataType::Int32),
			std::make_pair("uint", new CE::DataType::UInt32),
			std::make_pair("long", new CE::DataType::Int32),
			std::make_pair("ulong", new CE::DataType::UInt32),
			std::make_pair("dword", new CE::DataType::Int32),
			std::make_pair("float", new CE::DataType::Float),
			std::make_pair("ImageBaseOffset32", new CE::DataType::UInt32),
			std::make_pair("undefined4", new CE::DataType::Int32),

			std::make_pair("longlong", new CE::DataType::Int64),
			std::make_pair("ulonglong", new CE::DataType::UInt64),
			std::make_pair("qword", new CE::DataType::Int64),
			std::make_pair("double", new CE::DataType::Double),
			std::make_pair("undefined8", new CE::DataType::Int64),

			std::make_pair("GUID", new CE::DataType::UInt128)
		};

		void addGhidraSystemTypes();

		void loadTypes();

		void loadClasses();

		const std::string& getGhidraTypeName(DataType::Type* type);

		DataType::Typedef* createTypedef(DataType::Type* refType, const std::string& name, const std::string& desc = "");

		DataType::Enum* createEnum(const std::string& name, const std::string& desc = "");

		DataType::Class* createClass(const std::string& name, const std::string& desc = "");

		DataType::Type* getDefaultType();

		DataType::Type* getDefaultReturnType();

		DataType::Type* getTypeById(DB::Id id);

		DataType::Type* getTypeByName(const std::string& typeName);

		DataType::Type* getType(DataType::Type* type, int pointer_lvl = 0, int array_size = 0);

		DataType::Type* getType(int type_id, int pointer_lvl = 0, int array_size = 0);

		void setGhidraManager(Ghidra::DataTypeManager* ghidraManager);

		Ghidra::DataTypeManager* getGhidraManager();

		bool isGhidraManagerWorking();
	private:
		DB::DataTypeMapper* m_dataTypeMapper;
		Ghidra::DataTypeManager* m_ghidraManager;
	};
};