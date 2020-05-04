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
			std::make_pair("void", new DataType::Void),
			std::make_pair("unicode", new DataType::Void),
			std::make_pair("string", new DataType::Void),

			std::make_pair("uchar", new DataType::Byte),
			std::make_pair("uint8_t", new DataType::Byte),
			std::make_pair("undefined1", new DataType::Int8),

			std::make_pair("short", new DataType::Int16),
			std::make_pair("ushort", new DataType::UInt16),
			std::make_pair("word", new DataType::Int16),
			std::make_pair("undefined2", new DataType::Int16),

			std::make_pair("int", new DataType::Int32),
			std::make_pair("uint", new DataType::UInt32),
			std::make_pair("long", new DataType::Int32),
			std::make_pair("ulong", new DataType::UInt32),
			std::make_pair("dword", new DataType::Int32),
			std::make_pair("float", new DataType::Float),
			std::make_pair("ImageBaseOffset32", new DataType::UInt32),
			std::make_pair("undefined4", new DataType::Int32),

			std::make_pair("longlong", new DataType::Int64),
			std::make_pair("ulonglong", new DataType::UInt64),
			std::make_pair("qword", new DataType::Int64),
			std::make_pair("double", new DataType::Double),
			std::make_pair("undefined8", new DataType::Int64),

			std::make_pair("GUID", new DataType::UInt128)
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

		void setGhidraManager(Ghidra::DataTypeManager* ghidraManager);

		Ghidra::DataTypeManager* getGhidraManager();

		bool isGhidraManagerWorking();
	private:
		DB::DataTypeMapper* m_dataTypeMapper;
		Ghidra::DataTypeManager* m_ghidraManager;
	};
};