#pragma once
#include "AbstractManager.h"
#include <Code/Type/Type.h>

namespace CE
{
	namespace Ghidra
	{
		class DataTypeManager;
	};

	/*namespace API::Type
	{
		class AbstractType : public ItemDB
		{
		public:
			AbstractType(TypeManager* typeManager)
				: m_typeManager(typeManager)
			{}

			virtual ~AbstractType() {}

			TypeManager* getTypeManager() {
				return m_typeManager;
			}
		private:
			TypeManager* m_typeManager;
		};

		class Type : public AbstractType
		{
		public:
			Type(TypeManager* typeManager, CE::DataType::Type* type)
				: AbstractType(typeManager), m_type(type)
			{
				m_type->addOwner();
			}

			~Type() {
				m_type->free();
			}

			virtual void pushToGhidra() {}

			void save() override;

			CE::DataType::Type* getType() {
				return m_type;
			}
		private:
			CE::DataType::Type* m_type;
		};

		class Typedef : public Type
		{
		public:
			Typedef(TypeManager* typeManager, CE::DataType::Typedef* typeDef)
				: Type(typeManager, typeDef)
			{}

			void pushToGhidra() override;

			CE::DataType::Typedef* getTypedef() {
				return static_cast<CE::DataType::Typedef*>(getType());
			}
		};

		class Enum : public Type
		{
		public:
			Enum(TypeManager* typeManager, CE::DataType::Enum* Enum)
				: Type(typeManager, Enum)
			{}

			void pushToGhidra() override;

			CE::DataType::Enum* getEnum() {
				return static_cast<CE::DataType::Enum*>(getType());
			}
		};

		class Class : public Type
		{
		public:
			Class(TypeManager* typeManager, CE::DataType::Class* Class)
				: Type(typeManager, Class)
			{}

			void pushToGhidra() override;

			CE::DataType::Class* getClass() {
				return static_cast<CE::DataType::Class*>(getType());
			}
		};
	};*/

	class TypeManager : public AbstractManager
	{
	public:
		using TypeDict = std::map<int, API::Type::Type*>;

		TypeManager(ProgramModule* module);

	private:
		void addSystemTypes() {
			addType(new API::Type::Type(this, new CE::DataType::Void));
			addType(new API::Type::Type(this, new CE::DataType::Bool));
			addType(new API::Type::Type(this, new CE::DataType::Byte));
			addType(new API::Type::Type(this, new CE::DataType::Int8));
			addType(new API::Type::Type(this, new CE::DataType::Int16));
			addType(new API::Type::Type(this, new CE::DataType::Int32));
			addType(new API::Type::Type(this, new CE::DataType::Int64));
			addType(new API::Type::Type(this, new CE::DataType::UInt16));
			addType(new API::Type::Type(this, new CE::DataType::UInt32));
			addType(new API::Type::Type(this, new CE::DataType::UInt64));
			addType(new API::Type::Type(this, new CE::DataType::Float));
			addType(new API::Type::Type(this, new CE::DataType::Double));
			addType(new API::Type::Type(this, new CE::DataType::Char));
			addType(new API::Type::Type(this, new CE::DataType::WChar));
		}

		inline static std::vector<std::pair<std::string, DataType::Type*>> ghidraTypes = {
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

		void addGhidraSystemTypes() {
			for (const auto& it : ghidraTypes) {
				createTypedef(it.second, it.first);
			}
		}
	public:
		const std::string& getGhidraName(DataType::Type* type) {
			for (const auto& it : ghidraTypes) {
				if (it.second->getId() == type->getId()) {
					return it.first;
				}
			}
			return getGhidraName(getDefaultType()->getType());
		}

		void saveType(DataType::Type* type) {
			if (!type->isUserDefined()) {
				return;
			}

			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			{
				SQLite::Statement query(db, "REPLACE INTO sda_types (id, group, name, desc) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, type->getId());
				query.bind(2, (int)type->getGroup());
				query.bind(3, type->getName());
				query.bind(4, type->getDesc());
				query.exec();
			}
			if (type->getGroup() == DataType::Type::Class) {
				auto Class = static_cast<DataType::Class*>(type);
				SQLite::Statement query(db, "REPLACE INTO sda_classes (class_id, base_class_id, size, vtable_id) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, Class->getId());
				query.bind(2, Class->getBaseClass() != nullptr ? Class->getBaseClass()->getId() : 0);
				query.bind(3, Class->getRelSize());
				auto vtable = Class->getVtable();
				query.bind(4, vtable == nullptr ? 0 : vtable->getId());
				query.exec();
			}
			else if (type->getGroup() == DataType::Type::Typedef) {
				auto Typedef = static_cast<DataType::Typedef*>(type);
				SQLite::Statement query(db, "REPLACE INTO sda_typedefs (type_id, ref_type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, Typedef->getId());
				query.bind(2, Typedef->getRefType()->getId());
				query.bind(3, Typedef->getRefType()->getPointerLvl());
				query.bind(4, Typedef->getRefType()->getArraySize());
				query.exec();
			}
		}

		void removeType(DataType::Type* type) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();

			{
				SQLite::Statement query(db, "DELETE FROM sda_types WHERE id=?1");
				query.bind(1, type->getId());
				query.exec();
			}

			if (type->getGroup() == DataType::Type::Class) {
				SQLite::Statement query(db, "DELETE FROM sda_classes WHERE class_id=?1");
				query.bind(1, type->getId());
				query.exec();
			}
			else if (type->getGroup() == DataType::Type::Typedef) {
				SQLite::Statement query(db, "DELETE FROM sda_typedefs WHERE type_id=?1");
				query.bind(1, type->getId());
				query.exec();
			}

			auto it = m_types.find(type->getId());
			if (it != m_types.end()) {
				m_types.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_types.find(id) != m_types.end())
				id++;
			return id;
		}

		API::Type::Typedef* createTypedef(DataType::Type* refType, std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new API::Type::Typedef(this, new DataType::Typedef(refType, id, name, desc));
			m_types[id] = type;
			return type;
		}

		API::Type::Enum* createEnum(std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new API::Type::Enum(this, new DataType::Enum(id, name, desc));
			m_types[id] = type;
			return type;
		}

		API::Type::Class* createClass(std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new API::Type::Class(this, new DataType::Class(id, name, desc));
			m_types[id] = type;
			return type;
		}

		void saveEnumFields(DataType::Enum* Enum) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_enum_fields WHERE enum_id=?1");
				query.bind(1, Enum->getId());
				query.exec();
			}

			{
				for (auto it : Enum->getFieldDict()) {
					SQLite::Statement query(db, "INSERT INTO sda_enum_fields (enum_id, name, value) VALUES(?1, ?2, ?3)");
					query.bind(1, Enum->getId());
					query.bind(2, it.second);
					query.bind(3, it.first);
					query.exec();
				}
			}

			transaction.commit();
		}

		void saveClassFields(DataType::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_class_fields WHERE class_id=?1");
				query.bind(1, Class->getId());
				query.exec();
			}

			{
				Class->iterateFields([&](int offset, DataType::Class::Field* field) {
					SQLite::Statement query(db, "INSERT INTO sda_class_fields (class_id, rel_offset, name, type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
					query.bind(1, Class->getId());
					query.bind(2, offset);
					query.bind(3, field->getName());
					query.bind(4, field->getType()->getId());
					query.bind(5, field->getType()->getPointerLvl());
					query.bind(6, field->getType()->getArraySize());
					query.exec();
					return true;
				});
			}

			transaction.commit();
		}

		void saveClassMethods(DataType::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_class_methods WHERE class_id=?1");
				query.bind(1, Class->getId());
				query.exec();
			}

			{
				for (auto method : Class->getMethodList()) {
					SQLite::Statement query(db, "INSERT INTO sda_class_fields (class_id, function_id) VALUES(?1, ?2)");
					query.bind(1, Class->getId());
					query.bind(2, method->getId());
					query.exec();
				}
			}

			transaction.commit();
		}

		void loadTypes() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_types");

			while (query.executeStep())
			{
				DataType::Type* type = nullptr;

				int t = query.getColumn("group");
				switch (t)
				{
				case DataType::Type::Group::Typedef:
				{
					type = new DataType::Typedef(
						getDefaultType()->getType(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					addType(new API::Type::Typedef(this, static_cast<DataType::Typedef*>(type)));
					break;
				}

				case DataType::Type::Group::Enum:
				{
					type = new DataType::Enum(
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					loadFieldsForEnum(static_cast<DataType::Enum*>(type));
					addType(new API::Type::Enum(this, static_cast<DataType::Enum*>(type)));
					break;
				}

				case DataType::Type::Group::Class:
				{
					type = new DataType::Class(
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					addType(new API::Type::Class(this, static_cast<DataType::Class*>(type)));
					break;
				}
				}
			}
		}

		void loadTypedefs() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_typedefs");

			while (query.executeStep())
			{
				auto type = getTypeById(query.getColumn("type_id"));
				if (type != nullptr && type->getType()->getGroup() == DataType::Type::Group::Typedef) {
					auto Typedef = static_cast<DataType::Typedef*>(type->getType());
					auto refType = getType(query.getColumn("ref_type_id"), query.getColumn("pointer_lvl"), query.getColumn("array_size"));
					if (refType != nullptr)
						Typedef->setRefType(refType);
				}
			}
		}

		void loadFieldsForEnum(DataType::Enum* Enum) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT name,value FROM sda_enum_fields WHERE enum_id=?1 GROUP BY value");
			query.bind(1, Enum->getId());

			while (query.executeStep())
			{
				Enum->addField(query.getColumn("name"), query.getColumn("value"));
			}
		}

		void loadClasses()
		{
			for (auto it : m_types) {
				if (it.second->getType()->getGroup() == DataType::Type::Group::Class) {
					auto Class = static_cast<DataType::Class*>(it.second->getType());
					loadInfoForClass(Class);
					loadMethodsForClass(Class);
					loadFieldsForClass(Class);
				}
			}
		}

		void loadInfoForClass(DataType::Class* Class)
		{
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_classes WHERE class_id=?1");
			query.bind(1, Class->getId());
			if (!query.executeStep())
				return;

			Function::VTable* vtable = getProgramModule()->getVTableManager()->getVTableById(query.getColumn("vtable_id"));
			if (vtable != nullptr) {
				Class->setVtable(vtable);
			}
			auto baseClass = getTypeById(query.getColumn("base_class_id"));
			if (baseClass != nullptr) {
				Class->setBaseClass(static_cast<DataType::Class*>(baseClass->getType()));
			}
			Class->resize(query.getColumn("size"));
		}

		void loadMethodsForClass(DataType::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT decl_id,def_id FROM sda_class_methods WHERE class_id=?1");
			query.bind(1, Class->getId());

			while (query.executeStep())
			{
				int def_id = query.getColumn("def_id");
				if (def_id != 0) {
					/*auto function = getProgramModule()->getFunctionManager()->getFunctionById(def_id);
					if (function != nullptr && !function->getFunction()->isFunction()) {
					Class->addMethod(function->getMethod());
					}*/
				}
				else {
					int decl_id = query.getColumn("decl_id");
					auto decl = getProgramModule()->getFunctionManager()->getFunctionDeclManager()->getFunctionDeclById(decl_id);
					if (decl != nullptr && !decl->isFunction()) {
						Class->addMethod((Function::MethodDecl*)decl);
					}
				}
			}
		}

		void loadFieldsForClass(DataType::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_class_fields WHERE class_id=?1 GROUP BY rel_offset");
			query.bind(1, Class->getId());

			while (query.executeStep())
			{
				DataType::Type* type = getProgramModule()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getProgramModule()->getTypeManager()->getDefaultType()->getType();
				}
				Class->addField(query.getColumn("rel_offset"), query.getColumn("name"), type);
			}
		}

		API::Type::Type* getDefaultType() {
			return getTypeById(DataType::SystemType::Byte);
		}

		API::Type::Type* getDefaultReturnType() {
			return getTypeById(DataType::SystemType::Void);
		}

		TypeDict& getTypes() {
			return m_types;
		}

		void addType(API::Type::Type* type) {
			m_types.insert(std::make_pair(type->getType()->getId(), type));
		}

		inline API::Type::Type* getTypeById(int type_id) {
			if (m_types.find(type_id) == m_types.end())
				return nullptr;
			return m_types[type_id];
		}

		DataType::Type* getType(DataType::Type* type, int pointer_lvl = 0, int array_size = 0) {
			if (pointer_lvl > 0) {
				for (int i = 0; i < pointer_lvl; i++) {
					type = new DataType::Pointer(type);
				}
			}

			if (array_size > 0) {
				type = new DataType::Array(type, array_size);
			}
			return type;
		}

		DataType::Type* getType(int type_id, int pointer_lvl = 0, int array_size = 0) {
			DataType::Type* type = getTypeById(type_id)->getType();
			if (type != nullptr) {
				type = getType(type, pointer_lvl, array_size);
			}
			return type;
		}

		void setGhidraManager(Ghidra::DataTypeManager* ghidraManager) {
			m_ghidraManager = ghidraManager;
		}

		Ghidra::DataTypeManager* getGhidraManager() {
			return m_ghidraManager;
		}

		bool isGhidraManagerWorking() {
			return getGhidraManager() != nullptr;
		}
	private:
		TypeDict m_types;
		Ghidra::DataTypeManager* m_ghidraManager;
	};
};