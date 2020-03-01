#pragma once
#include "AbstractManager.h"
#include <Code/Type/Type.h>

namespace CE
{
	namespace Ghidra
	{
		class DataTypeManager;
	};

	namespace API::Type
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
			Type(TypeManager* typeManager, CE::Type::Type* type)
				: AbstractType(typeManager), m_type(type)
			{
				m_type->addOwner();
			}

			~Type() {
				m_type->free();
			}

			virtual void pushToGhidra() {}

			void save() override;

			CE::Type::Type* getType() {
				return m_type;
			}
		private:
			CE::Type::Type* m_type;
		};

		class Typedef : public Type
		{
		public:
			Typedef(TypeManager* typeManager, CE::Type::Typedef* typeDef)
				: Type(typeManager, typeDef)
			{}

			void pushToGhidra() override;

			CE::Type::Typedef* getTypedef() {
				return static_cast<CE::Type::Typedef*>(getType());
			}
		};

		class Enum : public Type
		{
		public:
			Enum(TypeManager* typeManager, CE::Type::Enum* Enum)
				: Type(typeManager, Enum)
			{}

			void pushToGhidra() override;

			CE::Type::Enum* getEnum() {
				return static_cast<CE::Type::Enum*>(getType());
			}
		};

		class Class : public Type
		{
		public:
			Class(TypeManager* typeManager, CE::Type::Class* Class)
				: Type(typeManager, Class)
			{}

			void pushToGhidra() override;

			CE::Type::Class* getClass() {
				return static_cast<CE::Type::Class*>(getType());
			}
		};
	};

	class TypeManager : public AbstractManager
	{
	public:
		using TypeDict = std::map<int, API::Type::Type*>;

		TypeManager(ProgramModule* module);

	private:
		void addSystemTypes() {
			addType(new API::Type::Type(this, new CE::Type::Void));
			addType(new API::Type::Type(this, new CE::Type::Bool));
			addType(new API::Type::Type(this, new CE::Type::Byte));
			addType(new API::Type::Type(this, new CE::Type::Int8));
			addType(new API::Type::Type(this, new CE::Type::Int16));
			addType(new API::Type::Type(this, new CE::Type::Int32));
			addType(new API::Type::Type(this, new CE::Type::Int64));
			addType(new API::Type::Type(this, new CE::Type::UInt16));
			addType(new API::Type::Type(this, new CE::Type::UInt32));
			addType(new API::Type::Type(this, new CE::Type::UInt64));
			addType(new API::Type::Type(this, new CE::Type::Float));
			addType(new API::Type::Type(this, new CE::Type::Double));
			addType(new API::Type::Type(this, new CE::Type::Char));
			addType(new API::Type::Type(this, new CE::Type::WChar));
		}

		inline static std::vector<std::pair<std::string, Type::Type*>> ghidraTypes = {
			std::make_pair("void", new CE::Type::Void),
			std::make_pair("unicode", new CE::Type::Void),
			std::make_pair("string", new CE::Type::Void),

			std::make_pair("uchar", new CE::Type::Byte),
			std::make_pair("uint8_t", new CE::Type::Byte),
			std::make_pair("undefined1", new CE::Type::Int8),

			std::make_pair("short", new CE::Type::Int16),
			std::make_pair("ushort", new CE::Type::UInt16),
			std::make_pair("word", new CE::Type::Int16),
			std::make_pair("undefined2", new CE::Type::Int16),

			std::make_pair("int", new CE::Type::Int32),
			std::make_pair("uint", new CE::Type::UInt32),
			std::make_pair("long", new CE::Type::Int32),
			std::make_pair("ulong", new CE::Type::UInt32),
			std::make_pair("dword", new CE::Type::Int32),
			std::make_pair("float", new CE::Type::Float),
			std::make_pair("ImageBaseOffset32", new CE::Type::UInt32),
			std::make_pair("undefined4", new CE::Type::Int32),

			std::make_pair("longlong", new CE::Type::Int64),
			std::make_pair("ulonglong", new CE::Type::UInt64),
			std::make_pair("qword", new CE::Type::Int64),
			std::make_pair("double", new CE::Type::Double),
			std::make_pair("undefined8", new CE::Type::Int64),

			std::make_pair("GUID", new CE::Type::UInt128)
		};

		void addGhidraSystemTypes() {
			for (const auto& it : ghidraTypes) {
				createTypedef(it.second, it.first);
			}
		}
	public:
		const std::string& getGhidraName(Type::Type* type) {
			for (const auto& it : ghidraTypes) {
				if (it.second->getId() == type->getId()) {
					return it.first;
				}
			}
			return getGhidraName(getDefaultType()->getType());
		}

		void saveType(Type::Type* type) {
			if (!type->isUserDefined()) {
				return;
			}

			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			{
				SQLite::Statement query(db, "REPLACE INTO sda_types (id, `group`, name, desc) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, type->getId());
				query.bind(2, (int)type->getGroup());
				query.bind(3, type->getName());
				query.bind(4, type->getDesc());
				query.exec();
			}
			if (type->getGroup() == Type::Type::Class) {
				auto Class = static_cast<Type::Class*>(type);
				SQLite::Statement query(db, "REPLACE INTO sda_classes (class_id, base_class_id, size, vtable_id) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, Class->getId());
				query.bind(2, Class->getBaseClass() != nullptr ? Class->getBaseClass()->getId() : 0);
				query.bind(3, Class->getRelSize());
				auto vtable = Class->getVtable();
				query.bind(4, vtable == nullptr ? 0 : vtable->getId());
				query.exec();
			}
			else if (type->getGroup() == Type::Type::Typedef) {
				auto Typedef = static_cast<Type::Typedef*>(type);
				SQLite::Statement query(db, "REPLACE INTO sda_typedefs (type_id, ref_type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, Typedef->getId());
				query.bind(2, Typedef->getRefType()->getId());
				query.bind(3, Typedef->getRefType()->getPointerLvl());
				query.bind(4, Typedef->getRefType()->getArraySize());
				query.exec();
			}
		}

		void removeType(Type::Type* type) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();

			{
				SQLite::Statement query(db, "DELETE FROM sda_types WHERE id=?1");
				query.bind(1, type->getId());
				query.exec();
			}

			if (type->getGroup() == Type::Type::Class) {
				SQLite::Statement query(db, "DELETE FROM sda_classes WHERE class_id=?1");
				query.bind(1, type->getId());
				query.exec();
			}
			else if (type->getGroup() == Type::Type::Typedef) {
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

		API::Type::Typedef* createTypedef(Type::Type* refType, std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new API::Type::Typedef(this, new Type::Typedef(refType, id, name, desc));
			m_types[id] = type;
			return type;
		}

		API::Type::Enum* createEnum(std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new API::Type::Enum(this, new Type::Enum(id, name, desc));
			m_types[id] = type;
			return type;
		}

		API::Type::Class* createClass(std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new API::Type::Class(this, new Type::Class(id, name, desc));
			m_types[id] = type;
			return type;
		}

		void saveEnumFields(Type::Enum* Enum) {
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

		void saveClassFields(Type::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_class_fields WHERE class_id=?1");
				query.bind(1, Class->getId());
				query.exec();
			}

			{
				Class->iterateFields([&](int offset, Type::Class::Field* field) {
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

		void saveClassMethods(Type::Class* Class) {
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
				Type::Type* type = nullptr;

				int t = query.getColumn("group");
				switch (t)
				{
				case Type::Type::Group::Typedef:
				{
					type = new Type::Typedef(
						getDefaultType()->getType(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					addType(new API::Type::Typedef(this, static_cast<Type::Typedef*>(type)));
					break;
				}

				case Type::Type::Group::Enum:
				{
					type = new Type::Enum(
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					loadFieldsForEnum(static_cast<Type::Enum*>(type));
					addType(new API::Type::Enum(this, static_cast<Type::Enum*>(type)));
					break;
				}

				case Type::Type::Group::Class:
				{
					type = new Type::Class(
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					addType(new API::Type::Class(this, static_cast<Type::Class*>(type)));
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
				if (type != nullptr && type->getType()->getGroup() == Type::Type::Group::Typedef) {
					auto Typedef = static_cast<Type::Typedef*>(type->getType());
					auto refType = getType(query.getColumn("ref_type_id"), query.getColumn("pointer_lvl"), query.getColumn("array_size"));
					if (refType != nullptr)
						Typedef->setRefType(refType);
				}
			}
		}

		void loadFieldsForEnum(Type::Enum* Enum) {
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
				if (it.second->getType()->getGroup() == Type::Type::Group::Class) {
					auto Class = static_cast<Type::Class*>(it.second->getType());
					loadInfoForClass(Class);
					loadMethodsForClass(Class);
					loadFieldsForClass(Class);
				}
			}
		}

		void loadInfoForClass(Type::Class* Class);
		void loadMethodsForClass(Type::Class* Class);

		void loadFieldsForClass(Type::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_class_fields WHERE class_id=?1 GROUP BY rel_offset");
			query.bind(1, Class->getId());

			while (query.executeStep())
			{
				Type::Type* type = getProgramModule()->getTypeManager()->getType(
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
			return getTypeById(Type::SystemType::Byte);
		}

		API::Type::Type* getDefaultReturnType() {
			return getTypeById(Type::SystemType::Void);
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

		Type::Type* getType(Type::Type* type, int pointer_lvl = 0, int array_size = 0) {
			if (pointer_lvl > 0) {
				for (int i = 0; i < pointer_lvl; i++) {
					type = new Type::Pointer(type);
				}
			}

			if (array_size > 0) {
				type = new Type::Array(type, array_size);
			}
			return type;
		}

		Type::Type* getType(int type_id, int pointer_lvl = 0, int array_size = 0) {
			Type::Type* type = getTypeById(type_id)->getType();
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