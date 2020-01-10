#pragma once
#include "UserType.h"
#include "SystemType.h"
#include "../Function/Method.h"
#include "../VTable/VTable.h"

namespace CE
{
	namespace Type
	{
		class Class : public UserType
		{
		public:
			class Field
			{
			public:
				Field(std::string name, Type* type, std::string desc = "")
					: m_name(name), m_type(type), m_desc(desc)
				{}

				std::string& getName() {
					return m_name;
				}

				std::string& getDesc() {
					return m_desc;
				}

				void setType(Type* type) {
					m_type = type;
				}

				inline Type* getType() {
					return m_type;
				}
			private:
				std::string m_name;
				std::string m_desc;
				Type* m_type;
			};

			using FieldDict = std::map<int, Field>;
			using MethodList = std::list<Function::Method*>;

			Class(int id, std::string name, std::string desc = "")
				: UserType(id, name, desc)
			{}

			Group getGroup() override {
				return Group::Class;
			}
		public:
			int getSize() override {
				return getSizeWithoutVTable() + hasVTable() * 0x8;
			}

			int getSizeWithoutVTable() {
				int result = 0;
				if (getBaseClass() != nullptr) {
					result += getBaseClass()->getSizeWithoutVTable();
				}
				return result + getRelSize();
			}

			int getRelSize() {
				return m_size;
			}

			void resize(int size) {
				m_size = size;
			}

			MethodList& getMethodList() {
				return m_methods;
			}

			FieldDict& getFieldDict() {
				return m_fields;
			}

			void addMethod(Function::Method* method) {
				getMethodList().push_back(method);
				method->setClass(this);
			}

			void iterateClasses(std::function<void(Class*)> callback)
			{
				if (getBaseClass() != nullptr) {
					getBaseClass()->iterateClasses(callback);
				}

				callback(this);
			}

			void iterateAllMethods(std::function<void(Function::Method*)> callback)
			{
				for (auto method : getMethodList()) {
					callback(method);
				}

				if (getBaseClass() != nullptr) {
					getBaseClass()->iterateAllMethods(callback);
				}
			}

			void iterateMethods(void(*callback)(Function::Method*))
			{
				std::set<std::string> methods;
				iterateAllMethods([&](Function::Method* method) {
					std::string sigName = method->getSigName();
					if (!methods.count(sigName)) {
						callback(method);
					}
					methods.insert(sigName);
					});
			}

			void iterateFields(std::function<void(Class*, int, Field*)> callback)
			{
				if (getBaseClass() != nullptr) {
					getBaseClass()->iterateFields(callback);
				}

				for (auto& it : m_fields) {
					callback(this, it.first, &it.second);
				}
			}

			void iterateFieldsWithOffset(std::function<void(Class*, int, Field*)> callback)
			{
				int curClassBase = hasVTable() * 0x8;
				Class* curClass = nullptr;
				iterateFields([&](Class* Class, int relOffset, Field* field) {
					if (curClass != nullptr && curClass != Class) {
						curClassBase += curClass->getRelSize();
					}
					int curOffset = curClassBase + relOffset;
					callback(Class, curOffset, field);
					});
			}

			Class* getBaseClass() {
				return m_base;
			}

			void setBaseClass(Class* base) {
				m_base = base;
			}

			Function::VTable* getVtable() {
				if (m_vtable != nullptr && getBaseClass() != nullptr) {
					return getBaseClass()->getVtable();
				}
				return m_vtable;
			}

			bool hasVTable() {
				return getVtable() != nullptr;
			}

			void setVtable(Function::VTable* vtable) {
				m_vtable = vtable;
			}

			std::pair<Class*, int> getFieldLocationByOffset(int offset) {
				std::pair<Class*, int> result(nullptr, -1);
				int curOffset = hasVTable() * 0x8;
				iterateClasses([&](Class* Class) {
					if (curOffset + Class->getRelSize() > offset) {
						if (result.second == -1) {
							result.first = Class;
							result.second = offset - curOffset;
						}
					}
					curOffset += Class->getRelSize();
					});
				return result;
			}

			std::pair<int, Field*> getField(int relOffset) {
				auto it = getFieldIterator(relOffset);
				if (it != m_fields.end()) {
					return std::make_pair(it->first, &it->second);
				}
				static Field defaultField = Field("undefined", new Byte);
				return std::make_pair(-1, &defaultField);
			}

			FieldDict::iterator getFieldIterator(int relOffset) {
				auto it = m_fields.lower_bound(relOffset);
				if (it != m_fields.end()) {
					if (it->first + it->second.getType()->getSize() >= relOffset) {
						return it;
					}
				}
				return m_fields.end();
			}

			bool canTypeBeInsertedTo(int relOffset, int size) {
				if (relOffset + size > getRelSize())
					return false;

				auto field_down = m_fields.lower_bound(relOffset);
				if (field_down != m_fields.end() && field_down->first + field_down->second.getType()->getSize() >= relOffset)
					return false;

				auto field_up = m_fields.upper_bound(relOffset);
				if (field_up != m_fields.end() && field_up->first <= relOffset + size)
					return false;
			}

			void addField(int relOffset, std::string name, Type* type, std::string desc = "") {
				m_fields.insert(std::make_pair(relOffset, Field(name, type, desc)));
				m_size = max(m_size, relOffset + type->getSize());
			}

			bool removeField(int relOffset) {
				auto it = getFieldIterator(relOffset);
				if (it != m_fields.end()) {
					m_fields.erase(it);
					return true;
				}
				return false;
			}
		private:
			int m_size = 0;
			Function::VTable* m_vtable = nullptr;
			Class* m_base = nullptr;
			FieldDict m_fields;
			MethodList m_methods;
		};
	};
};