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

			int getAllMethodCount() {
				return getMethodList().size() +
					(getBaseClass() != nullptr ? getBaseClass()->getAllMethodCount() : 0);
			}

			int getAllFieldCount() {
				return getFieldDict().size() +
					(getBaseClass() != nullptr ? getBaseClass()->getAllFieldCount() : 0);
			}

			int getBaseOffset() {
				return getBaseClass() != nullptr ? getBaseClass()->getRelSize() + getBaseClass()->getBaseOffset() : 0;
			}

			bool iterateClasses(std::function<bool(Class*)> callback)
			{
				if (getBaseClass() != nullptr) {
					if (!getBaseClass()->iterateClasses(callback))
						return false;
				}

				return callback(this);
			}

		private:
			bool iterateAllMethods(std::function<bool(Function::Method*)> callback)
			{
				if (getBaseClass() != nullptr) {
					if (!getBaseClass()->iterateAllMethods(callback))
						return false;
				}

				for (auto method : getMethodList()) {
					if (!callback(method))
						return false;
				}
				return true;
			}

		public:
			bool iterateMethods(std::function<bool(Function::Method*)> callback)
			{
				std::set<std::string> methods;
				return iterateAllMethods([&](Function::Method* method) {
					std::string sigName = method->getSigName();
					if (!methods.count(sigName)) {
						return callback(method);
					}
					methods.insert(sigName);
					return true;
				});
			}

			bool iterateFields(const std::function<bool(int&, Field*)>& callback, bool emptyFields = false)
			{
				if (!emptyFields) {
					for (auto& it : m_fields) {
						int relOffset = it.first;
						if (!callback(relOffset, &it.second))
							return false;
					}
				}
				else {
					for (int byteIdx = 0; byteIdx < getRelSize(); byteIdx++) {
						auto fieldPair = getField(byteIdx);

						if (!callback(byteIdx, fieldPair.second))
							return false;

						if (fieldPair.first != -1) {
							byteIdx += fieldPair.second->getType()->getSize() - 1;
						}
					}
				}

				return true;
			}

			bool iterateFields(const std::function<bool(Class*, int&, Field*)>& callback, bool emptyFields = false)
			{
				if (getBaseClass() != nullptr) {
					if (!getBaseClass()->iterateFields(callback, emptyFields))
						return false;
				}

				return iterateFields([&](int& relOffset, Field* field) {
					return callback(this, relOffset, field);
				}, emptyFields);
			}

			bool iterateFieldsWithOffset(std::function<bool(Class*, int, Field*)> callback, bool emptyFields = false)
			{
				int curClassBase = hasVTable() * 0x8;
				Class* curClass = nullptr;
				return iterateFields([&](Class* Class, int& relOffset, Field* field) {
					if (curClass != nullptr && curClass != Class) {
						curClassBase += curClass->getRelSize();
					}
					int curOffset = curClassBase + relOffset;
					return callback(Class, curOffset, field);
				}, emptyFields);
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
					return true;
					});
				return result;
			}

			bool isEmptyField(int startByteIdx, int size) {
				if (startByteIdx < 0 || startByteIdx + size > getRelSize() || size <= 0)
					return false;

				auto it = m_fields.upper_bound(startByteIdx);
				if (it != m_fields.end()) {
					if (it->first < startByteIdx + size)
						return false;
				}

				return true;
			}

			static Field* getDefaultField() {
				static Field defaultField = Field("undefined", new Byte);
				return &defaultField;
			}

			static bool isDefaultField(Field* field) {
				return field == getDefaultField();
			}

			std::pair<int, Field*> getField(int relOffset) {
				auto it = getFieldIterator(relOffset);
				if (it != m_fields.end()) {
					return std::make_pair(it->first, &it->second);
				}
				return std::make_pair(-1, getDefaultField());
			}

			FieldDict::iterator getFieldIterator(int relOffset) {
				auto it = m_fields.lower_bound(relOffset);
				if (it != m_fields.end()) {
					if (it->first <= relOffset && it->first + it->second.getType()->getSize() > relOffset) {
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