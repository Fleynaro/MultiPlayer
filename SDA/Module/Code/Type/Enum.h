#pragma once
#include "UserType.h"

namespace CE
{
	namespace Type
	{
		class Enum : public UserType
		{
		public:
			using FieldDict = std::map<int, std::string>;

			Enum(int id, std::string name, std::string desc = "")
				: UserType(id, name, desc)
			{}

			int getSize() override {
				return m_size;
			}

			void setSize(int size) {
				m_size = size;
			}

			Group getGroup() override {
				return Group::Enum;
			}

			std::string getViewValue(void* addr) override {
				auto value = m_fields.find(*(int*)(addr));
				if (value == m_fields.end())
					return UserType::getViewValue(addr);
				return value->second;
			}

			FieldDict& getFieldDict() {
				return m_fields;
			}

			bool removeField(int value) {
				auto it = m_fields.find(value);
				if (it != m_fields.end()) {
					m_fields.erase(it);
					return true;
				}
				return false;
			}

			void addField(std::string name, int value) {
				m_fields[value] = name;
			}

			void deleteAll() {
				m_fields.clear();
			}
		private:
			FieldDict m_fields;
			int m_size = 4;
		};
	};
};