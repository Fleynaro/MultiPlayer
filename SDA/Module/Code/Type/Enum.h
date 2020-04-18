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

			int getSize() override;

			void setSize(int size);

			Group getGroup() override;

			std::string getViewValue(void* addr) override;

			FieldDict& getFieldDict();

			bool removeField(int value);

			void addField(std::string name, int value);

			void deleteAll();
		private:
			FieldDict m_fields;
			int m_size = 4;
		};
	};
};