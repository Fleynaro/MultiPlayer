#pragma once
#include "UserType.h"

namespace CE::DataType
{
	class Structure : public UserType
	{
	public:
		class Field : public Descrtiption
		{
		public:
			Field(Structure* structure, const std::string& name, DataTypePtr type, int offset, const std::string& comment = "");

			void setType(DataTypePtr type);

			DataTypePtr getType();

			int getOffset();

			bool isDefault();
		private:
			DataTypePtr m_type;
			int m_offset;
			Structure* m_structure;
		};

		using FieldMapType = std::map<int, Field*>;

		Structure(TypeManager* typeManager, const std::string& name, const std::string& comment = "");

		~Structure();

		Group getGroup() override;

		int getSize() override;

		void resize(int size);

		int getSizeByLastField();

		FieldMapType& getFields();

		int getNextEmptyBytesCount(int offset);

		bool areEmptyFields(int offset, int size);

		Field* getField(int offset);

		void addField(int offset, const std::string& name, DataTypePtr type, const std::string& desc = "");

		bool removeField(Field* field);

		bool removeField(int offset);

		bool moveField(int offset, int bytesCount);

		bool moveFields(int offset, int bytesCount);

	private:
		FieldMapType::iterator getFieldIterator(int offset);

		Field* getDefaultField();

		void moveField_(int offset, int bytesCount);

	protected:
		int m_size = 0;
		FieldMapType m_fields;
		Field* m_defaultField;
	};
};