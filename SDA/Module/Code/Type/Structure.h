#pragma once
#include "UserType.h"

namespace CE::DataType
{
	class Structure : public UserType
	{
	public:
		class Field : public Descrtiption
		{
			friend class Structure;
		public:
			Field(Structure* structure, const std::string& name, DataTypePtr type, int absBitOffset, int bitSize, const std::string& comment = "");

			void setDataType(DataTypePtr type);

			DataTypePtr getDataType();

			int getBitSize();

			int getAbsBitOffset();

			int getBitOffset();

			int getSize();

			int getOffset();

			bool isBitField();

			bool isDefault();
		private:
			DataTypePtr m_type;
			int m_bitSize;
			int m_absBitOffset;
			Structure* m_structure;
		};

		using FieldMapType = std::map<int, Field*>;

		Structure(TypeManager* typeManager, const std::string& name, const std::string& comment = "")
			: UserType(typeManager, name, comment)
		{
			m_defaultField = new Field(this, "undefined", GetUnit(new DataType::Byte), -1, -1);
		}

		~Structure();

		Group getGroup() override;

		int getSize() override;

		void resize(int size);

		int getSizeByLastField();

		FieldMapType& getFields();

		int getNextEmptyBitsCount(int bitOffset);

		bool areEmptyFields(int bitOffset, int bitSize);

		bool areEmptyFieldsInBytes(int offset, int size);

		Field* getField(int bitOffset);

		void addField(int bitOffset, int bitSize, const std::string& name, DataTypePtr type, const std::string& desc = "");

		void addField(int offset, const std::string& name, DataTypePtr type, const std::string& desc = "");

		bool removeField(Field* field);

		bool removeField(int bitOffset);

		bool moveField(int bitOffset, int bitsCount);

		bool moveFields(int bitOffset, int bitsCount);

	private:
		FieldMapType::iterator getFieldIterator(int bitOffset);

		Field* getDefaultField();

		void moveField_(int bitOffset, int bitsCount);

	protected:
		int m_size = 0;
		FieldMapType m_fields;
		Field* m_defaultField;
	};
};