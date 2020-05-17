#pragma once
#include <Utils/Description.h>
#include <DB/DomainObject.h>
#include <GhidraSync/GhidraObject.h>

namespace CE
{
	/*
		���� ��������� ����(����������������� � ����������), ���� ����������������
		���������������� ������ ������������(�����, ������������) � typedef. ��� - ���������� ��������� �����.
		����� ���� ��������� ������� - ���� ���.
		���� ������� - ��� ������ � ���������.
	*/
	class TypeManager;

	namespace DataType
	{
		class Type : public DB::IDomainObject, public Descrtiption
		{
		protected:
			virtual ~Type() {}
		public:
			enum Group
			{
				Simple,
				Enum,
				Structure,
				Class,
				Typedef,
				Signature
			};

			Type(TypeManager* typeManager, const std::string& name, const std::string& comment);

			virtual Group getGroup() = 0;

			virtual std::string getDisplayName() = 0;

			virtual int getSize() = 0;

			virtual bool isUserDefined() = 0;

			virtual std::string getViewValue(void* addr);

			std::string getViewValue(uint64_t value);

			Type* getBaseType(bool refType = true, bool dereferencedType = true);

			bool isSystem();

			virtual bool isSigned();

			void setTypeManager(TypeManager* typeManager);

			TypeManager* getTypeManager();
		private:
			TypeManager* m_typeManager;
		};
	};
};