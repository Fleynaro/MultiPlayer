#pragma once
#include "../Shared.h"
#include <DB/DomainObject.h>

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
		class Type : public DB::IDomainObject
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

			Type(TypeManager* typeManager)
				: m_typeManager(typeManager)
			{}

			virtual std::string getName() = 0;

			virtual std::string getDesc() {
				return "Not desc.";
			}

			virtual Group getGroup() = 0;

			virtual std::string getDisplayName() = 0;

			virtual bool isPointer();

			virtual int getSize() = 0;

			virtual bool isUserDefined() = 0;

			virtual std::string getViewValue(void* addr);

			std::string getViewValue(uint64_t value);

			Type* getBaseType(bool refType = true, bool dereferencedType = true);

			bool isSystem();

			bool isString();

			virtual bool isSigned();

			void setTypeManager(TypeManager* typeManager);

			TypeManager* getTypeManager();
		private:
			TypeManager* m_typeManager;
		};
	};
};