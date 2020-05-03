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

			virtual int getPointerLvl() = 0;

			virtual int getArraySize() = 0;

			virtual int getSize() = 0;

			virtual bool isUserDefined() = 0;

			virtual void free() {
				/*m_ownerCount--;
				if (m_ownerCount == 0) {
					m_isDeleted = true;
					delete this;
				}
				else if (m_ownerCount < 0) {
					if (m_isDeleted)
						throw std::logic_error("Double deleting. Trying to delete already deleted type.");
					else throw std::logic_error("m_ownerCount < 0. The lack of calling addOwner somewhere.");
				}*/
			}

			virtual std::string getViewValue(void* addr);

			virtual std::string getViewValue(uint64_t value);

			Type* getBaseType(bool refType = true, bool dereferencedType = true);

			bool isSystem();

			bool isPointer();

			bool isArray();

			bool isArrayOfPointers();

			bool isArrayOfObjects();

			bool isString();

			virtual bool isSigned();

			void addOwner() {
				
			}

			void setTypeManager(TypeManager* typeManager) {
				m_typeManager = typeManager;
			}

			TypeManager* getTypeManager() {
				return m_typeManager;
			}
		private:
			TypeManager* m_typeManager;
		};
	};
};