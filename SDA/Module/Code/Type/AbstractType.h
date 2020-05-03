#pragma once
#include "../Shared.h"
#include <DB/DomainObject.h>

namespace CE
{
	/*
		Есть системные типы(зарезервированные и неизменные), есть пользовательские
		Пользовательские бывают композитными(класс, перечисление) и typedef. Они - агрегаторы системных типов.
		Также есть сигнатуры функций - тоже тип.
		Есть обертки - это массив и указатель.
	*/
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
				m_ownerCount--;
				if (m_ownerCount == 0) {
					m_isDeleted = true;
					delete this;
				}
				else if (m_ownerCount < 0) {
					if (m_isDeleted)
						throw std::logic_error("Double deleting. Trying to delete already deleted type.");
					else throw std::logic_error("m_ownerCount < 0. The lack of calling addOwner somewhere.");
				}
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
				m_ownerCount++;
			}
		private:
			int m_ownerCount = 0;
			bool m_isDeleted = false;
		};
	};
};