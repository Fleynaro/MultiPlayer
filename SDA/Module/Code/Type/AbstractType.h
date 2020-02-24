#pragma once
#include "../Shared.h"

namespace CE
{
	namespace Type
	{
		class Type : public IDesc
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
				else if (m_ownerCount < 0)
					if(m_isDeleted)
						throw std::logic_error("Double deleting. Trying to delete already deleted type.");
					else throw std::logic_error("m_ownerCount < 0. The lack of calling addOwner somewhere.");
			}

			virtual std::string getViewValue(void* addr) {
				uint64_t mask = 0x0;
				for (int i = 0; i < max(8, getSize()); i++)
					mask |= 0xFF << i;
				return std::to_string(*(uint64_t*)addr & mask);
			}

			Type* getBaseType();

			bool isSystem() {
				return !isUserDefined();
			}

			bool isPointer() {
				return getPointerLvl() != 0;
			}

			bool isArray() {
				return getArraySize() != 0;
			}

			bool isArrayOfPointers() {
				return isArray() && isPointer();
			}

			void addOwner() {
				m_ownerCount ++;
			}
		private:
			int m_ownerCount = 0;
			bool m_isDeleted = false;
		};
	};
};