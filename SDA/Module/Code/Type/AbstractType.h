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
				if(m_canBeRemoved)
					delete this;
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

			void setCanBeRemoved(bool toggle) {
				m_canBeRemoved = toggle;
			}
		private:
			bool m_canBeRemoved = true;
		};
	};
};