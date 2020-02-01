#pragma once
#include "../Shared.h"

namespace CE
{
	namespace Type
	{
		class Type : public IDesc
		{
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
			virtual void free() {}

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
		};
	};
};