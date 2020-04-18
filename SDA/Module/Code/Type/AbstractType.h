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

			virtual void free();

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

			void addOwner();
		private:
			int m_ownerCount = 0;
			bool m_isDeleted = false;
		};
	};
};