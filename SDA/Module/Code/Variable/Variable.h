#pragma once
#include "../Type/AbstractType.h"
#include "../Type/Pointer.h"
#include "../Type/Array.h"

namespace CE
{
	namespace Variable
	{
		class Variable
		{
		public:
			Variable(Type::Type* type)
				: m_type(type)
			{}

			Type::Type* getType() {
				return m_type;
			}
		private:
			Type::Type* m_type;
		};

		class Global : public Variable, public Desc
		{
		public:
			Global(Type::Type* type, void* addr, int id, std::string name, std::string desc = "")
				: Variable(type), m_addr(addr), Desc(id, name, desc)
			{}

			void* getAddress() {
				return m_addr;
			}
		private:
			void* m_addr;
		};

		class Local : public Variable
		{
		public:
			Local(Type::Type* type, void* addr)
				: Variable(type), m_addr(addr)
			{}


		private:
			void* m_addr;
		};

		class Param : public Local
		{
		public:

		};
	};
};