#pragma once
#include "../Type/TypeUnit.h"

namespace CE
{
	namespace Variable
	{
		class Variable
		{
		public:
			Variable(DataTypePtr type)
				: m_type(type)
			{}

			DataTypePtr getType() {
				return m_type;
			}
		private:
			DataTypePtr m_type;
		};

		class Global : public Variable, public Desc
		{
		public:
			Global(DataTypePtr type, void* addr, int id, std::string name, std::string desc = "")
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
			Local(DataTypePtr type, void* addr)
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