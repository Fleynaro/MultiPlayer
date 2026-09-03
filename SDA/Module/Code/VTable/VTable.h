#pragma once
#include "../Function/Function.h"

namespace CE
{
	namespace Function
	{
		class VTable : public Descrtiption
		{
		public:
			using vMethodList = std::vector<CE::Function::Function*>;

			VTable(void* addr, int id, std::string name, std::string desc = "")
				: m_addr(addr), Descrtiption(name, desc)
			{}

			inline vMethodList& getVMethodList() {
				return m_vmethods;
			}

			void addMethod(CE::Function::Function* method) {
				getVMethodList().push_back(method);
			}

			void* getAddress() {
				return m_addr;
			}
		private:
			void* m_addr;
			vMethodList m_vmethods;
		};
	};
};