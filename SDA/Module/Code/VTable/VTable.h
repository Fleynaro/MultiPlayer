#pragma once
#include "../Function/Method.h"

namespace CE
{
	namespace Function
	{
		class VTable : public Desc
		{
		public:
			using vMethodList = std::vector<CE::Function::Method*>;

			VTable(void* addr, int id, std::string name, std::string desc = "")
				: m_addr(addr), Desc(id, name, desc)
			{}

			inline vMethodList& getVMethodList() {
				return m_vmethods;
			}

			void addMethod(Method* method) {
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