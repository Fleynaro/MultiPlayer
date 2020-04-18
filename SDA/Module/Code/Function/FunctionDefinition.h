#pragma once
#include "FunctionDeclaration.h"
#include "AddressRange.h"

namespace CE
{
	namespace Trigger::Function
	{
		class Hook;
	};

	namespace Function
	{
		class FunctionDefinition
		{
		public:
			using ArgList = std::vector<Variable::Param>;

			FunctionDefinition(void* addr, AddressRangeList ranges, int def_id, FunctionDecl* decl)
				: m_addr(addr), m_ranges(ranges), m_id(def_id), m_decl(decl)
			{}

			int getId();

			virtual void call(ArgList args) {}

			void* getAddress();

			AddressRangeList& getRangeList();

			void addRange(AddressRange range);

			bool isContainingAddress(void* addr);

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			FunctionDecl* getDeclarationPtr();

			FunctionDecl& getDeclaration();
		protected:
			int m_id;
			void* m_addr;
			AddressRangeList m_ranges;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionDecl* m_decl;
		};
	};
};