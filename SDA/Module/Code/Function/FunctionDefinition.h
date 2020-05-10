#pragma once
#include "FunctionDeclaration.h"
#include "MethodDeclaration.h"
#include "AddressRange.h"

namespace CE
{
	namespace Trigger::Function
	{
		class Hook;
	};

	namespace CodeGraph::Node
	{
		class FunctionBody;
	};

	class FunctionManager;

	namespace Function
	{
		class FunctionDefinition : public DB::DomainObject, public IGhidraUnit
		{
		public:
			using ArgList = std::vector<Variable::Param>;

			FunctionDefinition(FunctionManager* manager, void* addr, AddressRangeList ranges, FunctionDecl* decl);

			std::string getName();

			std::string getComment();

			std::string getSigName();

			bool isFunction();

			Signature& getSignature();

			ArgNameList& getArgNameList();

			virtual void call(ArgList args) {}

			void* getAddress();

			int getOffset();

			AddressRangeList& getAddressRangeList();

			void addRange(AddressRange range);

			bool isContainingAddress(void* addr);

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			FunctionDecl* getDeclarationPtr();

			FunctionDecl& getDeclaration();

			bool hasBody();

			CodeGraph::Node::FunctionBody* getBody();

			void setBody(CodeGraph::Node::FunctionBody* body);

			bool isGhidraUnit() override;

			void setGhidraUnit(bool toggle) override;

			FunctionManager* getManager();
		private:
			void* m_addr;
			AddressRangeList m_ranges;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionDecl* m_decl;
			CodeGraph::Node::FunctionBody* m_funcBody = nullptr;
			bool m_ghidraUnit = true;
			FunctionManager* m_manager;
		};

		using FunctionDef = FunctionDefinition;
		using Function = FunctionDefinition;
	};
};