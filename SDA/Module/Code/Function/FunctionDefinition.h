#pragma once
#include "FunctionDeclaration.h"
#include "MethodDeclaration.h"
#include <Address/AddressRange.h>
#include <GhidraSync/IGhidraObject.h>

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
	class ProccessModule;

	namespace Function
	{
		class FunctionDefinition : public DB::DomainObject, public IDescription, public IGhidraObject
		{
		public:
			using ArgList = std::vector<Variable::Param>;

			FunctionDefinition(FunctionManager* manager, ProccessModule* module, AddressRangeList ranges, FunctionDecl* decl);

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			std::string getSigName();

			bool isFunction();

			Signature& getSignature();

			ArgNameList& getArgNameList();

			virtual void call(ArgList args) {}

			void* getAddress();

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

			ProccessModule* getProccessModule();

			FunctionManager* getManager();
		private:
			ProccessModule* m_module;
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