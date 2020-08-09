#pragma once
#include "FunctionDeclaration.h"
#include "MethodDeclaration.h"
#include <Address/AddressRange.h>
#include <GhidraSync/GhidraObject.h>
#include "../Symbol/MemoryArea/MemoryArea.h"

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
	class ProcessModule;

	namespace Function
	{
		class FunctionDefinition : public DB::DomainObject, public Ghidra::Object, public IDescription
		{
		public:
			//using ArgList = std::vector<Variable::Param>;

			FunctionDefinition(FunctionManager* manager, ProcessModule* module, AddressRangeList ranges, FunctionDecl* decl);

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			bool isFunction();

			DataType::Signature* getSignature();

			//virtual void call(ArgList args) {}

			void* getAddress();

			AddressRangeList& getAddressRangeList();

			void addRange(AddressRange range);

			bool isContainingAddress(void* addr);

			Symbol::MemoryArea* getStackMemoryArea();

			void setStackMemoryArea(Symbol::MemoryArea* stackMemoryArea);

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			FunctionDecl* getDeclarationPtr();

			FunctionDecl& getDeclaration();

			bool hasBody();

			CodeGraph::Node::FunctionBody* getBody();

			void setBody(CodeGraph::Node::FunctionBody* body);

			void setExported(bool toggle);

			bool isExported();

			Ghidra::Id getGhidraId() override;

			ProcessModule* getProcessModule();

			FunctionManager* getManager();
		private:
			ProcessModule* m_module;
			AddressRangeList m_ranges;
			Symbol::MemoryArea* m_stackMemoryArea = nullptr;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionDecl* m_decl;
			CodeGraph::Node::FunctionBody* m_funcBody = nullptr;
			FunctionManager* m_manager;
		};

		using FunctionDef = FunctionDefinition;
		using Function = FunctionDefinition;
	};
};