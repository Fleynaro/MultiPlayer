#pragma once
#include "AbstractManager.h"
#include "GVarManager.h"
#include <Code/Function/Method.h>
#include <Utils/BitStream.h>

namespace CE
{
	namespace Ghidra
	{
		class FunctionManager;
	};

	namespace CallGraph::Unit
	{
		class FunctionBody;
		class NodeGroup;
	};

	namespace Function::Tag
	{
		class Manager;
	};

	namespace API::Function
	{
		class FunctionDecl : public ItemDB
		{
		public:
			FunctionDecl(FunctionManager* funcManager, CE::Function::FunctionDecl* decl)
				: m_funcManager(funcManager), m_decl(decl)
			{}

			FunctionManager* getFunctionManager() {
				return m_funcManager;
			}

			void save() override {

			}

			CE::Function::FunctionDecl* getFunctionDecl() {
				return m_decl;
			}

			CE::Function::MethodDecl* getMethodDecl() {
				return static_cast<CE::Function::MethodDecl*>(getFunctionDecl());
			}
		private:
			FunctionManager* m_funcManager;
			CE::Function::FunctionDecl* m_decl;
		};

		class Function : public ItemDB
		{
		public:
			Function(FunctionManager* funcManager, CE::Function::Function* function, API::Function::FunctionDecl* decl)
				: m_funcManager(funcManager), m_function(function), m_decl(decl)
			{}

			FunctionManager* getFunctionManager() {
				return m_funcManager;
			}

			void save() override;

			bool hasBody() {
				return m_funcBody != nullptr;
			}

			CallGraph::Unit::FunctionBody* getBody();

			void setBody(CallGraph::Unit::FunctionBody* body);

			API::Function::FunctionDecl* getDeclaration() {
				return m_decl;
			}

			CE::Function::FunctionDefinition& getDefinition() {
				return getFunction()->getDefinition();
			}

			bool isFunction() {
				return getFunction()->isFunction();
			}

			CE::Function::Function* getFunction() {
				return m_function;
			}

			CE::Function::Method* getMethod() {
				return static_cast<CE::Function::Method*>(getFunction());
			}
		private:
			API::Function::FunctionDecl* m_decl;
			CallGraph::Unit::FunctionBody* m_funcBody = nullptr;
			FunctionManager* m_funcManager;
		protected:
			CE::Function::Function* m_function;
		};
	};



	class FunctionDefManager : public AbstractItemManager
	{
	public:
		using FunctionDict = std::map<int, API::Function::Function*>;
		using FunctionDeclDict = std::map<int, API::Function::FunctionDecl*>;

		FunctionDefManager(ProgramModule* module);

		API::Function::Function* getDefaultFunction() {
			return m_defFunction;
		}
	private:
		API::Function::Function* m_defFunction = nullptr;
		void createDefaultFunction() {
			m_defFunction = createFunction(nullptr, {}, createFunctionDecl("DefaultFunction", "This function created automatically."));
			getFunctions().erase(m_defFunction->getDefinition().getId());
			getFunctionDecls().erase(m_defFunction->getDeclaration()->getFunctionDecl()->getId());
		}
	public:

		void saveFunction(Function::Function& function) {
			saveFunctionDecl(function.getDeclaration());
			//if (function.getDeclaration().m_argumentsChanged) {
				saveFunctionDeclArguments(function.getDeclaration());
			//}
			if (function.hasDefinition()) {
				saveFunctionDefinition(function.getDefinition());
				saveFunctionRanges(function.getDefinition());
			}
		}

		void saveFunctions() {
			for (auto it : m_functions) {
				auto func = it.second->getFunction();
				saveFunction(*func);
			}
		}

		void removeFunctionDefinition(Function::FunctionDefinition& definition) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_func_defs WHERE def_id=?1");
			query.bind(1, definition.getId());
			query.exec();

			auto it = m_functions.find(definition.getId());
			if (it != m_functions.end()) {
				m_functions.erase(it);
			}
		}

		void removeFunction(Function::Function& function) {
			removeFunctionDecl(function.getDeclaration());
			if (function.hasDefinition()) {
				removeFunctionDefinition(function.getDefinition());
			}
		}

		API::Function::Function* createFunction(void* addr, Function::AddressRangeList ranges, API::Function::FunctionDecl* decl = nullptr) {
			int id = getNewFuncId();
			auto dd = decl->getFunctionDecl();
			auto func = m_functions[id] = new API::Function::Function(
				this,
				new CE::Function::Function(
					new CE::Function::FunctionDefinition(addr, ranges, id, decl->getFunctionDecl())
				),
				decl
			);
			func->getFunction()->getSignature().setReturnType(getProgramModule()->getTypeManager()->getDefaultReturnType()->getType());
			return m_functions[id];
		}

		API::Function::Function* createFunction(Function::AddressRangeList ranges, API::Function::FunctionDecl* decl = nullptr) {
			return createFunction(ranges[0].getMinAddress(), ranges, decl);
		}

		API::Function::FunctionDecl* createFunctionDecl(std::string name, std::string desc = "") {
			int decl_id = getNewFuncDeclId();
			auto decl = new API::Function::FunctionDecl(this, new CE::Function::FunctionDecl(decl_id, name, desc));
			m_decls[decl_id] = decl;
			return decl;
		}

		API::Function::FunctionDecl* createMethodDecl(std::string name, std::string desc = "") {
			int decl_id = getNewFuncDeclId();
			auto decl = new API::Function::FunctionDecl(this, new CE::Function::MethodDecl(decl_id, name, desc));
			m_decls[decl_id] = decl;
			return decl;
		}

		void loadFunctionBodies() {
			for (auto it : m_functions) {
				loadFunctionBody(it.second);
			}
		}

		void buildFunctionBodies();

		void buildFunctionBasicInfo();

		FunctionDict& getFunctions() {
			return m_functions;
		}

		FunctionDeclDict& getFunctionDecls() {
			return m_decls;
		}

		void addFunction(API::Function::Function* function) {
			m_functions.insert(std::make_pair(function->getFunction()->getId(), function));
		}

		void addFunctionDecl(API::Function::FunctionDecl* decl) {
			m_decls.insert(std::make_pair(decl->getFunctionDecl()->getId(), decl));
		}

		inline API::Function::Function* getFunctionById(int id) {
			if (m_functions.find(id) == m_functions.end())
				return nullptr;
			return m_functions[id];
		}

		inline API::Function::FunctionDecl* getFunctionDeclById(int id) {
			if (m_decls.find(id) == m_decls.end())
				return nullptr;
			return m_decls[id];
		}

		API::Function::Function* getFunctionAt(void* addr) {
			for (auto& it : getFunctions()) {
				if (it.second->getDefinition().isContainingAddress(addr)) {
					return it.second;
				}
			}
			return nullptr;
		}

		int getFunctionOffset(Function::Function* function) {
			return getProgramModule()->toRelAddr(function->getAddress());
		}

		void setFunctionTagManager(Function::Tag::Manager* manager) {
			m_tagManager = manager;
		}

		Function::Tag::Manager* getFunctionTagManager() {
			return m_tagManager;
		}

		void setGhidraManager(Ghidra::FunctionManager* ghidraManager) {
			m_ghidraManager = ghidraManager;
		}

		Ghidra::FunctionManager* getGhidraManager() {
			return m_ghidraManager;
		}

		bool isGhidraManagerWorking() {
			return getGhidraManager() != nullptr;
		}
	private:
		FunctionDict m_functions;
		FunctionDeclDict m_decls;
		Function::Tag::Manager* m_tagManager;
		Ghidra::FunctionManager* m_ghidraManager;

	};

	class FunctionDeclManager : public AbstractItemManager
	{
	public:
		FunctionDeclManager(ProgramModule* module)
			: AbstractItemManager(module)
		{}
	
		CE::Function::FunctionDecl* createFunctionDecl(std::string name, std::string desc = "") {
			auto decl = new CE::Function::FunctionDecl(name, desc);
			return decl;
		}

		CE::Function::MethodDecl* createMethodDecl(std::string name, std::string desc = "") {
			auto decl = new CE::Function::MethodDecl(name, desc);
			return decl;
		}

		CE::Function::FunctionDecl* getFunctionDeclById(DB::Id id) {
			return (CE::Function::FunctionDecl*)find(id);
		}

	private:

	};
};