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

			CallGraph::Unit::FunctionBody* getBody();

			void setBody(CallGraph::Unit::FunctionBody* body) {
				if (m_funcBody != nullptr) {
					delete m_funcBody;
				}
				m_funcBody = body;
			}

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

	class FunctionManager : public AbstractManager
	{
	public:
		using FunctionDict = std::map<int, API::Function::Function*>;
		using FunctionDeclDict = std::map<int, API::Function::FunctionDecl*>;

		FunctionManager(ProgramModule* module);

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


		void saveFunctionNodeGroup(Function::FunctionDefinition& definition, CallGraph::Unit::NodeGroup* nodeGroup, int& id);
	public:
		void saveFunctionBody(API::Function::Function* function);

		void saveFunctionDeclArguments(Function::FunctionDecl& decl) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_arguments WHERE decl_id=?1");
				query.bind(1, decl.getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto type : decl.getSignature().getArgList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_arguments (decl_id, id, name, type_id, pointer_lvl, array_size) \
					VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
					query.bind(1, decl.getId());
					query.bind(2, id);
					query.bind(3, decl.getArgNameList()[id]);
					query.bind(4, type->getId());
					query.bind(5, type->getPointerLvl());
					query.bind(6, type->getArraySize());
					query.exec();
					id++;
				}
			}

			transaction.commit();
		}

		void saveFunctionRanges(Function::FunctionDefinition& definition) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_ranges WHERE function_id=?1");
				query.bind(1, definition.getId());
				query.exec();
			}

			{
				int order_id = 0;
				for (auto& range : definition.getRangeList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_ranges (def_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
					query.bind(1, definition.getId());
					query.bind(2, order_id);
					query.bind(3, getProgramModule()->toRelAddr(range.getMinAddress()));
					query.bind(4, getProgramModule()->toRelAddr(range.getMaxAddress()));
					query.exec();
					order_id++;
				}
			}

			transaction.commit();
		}

		void saveFunctionDecl(Function::FunctionDecl& decl) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_func_decls (decl_id, name, role, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
			query.bind(1, decl.getId());
			query.bind(2, decl.getName());
			query.bind(3, (int)decl.getRole());
			query.bind(4, decl.getSignature().getReturnType()->getId());
			query.bind(5, decl.getSignature().getReturnType()->getPointerLvl());
			query.bind(6, decl.getSignature().getReturnType()->getArraySize());
			query.bind(7, decl.getDesc());
			query.exec();
		}

		void saveFunctionDefinition(Function::FunctionDefinition& definition) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_functions (id, decl_id, offset)\
				VALUES(?1, ?2, ?3)");
			query.bind(1, definition.getId());
			query.bind(2, definition.getDeclaration().getId());
			query.bind(3, getProgramModule()->toRelAddr(definition.getAddress()));
			query.exec();
		}

		void saveFunction(Function::Function& function) {
			saveFunctionDecl(function.getDeclaration());
			if (function.getDeclaration().m_argumentsChanged) {
				saveFunctionDeclArguments(function.getDeclaration());
			}
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

		void removeFunctionDecl(Function::FunctionDecl& decl) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_func_decls WHERE decl_id=?1");
			query.bind(1, decl.getId());
			query.exec();

			auto it = m_decls.find(decl.getId());
			if (it != m_decls.end()) {
				m_decls.erase(it);
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

		int getNewFuncId() {
			int id = 1;
			while (m_functions.find(id) != m_functions.end())
				id++;
			return id;
		}

		int getNewFuncDeclId() {
			int id = 1;
			while (m_decls.find(id) != m_decls.end())
				id++;
			return id;
		}

		API::Function::Function* createFunction(void* addr, Function::FunctionDefinition::RangeList ranges, API::Function::FunctionDecl* decl = nullptr) {
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

		API::Function::Function* createFunction(Function::FunctionDefinition::RangeList ranges, API::Function::FunctionDecl* decl = nullptr) {
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

		void loadFunctionDecls() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_decls");
			
			while (query.executeStep())
			{
				Function::FunctionDecl* decl;
				Function::FunctionDecl::Role decl_role = (Function::FunctionDecl::Role)(int)query.getColumn("role");
				int decl_id = query.getColumn("decl_id");
				std::string decl_name = query.getColumn("name");
				std::string decl_desc = query.getColumn("desc");

				if (Function::FunctionDecl::isFunction(decl_role)) {
					decl = new Function::FunctionDecl(
						decl_id,
						decl_name,
						decl_desc
					);
				}
				else {
					decl = new Function::MethodDecl(
						decl_id,
						decl_name,
						decl_desc
					);
					static_cast<Function::MethodDecl*>(decl)->setRole((Function::MethodDecl::Role)(int)query.getColumn("role"));
				}

				Type::Type* type = getProgramModule()->getTypeManager()->getType(
					query.getColumn("ret_type_id"),
					query.getColumn("ret_pointer_lvl"),
					query.getColumn("ret_array_size")
				);

				if (type == nullptr) {
					type = getProgramModule()->getTypeManager()->getDefaultReturnType()->getType();
				}
				decl->getSignature().setReturnType(type);
				loadFunctionDeclArguments(*decl);

				decl->m_argumentsChanged = false;
				addFunctionDecl(new API::Function::FunctionDecl(this, decl));
			}
		}

		void loadFunctionDeclArguments(Function::FunctionDecl& decl) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_arguments WHERE decl_id=?1 GROUP BY id");
			query.bind(1, decl.getId());

			while (query.executeStep())
			{
				Type::Type* type = getProgramModule()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getProgramModule()->getTypeManager()->getDefaultType()->getType();
				}

				decl.addArgument(type, query.getColumn("name"));
			}
		}

		void loadFunctions() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_defs");

			while (query.executeStep())
			{
				int def_id = query.getColumn("def_id");
				int def_offset = query.getColumn("offset");
				int decl_id = query.getColumn("decl_id");

				auto decl = getFunctionDeclById(decl_id);
				if (decl == nullptr)
					continue;

				auto definition =
					new Function::FunctionDefinition(
						getProgramModule()->toAbsAddr(def_offset),
						Function::FunctionDefinition::RangeList(),
						def_id,
						decl->getFunctionDecl()
					);

				auto function =
					decl->getFunctionDecl()->isFunction() ? new Function::Function(definition) : new Function::Method(definition);

				addFunction(new API::Function::Function(this, function, decl));
				loadFunctionRanges(function->getDefinition());
			}
		}

		void loadFunctionRanges(Function::FunctionDefinition& definition) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_ranges WHERE def_id=?1 GROUP BY order_id");
			query.bind(1, definition.getId());

			while (query.executeStep())
			{
				definition.addRange(Function::FunctionDefinition::Range(
					getProgramModule()->toAbsAddr(query.getColumn("min_offset")),
					getProgramModule()->toAbsAddr(query.getColumn("max_offset"))
				));
			}
		}

		void loadFunctionBody(API::Function::Function* function);

		void loadFunctionBodies() {
			for (auto it : m_functions) {
				loadFunctionBody(it.second);
			}
		}

		void buildFunctionBodies();

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
		Ghidra::FunctionManager* m_ghidraManager;
	};
};