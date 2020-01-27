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
		class AbstractFunction : public ItemDB
		{
		public:
			AbstractFunction(FunctionManager* funcManager)
				: m_funcManager(funcManager)
			{}

			FunctionManager* getFunctionManager() {
				return m_funcManager;
			}
		private:
			FunctionManager* m_funcManager;
		};

		class Function : public AbstractFunction
		{
		public:
			Function(FunctionManager* funcManager, CE::Function::Function* function)
				: AbstractFunction(funcManager), m_function(function)
			{}

			void save() override;

			CallGraph::Unit::FunctionBody* getBody();

			void setBody(CallGraph::Unit::FunctionBody* body) {
				if (m_funcBody != nullptr) {
					delete m_funcBody;
				}
				m_funcBody = body;
			}

			CE::Function::Function* getFunction() {
				return m_function;
			}
		private:
			CE::Function::Function* m_function;
			CallGraph::Unit::FunctionBody* m_funcBody = nullptr;
		};

		class Method : public Function
		{
		public:
			Method(FunctionManager* funcManager, CE::Function::Method* method)
				: Function(funcManager, method)
			{}

			CE::Function::Method* getMethod() {
				return static_cast<CE::Function::Method*>(getFunction());
			}
		};
	};

	class FunctionManager : public AbstractManager
	{
	public:
		using FunctionDict = std::map<int, API::Function::Function*>;

		FunctionManager(ProgramModule* module);

		API::Function::Function* getDefaultFunction() {
			return m_defFunction;
		}
	private:
		API::Function::Function* m_defFunction = nullptr;
		void createDefaultFunction() {
			m_defFunction = createFunction(nullptr, {}, "DefaultFunction", "This function created automatically.");
			getFunctions().erase(m_defFunction->getFunction()->getId());
		}


		void saveFunctionNodeGroup(Function::Function* function, CallGraph::Unit::NodeGroup* nodeGroup, int& id);
	public:
		void saveFunctionBody(API::Function::Function* function);

		void saveFunctionArguments(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_arguments WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto type : function->getSignature().getArgList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_arguments (function_id, id, name, type_id, pointer_lvl, array_size) \
					VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
					query.bind(1, function->getId());
					query.bind(2, id);
					query.bind(3, function->getArgNameList()[id]);
					query.bind(4, type->getId());
					query.bind(5, type->getPointerLvl());
					query.bind(6, type->getArraySize());
					query.exec();
					id++;
				}
			}

			transaction.commit();
		}

		void saveFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_ranges WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			{
				int order_id = 0;
				for (auto& range : function->getRangeList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_ranges (function_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
					query.bind(1, function->getId());
					query.bind(2, order_id);
					query.bind(3, getProgramModule()->toRelAddr(range.getMinAddress()));
					query.bind(4, getProgramModule()->toRelAddr(range.getMaxAddress()));
					query.exec();
					order_id++;
				}
			}

			transaction.commit();
		}

		void saveFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_functions (id, name, method, offset, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
			query.bind(1, function->getId());
			query.bind(2, function->getName());
			query.bind(3, function->isMethod());
			query.bind(4, getProgramModule()->toRelAddr(function->getAddress()));
			query.bind(5, function->getSignature().getReturnType()->getId());
			query.bind(6, function->getSignature().getReturnType()->getPointerLvl());
			query.bind(7, function->getSignature().getReturnType()->getArraySize());
			query.bind(8, function->getDesc());
			query.exec();
		}

		void saveFunctions() {
			for (auto it : m_functions) {
				auto func = it.second->getFunction();
				saveFunction(func);
				saveFunctionRanges(func);
				if (func->getDeclaration().m_argumentsChanged) {
					saveFunctionArguments(func);
				}
			}
		}

		void removeFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_functions WHERE id=?1");
			query.bind(1, function->getId());
			query.exec();

			auto it = m_functions.find(function->getId());
			if (it != m_functions.end()) {
				m_functions.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_functions.find(id) != m_functions.end())
				id++;
			return id;
		}

		API::Function::Function* createFunction(void* addr, Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			int id = getNewId();
			auto func = m_functions[id] = new API::Function::Function(this, new Function::Function(addr, ranges, id, name, desc));
			func->getFunction()->getSignature().setReturnType(getProgramModule()->getTypeManager()->getDefaultReturnType()->getType());
			return m_functions[id];
		}

		API::Function::Function* createFunction(Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			return createFunction(ranges[0].getMinAddress(), ranges, name, desc);
		}

		API::Function::Method* createMethod(Type::Class* Class, void* addr, Function::Function::RangeList size, std::string name, std::string desc = "") {
			int id = getNewId();
			auto method = new API::Function::Method(this, new Function::Method(addr, size, id, name, desc));
			m_functions[id] = method;
			method->getFunction()->getSignature().setReturnType(getProgramModule()->getTypeManager()->getDefaultReturnType()->getType());
			Class->addMethod(method->getMethod());
			return method;
		}

		void loadFunctions() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_functions AS f INNER JOIN sda_func_decls AS d ON f.decl_id = d.decl_id");

			Function::FunctionDecl* decl = nullptr;
			Function::Function* function = nullptr;
			while (query.executeStep())
			{
				bool isMethod = (int)query.getColumn("method");
				int func_id = query.getColumn("id");
				int func_offset = query.getColumn("offset");
				int decl_id = query.getColumn("decl_id");
				bool isPrevDecl = decl != nullptr && decl->getId() == decl_id;

				if (!isPrevDecl)
				{
					std::string decl_name = query.getColumn("name");
					std::string decl_desc = query.getColumn("desc");
					if (isMethod) {
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
					}
				}

				if (isMethod) {
					function = new Function::Function(
						getProgramModule()->toAbsAddr(func_offset),
						Function::Function::RangeList(),
						func_id,
						decl
					);
					addFunction(new API::Function::Function(this, function));
				}
				else {
					function = new Function::Method(
						getProgramModule()->toAbsAddr(func_offset),
						Function::Function::RangeList(),
						func_id,
						static_cast<Function::MethodDecl*>(decl)
					);
					addFunction(new API::Function::Method(this, static_cast<Function::Method*>(function)));
				}

				loadFunctionRanges(function);

				if (!isPrevDecl) {
					Type::Type* type = getProgramModule()->getTypeManager()->getType(
						query.getColumn("ret_type_id"),
						query.getColumn("ret_pointer_lvl"),
						query.getColumn("ret_array_size")
					);

					if (type == nullptr) {
						type = getProgramModule()->getTypeManager()->getDefaultReturnType()->getType();
					}
					decl->getSignature().setReturnType(type);
					loadFunctionDeclArguments(decl);

					decl->m_argumentsChanged = false;
				}
			}
		}

		void loadFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_ranges WHERE function_id=?1 GROUP BY order_id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				function->addRange(Function::Function::Range(
					getProgramModule()->toAbsAddr(query.getColumn("min_offset")),
					getProgramModule()->toAbsAddr(query.getColumn("max_offset"))
				));
			}
		}

		void loadFunctionDeclArguments(Function::FunctionDecl* decl) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_arguments WHERE decl_id=?1 GROUP BY id");
			query.bind(1, decl->getId());

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

				decl->addArgument(type, query.getColumn("name"));
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

		void addFunction(API::Function::Function* function) {
			m_functions.insert(std::make_pair(function->getFunction()->getId(), function));
		}

		inline API::Function::Function* getFunctionById(int id) {
			if (m_functions.find(id) == m_functions.end())
				return nullptr;
			return m_functions[id];
		}

		Function::FunctionDecl* getFunctionDeclById(int decl_id) {
			for (auto& it : getFunctions()) {
				if (it.second->getFunction()->getDeclaration().getId() == decl_id) {
					return (Function::FunctionDecl*&)it.second->getFunction()->getDeclaration();
				}
			}
			return nullptr;
		}

		API::Function::Function* getFunctionAt(void* addr) {
			for (auto& it : getFunctions()) {
				if (it.second->getFunction()->isContainingAddress(addr)) {
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
		Ghidra::FunctionManager* m_ghidraManager;
	};
};