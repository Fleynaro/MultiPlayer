#pragma once
#include <Code/Function/FunctionDeclaration.h>
#include <Code/Function/MethodDeclaration.h>
#include <Manager/FunctionDeclManager.h>

/*
	1) сделать менеджер, зависимым от IRepository и абстрактного менеджера итемов
	2) сделать транзакции
*/

namespace DB
{
	class FunctionDeclMapper : public AbstractMapper
	{
	public:
		FunctionDeclMapper(IRepository* repository)
			: AbstractMapper(repository)
		{}

		void loadAll(Database* db) {
			Statement query(*db, "SELECT * FROM sda_func_decls");
			load(db, query);
		}

		CE::FunctionDeclManager* getManager() {
			return static_cast<CE::FunctionDeclManager*>(m_repository);
		}
	protected:
		DomainObject* doLoad(Database* db, SQLite::Statement& query) override {
			using namespace CE;
			Function::FunctionDecl* decl;
			Function::FunctionDecl::Role decl_role = (Function::FunctionDecl::Role)(int)query.getColumn("role");
			Id decl_id = query.getColumn("decl_id");
			std::string decl_name = query.getColumn("name");
			std::string decl_desc = query.getColumn("desc");

			if (Function::FunctionDecl::isFunction(decl_role)) {
				decl = new Function::FunctionDecl(
					getManager(),
					decl_name,
					decl_desc
				);
			}
			else {
				decl = new Function::MethodDecl(
					getManager(),
					decl_name,
					decl_desc
				);
				static_cast<Function::MethodDecl*>(decl)->setRole((Function::MethodDecl::Role)(int)query.getColumn("role"));
			}

			decl->setId(decl_id);

			Type::Type* type = getManager()->getProgramModule()->getTypeManager()->getType(
				query.getColumn("ret_type_id"),
				query.getColumn("ret_pointer_lvl"),
				query.getColumn("ret_array_size")
			);

			if (type == nullptr) {
				type = getManager()->getProgramModule()->getTypeManager()->getDefaultReturnType()->getType();
			}
			decl->getSignature().setReturnType(type);
			loadFunctionDeclArguments(db, *decl);
			return decl;
		}

		void loadFunctionDeclArguments(Database* db, CE::Function::FunctionDecl& decl) {
			using namespace CE;

			Statement query(*db, "SELECT * FROM sda_func_arguments WHERE decl_id=?1 GROUP BY id");
			query.bind(1, decl.getId());

			while (query.executeStep())
			{
				Type::Type* type = getManager()->getProgramModule()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getManager()->getProgramModule()->getTypeManager()->getDefaultType()->getType();
				}

				decl.addArgument(type, query.getColumn("name"));
			}
		}

		void saveFunctionDeclArguments(Database* db, CE::Function::FunctionDecl& decl) {
			{
				SQLite::Statement query(*db, "DELETE FROM sda_func_arguments WHERE decl_id=?1");
				query.bind(1, decl.getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto type : decl.getSignature().getArgList()) {
					SQLite::Statement query(*db, "INSERT INTO sda_func_arguments (decl_id, id, name, type_id, pointer_lvl, array_size) \
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
		}

		void doInsert(Database* db, DomainObject* obj) override {
			auto& decl = *(CE::Function::FunctionDecl*)obj;

			SQLite::Statement query(*db, "INSERT INTO sda_func_decls (name, role, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?2, ?3, ?4, ?5, ?6, ?7)");
			bind(query, decl);
			query.exec();
		}

		void doUpdate(Database* db, DomainObject* obj) override {
			auto& decl = *(CE::Function::FunctionDecl*)obj;

			SQLite::Statement query(*db, "REPLACE INTO sda_func_decls (decl_id, name, role, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
			query.bind(1, obj->getId());
			bind(query, decl);
			query.exec();
		}

		void doRemove(Database* db, DomainObject* obj) override {
			Statement query(*db, "DELETE FROM sda_func_decls WHERE decl_id=?1");
			query.bind(1, obj->getId());
			query.exec();
		}

	private:
		void bind(SQLite::Statement& query, CE::Function::FunctionDecl& decl) {
			query.bind(2, decl.getName());
			query.bind(3, (int)decl.getRole());
			query.bind(4, decl.getSignature().getReturnType()->getId());
			query.bind(5, decl.getSignature().getReturnType()->getPointerLvl());
			query.bind(6, decl.getSignature().getReturnType()->getArraySize());
			query.bind(7, decl.getDesc());
		}
	};
};