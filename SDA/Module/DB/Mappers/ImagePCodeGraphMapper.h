#pragma once
#include <DB/AbstractMapper.h>
#include <Decompiler/Graph/DecPCodeGraph.h>

namespace CE {
	class ImagePCodeGraphManager;
};

namespace DB
{
	class ImagePCodeGraphMapper : public AbstractMapper
	{
	public:
		ImagePCodeGraphMapper(IRepository* repository)
			: AbstractMapper(repository)
		{}

		void loadAll();

		Id getNextId() override;

		CE::ImagePCodeGraphManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void decodePCodeBlock(CE::Decompiler::PCodeBlock* block);

		void loadFuncPCodeGraphJson(const json& json_func_graph, CE::Decompiler::FunctionPCodeGraph* funcGraph);

		json createFuncPCodeGraphJson(CE::Decompiler::FunctionPCodeGraph* funcPCodeGraph);

		void bind(SQLite::Statement& query, Decompiler::ImagePCodeGraph* imgPCodeGraph);
	};
};