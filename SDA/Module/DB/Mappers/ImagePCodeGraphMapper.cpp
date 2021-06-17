#include "ImagePCodeGraphMapper.h"
#include <Manager/ImagePCodeGraphManager.h>

using namespace DB;
using namespace CE;
using namespace CE::Decompiler;

void DB::ImagePCodeGraphMapper::loadAll() {
	auto& db = getManager()->getProject()->getDB();
	Statement query(db, "SELECT * FROM sda_img_pcode_graphs");
	load(&db, query);
}

Id DB::ImagePCodeGraphMapper::getNextId() {
	auto& db = getManager()->getProject()->getDB();
	return GenerateNextId(&db, "sda_img_pcode_graphs");
}

CE::ImagePCodeGraphManager* DB::ImagePCodeGraphMapper::getManager() {
	return static_cast<ImagePCodeGraphManager*>(m_repository);
}

IDomainObject* DB::ImagePCodeGraphMapper::doLoad(Database* db, SQLite::Statement& query) {
	int graph_id = query.getColumn("graph_id");
	std::string json_instr_pool_str = query.getColumn("json_instr_pool");
	auto json_instr_pool = json::parse(json_instr_pool_str);

	auto imgPCodeGraph = getManager()->createImagePCodeGraph();
	// load modified instructions for instr. pool
	for (const auto& json_mod_instr : json_instr_pool["mod_instructions"]) {
		auto offset = json_mod_instr["offset"].get<int64_t>();
		auto mod = json_mod_instr["mod"].get<Decompiler::PCode::InstructionPool::MODIFICATOR>();
		imgPCodeGraph->getInstrPool()->m_modifiedInstructions[offset] = mod;
	}

	imgPCodeGraph->setId(graph_id);
	return imgPCodeGraph;
}

void DB::ImagePCodeGraphMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void DB::ImagePCodeGraphMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto imgPCodeGraph = dynamic_cast<ImagePCodeGraph*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_img_pcode_graphs (graph_id, json_instr_pool, save_id) VALUES(?1, ?2, ?3)");
	query.bind(1, imgPCodeGraph->getId());
	bind(query, imgPCodeGraph);
	query.bind(3, ctx->m_saveId);
	query.exec();
}

void DB::ImagePCodeGraphMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_img_pcode_graphs SET deleted=1" : "DELETE FROM sda_img_pcode_graphs";
	Statement query(*ctx->m_db, action_query_text + " WHERE graph_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void DB::ImagePCodeGraphMapper::bind(SQLite::Statement& query, Decompiler::ImagePCodeGraph* imgPCodeGraph) {
	json json_instr_pool;
	json json_mod_instrs;
	for (auto& pair : imgPCodeGraph->getInstrPool()->m_modifiedInstructions) {
		json json_mod_instr;
		json_mod_instr["offset"] = pair.first;
		json_mod_instr["mod"] = pair.second;
		json_mod_instrs.push_back(json_mod_instr);
	}
	json_instr_pool["mod_instructions"] = json_mod_instrs;

	query.bind(2, json_instr_pool.dump());
}
