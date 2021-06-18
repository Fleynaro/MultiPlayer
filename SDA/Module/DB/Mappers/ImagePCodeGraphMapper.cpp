#include "ImagePCodeGraphMapper.h"
#include <Manager/ImagePCodeGraphManager.h>
#include <Manager/TypeManager.h>
#include <Decompiler/PCode/Decoders/DecPCodeDecoderX86.h>

using namespace DB;
using namespace CE;
using namespace CE::Decompiler;

void DB::ImagePCodeGraphMapper::loadAll() {
	auto& db = getManager()->getProject()->getDB();
	Statement query(db, "SELECT * FROM sda_img_func_graphs");
	load(&db, query);
}

Id DB::ImagePCodeGraphMapper::getNextId() {
	auto& db = getManager()->getProject()->getDB();
	return GenerateNextId(&db, "sda_img_func_graphs");
}

CE::ImagePCodeGraphManager* DB::ImagePCodeGraphMapper::getManager() {
	return static_cast<ImagePCodeGraphManager*>(m_repository);
}

IDomainObject* DB::ImagePCodeGraphMapper::doLoad(Database* db, SQLite::Statement& query) {
	int graph_id = query.getColumn("graph_id");
	std::string json_instr_pool_str = query.getColumn("json_instr_pool");
	auto json_instr_pool = json::parse(json_instr_pool_str);
	std::string json_vfunc_calls_str = query.getColumn("json_vfunc_calls");
	auto json_vfunc_calls = json::parse(json_vfunc_calls_str);
	std::string json_func_graphs_str = query.getColumn("json_func_graphs");
	auto json_func_graphs = json::parse(json_func_graphs_str);

	auto imgPCodeGraph = getManager()->createImagePCodeGraph();
	// load modified instructions for instr. pool
	for (const auto& json_mod_instr : json_instr_pool["mod_instructions"]) {
		auto offset = json_mod_instr["offset"].get<int64_t>();
		auto mod = json_mod_instr["mod"].get<Decompiler::PCode::InstructionPool::MODIFICATOR>();
		imgPCodeGraph->getInstrPool()->m_modifiedInstructions[offset] = mod;
	}
	// load virtual func. calls
	for (const auto& json_vfunc_call : json_vfunc_calls) {
		auto offset = json_vfunc_call["offset"].get<int64_t>();
		auto sig_id = json_vfunc_call["sig_id"].get<DB::Id>();
		auto funcSig = dynamic_cast<DataType::IFunctionSignature*>(getManager()->getProject()->getTypeManager()->findTypeById(sig_id));
		imgPCodeGraph->getVirtFuncCalls()[offset] = funcSig;
	}
	// load pcode func. graphs
	for (const auto& json_func_graph : json_func_graphs) {
		auto funcGraph = imgPCodeGraph->createFunctionGraph();
		loadFuncPCodeGraphJson(json_func_graph, funcGraph);
	}
	// load pcode func. graph connections
	for (const auto& json_func_graph : json_func_graphs) {
		auto start_block = json_func_graph["start_block"].get<int64_t>();
		auto funcGraph = imgPCodeGraph->getFuncGraphAt(start_block);
		// load non-virt func calls
		for (const auto& json_nv_func : json_func_graph["nv_func_calls"]) {
			auto nonVirtFuncOffset = json_nv_func.get<int64_t>();
			auto otherFuncGraph = imgPCodeGraph->getFuncGraphAt(nonVirtFuncOffset);
			funcGraph->addNonVirtFuncCall(otherFuncGraph);
		}
		// load virt func calls
		for (const auto& json_v_func : json_func_graph["v_func_calls"]) {
			auto virtFuncOffset = json_v_func.get<int64_t>();
			auto otherFuncGraph = imgPCodeGraph->getFuncGraphAt(virtFuncOffset);
			funcGraph->addVirtFuncCall(otherFuncGraph);
		}
	}

	imgPCodeGraph->fillHeadFuncGraphs();
	imgPCodeGraph->setId(graph_id);
	return imgPCodeGraph;
}

void DB::ImagePCodeGraphMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void DB::ImagePCodeGraphMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto imgPCodeGraph = dynamic_cast<ImagePCodeGraph*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_img_func_graphs (graph_id, json_instr_pool, json_vfunc_calls, json_func_graphs, save_id) VALUES(?1, ?2, ?3, ?4, ?5)");
	query.bind(1, imgPCodeGraph->getId());
	bind(query, imgPCodeGraph);
	query.bind(5, ctx->m_saveId);
	query.exec();
}

void DB::ImagePCodeGraphMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_img_func_graphs SET deleted=1" : "DELETE FROM sda_img_func_graphs";
	Statement query(*ctx->m_db, action_query_text + " WHERE graph_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void DB::ImagePCodeGraphMapper::decodePCodeBlock(CE::Decompiler::PCodeBlock* block) {
	WarningContainer warningContainer;
	RegisterFactoryX86 registerFactoryX86;
	PCode::DecoderX86 decoder(&registerFactoryX86, &warningContainer);
	auto offset = block->getMinOffset() >> 8;
	while (offset < block->getMaxOffset() >> 8) {
		decoder.decode(bytes.data() + offset, offset, (int)bytes.size());
		if (!decoder.getOrigInstruction())
			break;
		for (auto instr : decoder.getDecodedPCodeInstructions()) {
			block->getInstructions().push_back(instr);
		}
		offset += decoder.getOrigInstruction()->m_length;
	}
}

void DB::ImagePCodeGraphMapper::loadFuncPCodeGraphJson(const json& json_func_graph, CE::Decompiler::FunctionPCodeGraph* funcGraph) {
	auto imgPCodeGraph = funcGraph->getImagePCodeGraph();

	// load blocks
	for (const auto& json_pcode_block : json_func_graph["blocks"]) {
		auto level = json_pcode_block["level"].get<int>();
		auto min_offset = json_pcode_block["min_offset"].get<int64_t>();
		auto max_offset = json_pcode_block["max_offset"].get<int64_t>();

		auto block = imgPCodeGraph->createBlock(min_offset, max_offset);
		block->m_level = level;
		funcGraph->addBlock(block);
	}
	// load block connections
	for (const auto& json_pcode_block : json_func_graph["blocks"]) {
		auto min_offset = json_pcode_block["min_offset"].get<int64_t>();
		auto block = imgPCodeGraph->getBlockAtOffset(min_offset);

		if (!json_pcode_block["next_near_block"].is_null()) {
			auto next_near_block = json_pcode_block["next_near_block"].get<int64_t>();
			auto nextNearBlock = imgPCodeGraph->getBlockAtOffset(next_near_block);
			block->setNextNearBlock(nextNearBlock);
		}
		if (!json_pcode_block["next_far_block"].is_null()) {
			auto next_far_block = json_pcode_block["next_far_block"].get<int64_t>();
			auto nextFarBlock = imgPCodeGraph->getBlockAtOffset(next_far_block);
			block->setNextNearBlock(nextFarBlock);
		}
	}
	// load start block
	auto start_block = json_func_graph["start_block"].get<int64_t>();
	auto startBlock = imgPCodeGraph->getBlockAtOffset(start_block);
	funcGraph->setStartBlock(startBlock);
}

json DB::ImagePCodeGraphMapper::createFuncPCodeGraphJson(CE::Decompiler::FunctionPCodeGraph* funcPCodeGraph) {
	json json_func_graph;

	// save pcode blocks
	json json_pcode_blocks;
	for (auto pcodeBlock : funcPCodeGraph->getBlocks()) {
		json json_pcode_block;
		json_pcode_block["level"] = pcodeBlock->m_level;
		json_pcode_block["min_offset"] = pcodeBlock->getMinOffset();
		json_pcode_block["max_offset"] = pcodeBlock->getMaxOffset();
		if (pcodeBlock->getNextNearBlock())
			json_pcode_block["next_near_block"] = pcodeBlock->getNextNearBlock()->getMinOffset();
		if (pcodeBlock->getNextFarBlock())
			json_pcode_block["next_far_block"] = pcodeBlock->getNextFarBlock()->getMinOffset();
		json_pcode_blocks.push_back(json_pcode_block);
	}
	json_func_graph["blocks"] = json_pcode_blocks;

	// save non-virt func calls
	json json_nv_func_calls;
	for (auto funcGraph : funcPCodeGraph->getNonVirtFuncCalls()) {
		json_nv_func_calls.push_back(funcGraph->getStartBlock()->getMinOffset());
	}
	json_func_graph["nv_func_calls"] = json_nv_func_calls;

	// save virt func calls
	json json_v_func_calls;
	for (auto funcGraph : funcPCodeGraph->getVirtFuncCalls()) {
		json_v_func_calls.push_back(funcGraph->getStartBlock()->getMinOffset());
	}
	json_func_graph["v_func_calls"] = json_v_func_calls;

	// save other
	json_func_graph["start_block"] = funcPCodeGraph->getStartBlock()->getMinOffset();

	return json_func_graph;
}

void DB::ImagePCodeGraphMapper::bind(SQLite::Statement& query, Decompiler::ImagePCodeGraph* imgPCodeGraph) {
	json json_instr_pool;
	json json_vfunc_calls;
	json json_func_graphs;

	// save modified instructions
	json json_mod_instrs;
	for (auto& pair : imgPCodeGraph->getInstrPool()->m_modifiedInstructions) {
		json json_mod_instr;
		json_mod_instr["offset"] = pair.first;
		json_mod_instr["mod"] = pair.second;
		json_mod_instrs.push_back(json_mod_instr);
	}
	json_instr_pool["mod_instructions"] = json_mod_instrs;

	// save virtual func. calls
	for (auto& pair : imgPCodeGraph->getVirtFuncCalls()) {
		json json_vfunc_call;
		json_vfunc_call["offset"] = pair.first;
		json_vfunc_call["sig_id"] = pair.second->getId();
		json_vfunc_calls.push_back(json_vfunc_call);
	}

	// save pcode func. graphs
	for (auto& funcGraph : imgPCodeGraph->getFunctionGraphList()) {
		auto json_func_graph = createFuncPCodeGraphJson(&funcGraph);
		json_func_graphs.push_back(json_func_graph);
	}

	query.bind(2, json_instr_pool.dump());
	query.bind(3, json_vfunc_calls.dump());
	query.bind(4, json_func_graphs.dump());
}

