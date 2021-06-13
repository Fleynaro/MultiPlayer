#include "ImageMapper.h"
#include <Manager/ImageManager.h>
#include <Manager/AddressSpaceManager.h>
#include <Manager/SymbolTableManager.h>

using namespace DB;
using namespace CE;

DB::ImageMapper::ImageMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void DB::ImageMapper::loadAll() {
	auto& db = getManager()->getProject()->getDB();
	Statement query(db, "SELECT * FROM sda_images");
	load(&db, query);
}

Id DB::ImageMapper::getNextId() {
	auto& db = getManager()->getProject()->getDB();
	return GenerateNextId(&db, "sda_images");
}

CE::ImageManager* DB::ImageMapper::getManager() {
	return static_cast<ImageManager*>(m_repository);
}

IDomainObject* DB::ImageMapper::doLoad(Database* db, SQLite::Statement& query) {
	int image_id = query.getColumn("image_id");
	auto type = (CE::ImageDecorator::IMAGE_TYPE)(int)query.getColumn("type");
	//std::uintptr_t addr = (int64_t)query.getColumn("addr");
	std::string name = query.getColumn("name");
	std::string comment = query.getColumn("comment");
	int addr_space_id = query.getColumn("addr_space_id");
	int global_table_id = query.getColumn("global_table_id");
	int vfunc_call_table_id = query.getColumn("vfunc_call_table_id");
	
	auto project = getManager()->getProject();
	auto addrSpace = project->getAddrSpaceManager()->findAddressSpaceById(addr_space_id);
	auto globalSymTable = project->getSymTableManager()->findSymbolTableById(global_table_id);
	auto vfuncCallSymTable = project->getSymTableManager()->findSymbolTableById(vfunc_call_table_id);

	auto image = getManager()->createImage(addrSpace, type, globalSymTable, vfuncCallSymTable, name, comment, false);
	image->load();

	addrSpace->getImages()[image->getAddress()] = image;

	image->setId(image_id);
	return image;
}

void DB::ImageMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void DB::ImageMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto as = dynamic_cast<ImageDecorator*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_images (image_id, type, name, comment, addr_space_id, global_table_id, vfunc_call_table_id, save_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6,? 7, ?8)");
	query.bind(1, as->getId());
	bind(query, *as);
	query.bind(8, ctx->m_saveId);
	query.exec();
}

void DB::ImageMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_images SET deleted=1" : "DELETE FROM sda_images";
	Statement query(*ctx->m_db, action_query_text + " WHERE image_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void DB::ImageMapper::bind(SQLite::Statement& query, CE::ImageDecorator& imageDec) {
	query.bind(2, imageDec.getType());
	query.bind(3, imageDec.getName());
	query.bind(4, imageDec.getComment());
	query.bind(5, imageDec.getAddressSpace()->getId());
	query.bind(6, imageDec.getGlobalSymbolTable()->getId());
	query.bind(7, imageDec.getVFuncCallSymbolTable()->getId());
}
