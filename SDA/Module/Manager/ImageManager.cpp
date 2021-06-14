#include "ImageManager.h"
#include <DB/Mappers/ImageMapper.h>
#include <Manager/SymbolTableManager.h>

using namespace CE;

CE::ImageManager::ImageManager(Project* project)
	: AbstractItemManager(project)
{
	m_imageMapper = new DB::ImageMapper(this);
}

ImageDecorator* CE::ImageManager::createImage(AddressSpace* addressSpace, ImageDecorator::IMAGE_TYPE type, Symbol::SymbolTable* globalSymbolTable, Symbol::SymbolTable* vfuncCallSymbolTable, const std::string& name, const std::string& comment, bool generateId) {
	auto imageDec = new ImageDecorator(this, addressSpace, type, globalSymbolTable, vfuncCallSymbolTable, name, comment);
	imageDec->setMapper(m_imageMapper);
	if (generateId)
		imageDec->setId(m_imageMapper->getNextId());
	return imageDec;
}

ImageDecorator* CE::ImageManager::createImage(AddressSpace* addressSpace, ImageDecorator::IMAGE_TYPE type, const std::string& name, const std::string& comment, bool generateId) {
	auto factory = getProject()->getSymTableManager()->getFactory();
	auto globalSymbolTable = factory.createSymbolTable(Symbol::SymbolTable::GLOBAL_SPACE, 0x100000000);
	auto vfuncCallSymbolTable = factory.createSymbolTable(Symbol::SymbolTable::GLOBAL_SPACE, 0x100000000);
	return createImage(addressSpace, type, globalSymbolTable, vfuncCallSymbolTable, name, comment, generateId);
}

void CE::ImageManager::loadImages() {
	m_imageMapper->loadAll();
}

ImageDecorator* CE::ImageManager::findImageById(DB::Id id) {
	return dynamic_cast<ImageDecorator*>(find(id));
}

ImageDecorator* CE::ImageManager::findImageByName(const std::string& name) {
	Iterator it(this);
	while (it.hasNext()) {
		auto item = it.next();
		if (item->getName() == name) {
			return item;
		}
	}
	throw ItemNotFoundException();
}
