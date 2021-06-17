#include "ImagePCodeGraphManager.h"
#include <DB/Mappers/ImagePCodeGraphMapper.h>

using namespace CE;

CE::ImagePCodeGraphManager::ImagePCodeGraphManager(Project* project)
	: AbstractItemManager(project)
{
	m_imagePCodeGraphMapper = new DB::ImagePCodeGraphMapper(this);
}

Decompiler::ImagePCodeGraph* CE::ImagePCodeGraphManager::createImagePCodeGraph(bool generateId) {
	auto imagePCodeGraph = new Decompiler::ImagePCodeGraph();
	imagePCodeGraph->setMapper(m_imagePCodeGraphMapper);
	if (generateId)
		imagePCodeGraph->setId(m_imagePCodeGraphMapper->getNextId());
	return imagePCodeGraph;
}

void CE::ImagePCodeGraphManager::loadImagePCodeGraphs() {
	m_imagePCodeGraphMapper->loadAll();
}

Decompiler::ImagePCodeGraph* CE::ImagePCodeGraphManager::findImagePCodeGraphById(DB::Id id) {
	return dynamic_cast<Decompiler::ImagePCodeGraph*>(find(id));
}
