#include "StatManager.h"

using namespace CE;

StatManager::StatManager(Project* sda)
	: AbstractManager(sda)
{
	auto bufferDir = getProject()->getDirectory().next("buffers");
	bufferDir.createIfNotExists();

	m_collector = new Stat::Function::Collector(bufferDir);
}

StatManager::~StatManager() {
	delete m_collector;
}

Stat::Function::Collector* StatManager::getCollector() {
	return m_collector;
}