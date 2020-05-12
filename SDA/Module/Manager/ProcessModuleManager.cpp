#include "ProcessModuleManager.h"
#include <DB/Mappers/ProcessModuleMapper.h>

using namespace CE;

ProcessModuleManager::ProcessModuleManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_proccessModuleMapper = new DB::ProcessModuleMapper(this);
	m_mainModule = new ProccessModule(this, GetModuleHandle(NULL), "main", "this is a main .exe module");
	m_mainModule->setId(1);
	m_items.insert(std::make_pair(1, m_mainModule));
}

ProcessModuleManager::~ProcessModuleManager() {
	delete m_mainModule;
}

void ProcessModuleManager::loadProcessModules()
{
	m_proccessModuleMapper->loadAll();
}

ProccessModule* ProcessModuleManager::createProcessModule(const std::string& name, const std::string& comment)
{
	auto module = new ProccessModule(this, GetModuleHandle(name.c_str()), name, comment);
	module->setMapper(m_proccessModuleMapper);
	module->setId(m_proccessModuleMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(module);
	return module;
}

ProccessModule* ProcessModuleManager::getProcessModuleById(DB::Id id)
{
	return static_cast<ProccessModule*>(find(id));
}

ProccessModule* ProcessModuleManager::getProcessModuleByName(const std::string& name)
{
	Iterator it(this);
	while (it.hasNext()) {
		auto module = it.next();
		if (module->getName() == name) {
			return module;
		}
	}
	return nullptr;
}

ProccessModule* ProcessModuleManager::getMainModule() {
	return m_mainModule;
}
