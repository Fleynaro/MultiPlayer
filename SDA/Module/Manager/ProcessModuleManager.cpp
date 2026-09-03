#include "ProcessModuleManager.h"
#include <DB/Mappers/ProcessModuleMapper.h>
#include <psapi.h>

using namespace CE;

ProcessModuleManager::ProcessModuleManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_processModuleMapper = new DB::ProcessModuleMapper(this);
	m_mainModule = new ProcessModule(this, GetModuleHandle(NULL), "main", "this is a main .exe module");
	m_mainModule->setId(1);
	m_items.insert(std::make_pair(1, m_mainModule));
}

ProcessModuleManager::~ProcessModuleManager() {
	delete m_mainModule;
}

void ProcessModuleManager::loadProcessModules()
{
	m_processModuleMapper->loadAll();
}

ProcessModule* ProcessModuleManager::createProcessModule(HMODULE hModule, const std::string& comment)
{
	auto module = new ProcessModule(this, hModule, comment);
	module->setMapper(m_processModuleMapper);
	module->setId(m_processModuleMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(module);
	return module;
}

ProcessModule* ProcessModuleManager::createProcessModule(FS::File file, const std::string& comment)
{
	return createProcessModule(GetModuleHandle(file.getFilename().c_str()), comment);
}

ProcessModule* ProcessModuleManager::getProcessModuleById(DB::Id id)
{
	return static_cast<ProcessModule*>(find(id));
}

ProcessModule* ProcessModuleManager::getProcessModuleByName(const std::string& name)
{
	using namespace Generic::String;
	Iterator it(this);
	while (it.hasNext()) {
		auto module = it.next();
		if (ToLower(module->getName()) == ToLower(name)) {
			return module;
		}
	}
	return nullptr;
}

ProcessModule* ProcessModuleManager::findProcessModule(HMODULE hModule)
{
	Iterator it(this);
	while (it.hasNext()) {
		auto module = it.next();
		if (module->getHModule() == hModule) {
			return module;
		}
	}
	return nullptr;
}

ProcessModule* ProcessModuleManager::getMainModule() {
	return m_mainModule;
}

std::list<HMODULE> ProcessModuleManager::getCurrentlyLoadedModules() {
	std::list<HMODULE> result;
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	hProcess = GetCurrentProcess();
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			result.push_back(hMods[i]);
		}
	}

	return result;
}
