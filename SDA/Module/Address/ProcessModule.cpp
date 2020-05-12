#include "ProcessModule.h"
#include <Psapi.h>

using namespace CE;

int CE::GetModuleSize(HMODULE module) {
	MODULEINFO lpmodinfo;
	GetModuleInformation(GetCurrentProcess(), module, &lpmodinfo, sizeof(MODULEINFO));
	return lpmodinfo.SizeOfImage;
}

ProccessModule::ProccessModule(ProcessModuleManager* manager, HMODULE module, const std::string& name, const std::string& comment)
	: AddressRange(module, GetModuleSize(module)), Descrtiption(name, comment)
{}

std::uintptr_t ProccessModule::getBaseAddr() {
	return (std::uintptr_t)getMinAddress();
}

void* ProccessModule::toAbsAddr(int offset) {
	return offset == 0 ? nullptr : reinterpret_cast<void*>(getBaseAddr() + (std::uintptr_t)offset);
}

int ProccessModule::toRelAddr(void* addr) {
	return addr == nullptr ? 0 : static_cast<int>((std::uintptr_t)addr - getBaseAddr());
}

ProcessModuleManager* ProccessModule::getManager() {
	return m_manager;
}
