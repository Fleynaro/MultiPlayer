#pragma once
#include "AddressRange.h"
#include <DB/DomainObject.h>
#include <Utils/Description.h>

namespace CE
{
	int GetModuleSize(HMODULE module);

	class ProcessModuleManager;

	class ProccessModule : public AddressRange, public DB::DomainObject, public Descrtiption
	{
	public:
		ProccessModule(ProcessModuleManager* manager, HMODULE module, const std::string& name, const std::string& comment);

		std::uintptr_t getBaseAddr();

		void* toAbsAddr(int offset);

		int toRelAddr(void* addr);

		ProcessModuleManager* getManager();

	private:
		ProcessModuleManager* m_manager;
	};
};