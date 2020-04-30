#include "Address.h"

bool CE::Address::canBeRead() {
	__try {
		byte firstByte = *(byte*)m_addr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
}

HMODULE CE::Address::getModuleHandle() {
	return (HMODULE)getInfo().AllocationBase;
}

MEMORY_BASIC_INFORMATION CE::Address::getInfo() {
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(m_addr, &mbi, sizeof(mbi));
	return mbi;
}

CE::Address CE::Address::dereference() {
	return Address((void*)*(std::uintptr_t*)m_addr);
}

void CE::Address::setProtect(ProtectFlags flags, int size) {
	DWORD new_ = PAGE_NOACCESS;
	DWORD old_;

	switch (flags)
	{
	case Read:
		new_ = PAGE_READONLY;
		break;
	case Write:
	case Read | Write:
		new_ = PAGE_READWRITE;
		break;
	case Execute:
		new_ = PAGE_EXECUTE;
		break;
	case Execute | Read:
		new_ = PAGE_EXECUTE_READ;
		break;
	case Execute | Write:
	case Execute | Read | Write:
		new_ = PAGE_EXECUTE_READWRITE;
		break;
	}

	VirtualProtect(m_addr, size, new_, &old_);
}

CE::Address::ProtectFlags CE::Address::getProtect() {
	auto protect = getInfo().Protect;
	DWORD result = 0;

	if (protect & PAGE_READONLY)
		result |= Read;
	if (protect & PAGE_READWRITE)
		result |= Read | Write;
	if (protect & PAGE_EXECUTE)
		result |= Execute;
	if (protect & PAGE_EXECUTE_READ)
		result |= Execute | Read;
	if (protect & PAGE_EXECUTE_READWRITE)
		result |= Execute | Read | Write;

	return (ProtectFlags)result;
}

void* CE::Address::Dereference(void* addr, int level)
{
	for (int i = 0; i < level; i++) {
		if (!Address(addr).canBeRead())
			return nullptr;
		addr = (void*)*(std::uintptr_t*)addr;
	}
	return addr;
}