#include "Address.h"

using namespace CE;

bool Address::canBeRead() {
	__try {
		byte firstByte = *(byte*)m_addr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
}

HMODULE Address::getModuleHandle() {
	return (HMODULE)getInfo().AllocationBase;
}

MEMORY_BASIC_INFORMATION Address::getInfo() {
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(m_addr, &mbi, sizeof(mbi));
	return mbi;
}

Address Address::dereference() {
	return Address((void*)*(std::uintptr_t*)m_addr);
}

void Address::addOffset(int offset) {
	(std::uintptr_t&)m_addr += offset;
}

void Address::setProtect(ProtectFlags flags, int size) {
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

Address::ProtectFlags Address::getProtect() {
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

void* Address::Dereference(void* addr, int level)
{
	for (int i = 0; i < level; i++) {
		if (!Address(addr).canBeRead())
			return nullptr;
		addr = (void*)*(std::uintptr_t*)addr;
	}
	return addr;
}

DereferenceIterator::DereferenceIterator(Address addr, DataTypePtr type)
	: m_addr(addr), m_curAddr(nullptr), m_type(type)
{
	m_levels = m_type->getPointerLevels();
	m_cur_levels = std::list<int>(m_levels.size(), 0);

	/*if (type->isString()) {
		m_levels.pop_back();
		m_levels.push_back(1);
	}*/
}

bool DereferenceIterator::hasNext() {
	if (m_isEnd)
		return false;

	m_curAddr = dereference();
	if (!m_curAddr.canBeRead()) {
		goNext();
		return hasNext();
	}

	return true;
}

DereferenceIteratorItemType DereferenceIterator::next() {
	auto result = std::make_pair(m_curAddr.getAddress(), m_type->getBaseType());
	goNext();
	return result;
}

void DereferenceIterator::goNext() {
	auto it = m_cur_levels.rbegin();
	auto it2 = m_levels.rbegin();
	while (it != m_cur_levels.rend()) {
		if (++(*it) < *it2) {
			break;
		}
		*it = 0;
		it++;
		it2++;
	}
	if (it == m_cur_levels.rend()) {
		m_isEnd = true;
	}
}

Address DereferenceIterator::dereference() {
	auto it = m_cur_levels.begin();
	Address addr = m_addr;
	while (it != std::prev(m_cur_levels.end())) {
		addr.addOffset(*it * 0x8);
		if (!addr.canBeRead()) {
			return Address(nullptr);
		}
		addr = addr.dereference();
		it++;
	}
	if (!m_cur_levels.empty()) {
		addr.addOffset(*it * m_type->getBaseType()->getSize());
	}
	return addr;
}
