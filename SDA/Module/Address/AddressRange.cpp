#include "AddressRange.h"

using namespace CE;

AddressRange::AddressRange(void* min_addr, void* max_addr)
	: m_min_addr(min_addr), m_max_addr(max_addr)
{}

AddressRange::AddressRange(void* entry_addr, int size)
	: m_min_addr(entry_addr), m_max_addr((void*)((std::uintptr_t)entry_addr + size))
{}

bool AddressRange::isContainingAddress(void* addr) {
	return (std::uintptr_t)addr >= (std::uintptr_t)getMinAddress() && (std::uintptr_t)addr <= (std::uintptr_t)getMaxAddress();
}

std::uintptr_t AddressRange::getSize() {
	return (std::uintptr_t)getMaxAddress() - (std::uintptr_t)getMinAddress();
}

void* AddressRange::getMinAddress() {
	return m_min_addr;
}

void* AddressRange::getMaxAddress() {
	return m_max_addr;
}
