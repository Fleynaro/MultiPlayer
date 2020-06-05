#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

ExprTree::Node* ExecutionBlockContext::getRegister(ZydisRegister reg) {
	/*if (m_registers.find(reg) != m_registers.end()) {
		return m_registers[reg];
	}*/
	return m_decompiler->requestRegister(reg);
}
