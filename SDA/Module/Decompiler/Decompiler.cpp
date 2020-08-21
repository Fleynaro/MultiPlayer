#include "Decompiler.h"

using namespace CE::Decompiler;

void Decompiler::buildDecompiledGraph() {
	for (auto& it : m_decompiledBlocks) {
		auto& info = it.second;
		m_decompiledGraph->getDecompiledBlocks().push_back(info.m_decBlock);
		m_decompiledGraph->getAsmGraphBlocks()[info.m_decBlock] = info.m_asmBlock;
	}
	m_decompiledGraph->sortBlocksByLevel();
}
