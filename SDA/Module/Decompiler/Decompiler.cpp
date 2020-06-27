#include "Decompiler.h"

using namespace CE::Decompiler;

void Decompiler::buildDecompiledGraph() {
	for (auto& it : m_decompiledBlocks) {
		m_decompiledGraph->getDecompiledBlocks().push_back(it.second.m_decBlock);
	}

	m_decompiledGraph->getDecompiledBlocks().sort([](PrimaryTree::Block* a, PrimaryTree::Block* b) {
		return a->m_level < b->m_level;
		});
}
