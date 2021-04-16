#include "Decompiler.h"
#include "DecGraphBlockLinker.h"

using namespace CE::Decompiler;

void Decompiler::start() {
	decompileAllBlocks();
	setAllBlocksLinks();
	buildDecompiledGraph();

	GraphBlockLinker graphBlockLinker(m_decompiledGraph, this);
	graphBlockLinker.start();
}

void Decompiler::buildDecompiledGraph() {
	for (auto& it : m_decompiledBlocks) {
		auto& info = it.second;
		m_decompiledGraph->getDecompiledBlocks().push_back(info.m_decBlock);
		m_decompiledGraph->getAsmGraphBlocks()[info.m_decBlock] = info.m_pcodeBlock;
	}
	m_decompiledGraph->sortBlocksByLevel();
}
