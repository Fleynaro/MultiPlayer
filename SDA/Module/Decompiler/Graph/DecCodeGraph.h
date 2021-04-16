#pragma once
#include "DecCodeGraphBlock.h"
#include "DecPCodeGraph.h"
#include "../DecStorage.h"

namespace CE::Decompiler
{
	class DecompiledCodeGraph
	{
	public:
		DecompiledCodeGraph(FunctionPCodeGraph* asmGraph, FunctionCallInfo functionCallInfo)
			: m_funcGraph(asmGraph), m_functionCallInfo(functionCallInfo)
		{}

		FunctionPCodeGraph* getFuncGraph() {
			return m_funcGraph;
		}

		std::map<PrimaryTree::Block*, PCodeBlock*>& getAsmGraphBlocks() {
			return m_decBlockToBlock;
		}

		PrimaryTree::Block* getStartBlock() {
			return *getDecompiledBlocks().begin();
		}

		std::list<PrimaryTree::Block*>& getDecompiledBlocks() {
			return m_decompiledBlocks;
		}

		FunctionCallInfo& getFunctionCallInfo() {
			return m_functionCallInfo;;
		}

		std::list<Symbol::Symbol*>& getSymbols() {
			return m_symbols;
		}

		void removeDecompiledBlock(PrimaryTree::Block* decBlock) {
			m_decompiledBlocks.remove(decBlock);
			m_removedDecompiledBlocks.push_back(decBlock);
			decBlock->disconnect();
		}

		void addSymbol(Symbol::Symbol* symbol) {
			symbol->setDecGraph(this);
			m_symbols.push_back(symbol);
		}

		void removeSymbol(Symbol::Symbol* symbol) {
			m_symbols.remove(symbol);
		}

		DecompiledCodeGraph* clone() {
			PrimaryTree::BlockCloneContext ctx;
			ctx.m_graph = new DecompiledCodeGraph(m_funcGraph, m_functionCallInfo);
			ctx.m_nodeCloneContext.m_cloneSymbols = true;
			getStartBlock()->clone(&ctx);
			for (auto pair : ctx.m_clonedBlocks) {
				auto origBlock = pair.first;
				auto clonedBlock = pair.second;
				ctx.m_graph->m_decompiledBlocks.push_back(clonedBlock);
				ctx.m_graph->m_decBlockToBlock[clonedBlock] = m_decBlockToBlock[origBlock];
			}
			for (auto block : m_removedDecompiledBlocks) {
				ctx.m_graph->m_removedDecompiledBlocks.push_back(block->clone(&ctx));
			}
			for (auto pair : ctx.m_nodeCloneContext.m_clonedSymbols) {
				auto clonedSymbol = pair.second;
				ctx.m_graph->m_symbols.push_back(clonedSymbol);
			}
			ctx.m_graph->sortBlocksByLevel();
			return ctx.m_graph;
		}

		void sortBlocksByLevel() {
			m_decompiledBlocks.sort([](PrimaryTree::Block* a, PrimaryTree::Block* b) {
				return a->m_level < b->m_level;
				});
		}

		void checkOnSingleParents() {
			for (const auto decBlock : getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					ExprTree::INode::UpdateDebugInfo(topNode->getNode());
					topNode->getNode()->checkOnSingleParents();
				}
			}
		}

		HS getHash() {
			HS hs;
			for (const auto decBlock : getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					hs = hs << topNode->getNode()->getHash();
				}
			}
			return hs;
		}

		// recalculate levels because some blocks can be removed (while parsing AND/OR block constructions)
		void recalculateLevelsForBlocks() {
			for (const auto decBlock : getDecompiledBlocks()) {
				decBlock->m_level = 0;
			}
			std::list<PrimaryTree::Block*> path;
			DecompiledCodeGraph::CalculateLevelsForDecBlocks(getStartBlock(), path);
		}

		// calculate count of lines(height) for each block beginining from lower blocks (need as some score for linearization)
		static int CalculateHeightForDecBlocks(PrimaryTree::Block* block) {
			int height = 0;
			for (auto nextBlock : block->getNextBlocks()) {
				if (nextBlock->m_level > block->m_level) { // to avoid loops
					auto h = CalculateHeightForDecBlocks(nextBlock);
					height = max(height, h);
				}
			}
			block->m_maxHeight = height + (int)block->getSeqAssignmentLines().size();
			return block->m_maxHeight;
		}
	private:
		FunctionPCodeGraph* m_funcGraph;
		std::map<PrimaryTree::Block*, PCodeBlock*> m_decBlockToBlock;
		std::list<PrimaryTree::Block*> m_decompiledBlocks;
		std::list<PrimaryTree::Block*> m_removedDecompiledBlocks;
		FunctionCallInfo m_functionCallInfo;
		std::list<Symbol::Symbol*> m_symbols;

		// pass decompiled graph and calculate max distance from the root to each node (dec block). Similarly to asm graph!
		static void CalculateLevelsForDecBlocks(PrimaryTree::Block* block, std::list<PrimaryTree::Block*>& path) {
			if (block == nullptr)
				return;

			//check if there's a loop
			for (auto it = path.rbegin(); it != path.rend(); it++) {
				if (block == *it) {
					return;
				}
			}

			path.push_back(block);
			block->m_level = max(block->m_level, (int)path.size());
			CalculateLevelsForDecBlocks(block->getNextNearBlock(), path);
			CalculateLevelsForDecBlocks(block->getNextFarBlock(), path);
			path.pop_back();
		}
	};
};