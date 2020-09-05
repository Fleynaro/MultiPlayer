#pragma once
#include "DecCodeGraphBlock.h"
#include "DecAsmGraph.h"
#include "../DecStorage.h"

namespace CE::Decompiler
{
	class DecompiledCodeGraph
	{
	public:
		DecompiledCodeGraph(AsmGraph* asmGraph, FunctionCallInfo functionCallInfo)
			: m_asmGraph(asmGraph), m_functionCallInfo(functionCallInfo)
		{}

		AsmGraph* getAsmGraph() {
			return m_asmGraph;
		}

		std::map<PrimaryTree::Block*, AsmGraphBlock*>& getAsmGraphBlocks() {
			return m_asmGraphBlocks;
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
			ctx.m_graph = new DecompiledCodeGraph(m_asmGraph, m_functionCallInfo);
			ctx.m_nodeCloneContext.m_cloneSymbols = true;
			getStartBlock()->clone(&ctx);
			for (auto pair : ctx.m_clonedBlocks) {
				auto origBlock = pair.first;
				auto clonedBlock = pair.second;
				ctx.m_graph->m_decompiledBlocks.push_back(clonedBlock);
				ctx.m_graph->m_asmGraphBlocks[clonedBlock] = m_asmGraphBlocks[origBlock];
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

		void generateSymbolIds() {
			int memVar_id = 1;
			int localVar_id = 1;
			int funcVar_id = 1;
			for (auto symbol : m_symbols) {
				if (auto var = dynamic_cast<Symbol::MemoryVariable*>(symbol)) {
					var->setId(memVar_id++);
				} else if (auto var = dynamic_cast<Symbol::LocalVariable*>(symbol)) {
					var->setId(localVar_id++);
				} else if (auto var = dynamic_cast<Symbol::FunctionResultVar*>(symbol)) {
					var->setId(funcVar_id++);
				}
			}
		}

		void sortBlocksByLevel() {
			m_decompiledBlocks.sort([](PrimaryTree::Block* a, PrimaryTree::Block* b) {
				return a->m_level < b->m_level;
				});
		}

		void checkOnSingleParents() {
			for (const auto decBlock : getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					topNode->getNode()->checkOnSingleParents();
				}
			}
		}

		static void CalculateLevelsForDecBlocks(PrimaryTree::Block* block, std::list<PrimaryTree::Block*>& path) {
			if (block == nullptr)
				return;

			//if that is a loop
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

		static int CalculateHeightForDecBlocks(PrimaryTree::Block* block) {
			int height = 0;
			for (auto refBlock : block->getNextBlocks()) {
				if (refBlock->m_level > block->m_level) {
					auto h = CalculateHeightForDecBlocks(refBlock);
					height = max(height, h);
				}
			}
			block->m_maxHeight = height + (int)block->getSeqLines().size();
			return block->m_maxHeight;
		}
	private:
		AsmGraph* m_asmGraph;
		std::map<PrimaryTree::Block*, AsmGraphBlock*> m_asmGraphBlocks;
		std::list<PrimaryTree::Block*> m_decompiledBlocks;
		std::list<PrimaryTree::Block*> m_removedDecompiledBlocks;
		FunctionCallInfo m_functionCallInfo;
		std::list<Symbol::Symbol*> m_symbols;
	};
};