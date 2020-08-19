#pragma once
#include "PrimaryTree/PrimaryTreeBlock.h"

namespace CE::Decompiler
{
	class DecompiledCodeGraph
	{
	public:
		DecompiledCodeGraph(ExprTree::FunctionCallInfo functionCallInfo = ExprTree::GetFunctionCallDefaultInfo())
			: m_functionCallInfo(functionCallInfo)
		{}

		PrimaryTree::Block* getStartBlock() {
			return *getDecompiledBlocks().begin();
		}

		std::list<PrimaryTree::Block*>& getDecompiledBlocks() {
			return m_decompiledBlocks;
		}

		ExprTree::FunctionCallInfo& getFunctionCallInfo() {
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
		std::list<PrimaryTree::Block*> m_decompiledBlocks;
		std::list<PrimaryTree::Block*> m_removedDecompiledBlocks;
		ExprTree::FunctionCallInfo m_functionCallInfo;
		std::list<Symbol::Symbol*> m_symbols;
	};
};