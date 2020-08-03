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
			CalculateLevelsForDecBlocks(block->m_nextNearBlock, path);
			CalculateLevelsForDecBlocks(block->m_nextFarBlock, path);
			path.pop_back();
		}

		static int CalculateHeightForDecBlocks(PrimaryTree::Block* block) {
			int height = 0;
			for (auto refBlock : { block->m_nextNearBlock, block->m_nextFarBlock }) {
				if (refBlock && refBlock->m_level > block->m_level) {
					auto h = CalculateHeightForDecBlocks(refBlock);
					height = max(height, h);
				}
			}
			block->m_maxHeight = height + (int)block->getSeqLines().size();
			return block->m_maxHeight;
		}
	private:
		std::list<PrimaryTree::Block*> m_decompiledBlocks;
		ExprTree::FunctionCallInfo m_functionCallInfo;
	};
};