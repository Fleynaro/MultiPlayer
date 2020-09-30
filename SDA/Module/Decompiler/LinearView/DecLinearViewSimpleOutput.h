#pragma once
#include "DecLinearView.h"

namespace CE::Decompiler
{
	class LinearViewSimpleConsoleOutput
	{
		LinearView::BlockList* m_blockList;
		DecompiledCodeGraph* m_decGraph;
	public:
		bool m_SHOW_ASM = true;
		bool m_SHOW_PCODE = false;
		bool m_SHOW_ALL_GOTO = true;
		bool m_SHOW_LINEAR_LEVEL_EXT = true;
		bool m_SHOW_BLOCK_HEADER = true;

		LinearViewSimpleConsoleOutput(LinearView::BlockList* blockList, DecompiledCodeGraph* decGraph)
			: m_blockList(blockList), m_decGraph(decGraph)
		{}

		void setMinInfoToShow() {
			m_SHOW_ASM = false;
			m_SHOW_PCODE = false;
			m_SHOW_ALL_GOTO = false;
			m_SHOW_LINEAR_LEVEL_EXT = false;
		}

		void show() {
			showCode(m_blockList);
		}
	private:
		std::set<LinearView::Block*> m_blocksToGoTo;

		void showCode(LinearView::BlockList* blockList, int level = 0) {
			std::string tabStr = "";
			for (int i = 0; i < level; i++)
				tabStr += "\t";

			for (auto block : blockList->getBlocks()) {
				auto decBlock = block->m_decBlock;
				auto asmBlock = m_decGraph->getAsmGraphBlocks()[decBlock];

				if (auto condition = dynamic_cast<LinearView::Condition*>(block)) {
					showBlockCode(asmBlock, block, tabStr);
					printf("%sif(%s) {\n", tabStr.c_str(), condition->m_cond ? condition->m_cond->printDebug().c_str() : "");
					showCode(condition->m_mainBranch, level + 1);
					if (m_SHOW_ALL_GOTO || !condition->m_elseBranch->isEmpty()) {
						printf("%s} else {\n", tabStr.c_str());
						showCode(condition->m_elseBranch, level + 1);
					}
					printf("%s}\n", tabStr.c_str());
				}
				else if (auto whileCycle = dynamic_cast<LinearView::WhileCycle*>(block)) {
					if (!whileCycle->m_isDoWhileCycle) {
						showBlockCode(asmBlock, block, tabStr);
						printf("%swhile(%s) {\n", tabStr.c_str(), whileCycle->m_cond ? whileCycle->m_cond->printDebug().c_str() : "");
						showCode(whileCycle->m_mainBranch, level + 1);
						printf("%s}\n", tabStr.c_str());
					}
					else {
						printf("%sdo {\n", tabStr.c_str());
						showCode(whileCycle->m_mainBranch, level + 1);
						showBlockCode(asmBlock, block, "\t" + tabStr);
						printf("%s} while(%s);\n", tabStr.c_str(), whileCycle->m_cond ? whileCycle->m_cond->printDebug().c_str() : "");
					}
				}
				else {
					showBlockCode(asmBlock, block, tabStr);
				}

				if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(decBlock)) {
					if (endBlock->getReturnNode() != nullptr) {
						printf("%sreturn %s\n", tabStr.c_str(), endBlock->getReturnNode()->printDebug().c_str());
					}
				}
			}

			std::string levelInfo;
			if (m_SHOW_LINEAR_LEVEL_EXT) {
				levelInfo = "backOrderId: " + std::to_string(blockList->getBackOrderId()) + "; minLinLevel: " + std::to_string(blockList->getMinLinearLevel()) + ", maxLinLevel: " + std::to_string(blockList->getMaxLinearLevel()) + "";
			}

			if (blockList->m_goto != nullptr) {
				auto gotoType = blockList->getGotoType();
				if (m_SHOW_ALL_GOTO || gotoType != LinearView::GotoType::None) {
					auto blockName = Generic::String::NumberToHex(m_decGraph->getAsmGraphBlocks()[blockList->m_goto->m_decBlock]->ID);
					std::string typeName = "";
					if (gotoType == LinearView::GotoType::None)
						typeName = "[None]";
					else if (gotoType == LinearView::GotoType::Normal) {
						typeName = "[Goto to label_" + blockName + "]";
						m_blocksToGoTo.insert(blockList->m_goto);
					}
					else if (gotoType == LinearView::GotoType::Break)
						typeName = "[break]";
					else if (gotoType == LinearView::GotoType::Continue)
						typeName = "[continue]";
					if (m_SHOW_ALL_GOTO) {
						printf("%s//goto to block %s (%s) %s\n", tabStr.c_str(), blockName.c_str(), levelInfo.c_str(), typeName.c_str());
					}
					else {
						printf("%s%s\n", tabStr.c_str(), typeName.c_str());
					}
				}
			}
			else if (m_SHOW_ALL_GOTO) {
				printf("%s//goto is null (%s)\n", tabStr.c_str(), levelInfo.c_str());
			}
		}

		void showBlockCode(AsmGraphBlock* asmBlock, LinearView::Block* block, std::string tabStr) {
			auto blockName = Generic::String::NumberToHex(asmBlock->ID);
			if (m_SHOW_BLOCK_HEADER) {
				printf("%s//block %s (level: %i, maxHeight: %i, backOrderId: %i, linearLevel: %i, refCount: %i)\n", tabStr.c_str(), blockName.c_str(), block->m_decBlock->m_level, block->m_decBlock->m_maxHeight, block->getBackOrderId(), block->getLinearLevel(), block->m_decBlock->getRefBlocksCount());
			}
			if (m_blocksToGoTo.find(block) != m_blocksToGoTo.end()) {
				printf("%slabel_%s:\n", tabStr.c_str(), blockName.c_str());
			}
			if (m_SHOW_ASM) {
				asmBlock->printDebug(nullptr, tabStr, false, m_SHOW_PCODE);
				printf("%s------------\n", tabStr.c_str());
			}
			block->m_decBlock->printDebug(false, tabStr);
		}
	};
};