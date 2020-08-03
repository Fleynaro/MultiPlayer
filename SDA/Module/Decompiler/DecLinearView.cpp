#include "DecLinearView.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::LinearView;

Block* BlockList::findBlock(PrimaryTree::Block* decBlock) {
	for (auto it : m_blocks) {
		if (it->m_decBlock == decBlock) {
			return it;
		}

		if (auto blockListAgregator = dynamic_cast<IBlockListAgregator*>(it)) {
			for (auto blockList : blockListAgregator->getBlockLists()) {
				auto block = blockList->findBlock(decBlock);
				if (block != nullptr) {
					return block;
				}
			}
		}
	}

	return nullptr;
}

GotoType BlockList::getGotoType() {
	if (!m_goto)
		return GotoType::None;
	if (m_goto->getLinearLevel() > getMaxLinearLevel()) {
		if (m_goto->getBackOrderId() == getBackOrderId())
			return GotoType::None;
		auto whileCycle = getWhileCycle();
		if (whileCycle && m_goto->getBackOrderId() == whileCycle->m_backOrderId - 1)
			return GotoType::Break;
	}
	else {
		auto whileCycle = getWhileCycle();
		if (whileCycle && m_goto == whileCycle->getFirstBlock())
			return GotoType::Continue;
	}

	return GotoType::Normal;
}

WhileCycle* BlockList::getWhileCycle() {
	if (auto block = dynamic_cast<Block*>(m_parent)) {
		return block->getWhileCycle();
	}
	return nullptr;
}

WhileCycle* Block::getWhileCycle() {
	return m_blockList->getWhileCycle();
}
