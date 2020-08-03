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
