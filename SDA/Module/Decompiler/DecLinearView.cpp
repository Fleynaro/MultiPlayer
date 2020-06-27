#include "DecLinearView.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::LinearView;

Block* BlockList::findBlock(PrimaryTree::Block* decBlock) {
	for (auto it : m_blocks) {
		if (it->m_decBlock == decBlock) {
			return it;
		}

		if (auto condition = dynamic_cast<Condition*>(it)) {
			for (auto branch : { condition->m_mainBranch, condition->m_elseBranch }) {
				auto block = branch->findBlock(decBlock);
				if (block != nullptr) {
					return block;
				}
			}
		}
	}

	return nullptr;
}
