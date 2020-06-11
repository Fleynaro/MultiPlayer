#include "DecLinearView.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::LinearView;

Block* BlockList::findBlock(AsmGraphBlock* graphBlock) {
	for (auto it : m_blocks) {
		if (it->m_graphBlock == graphBlock) {
			return it;
		}

		if (auto condition = dynamic_cast<Condition*>(it)) {
			for (auto branch : { condition->m_mainBranch, condition->m_elseBranch }) {
				auto block = branch->findBlock(graphBlock);
				if (block != nullptr) {
					return block;
				}
			}
		}
	}
}
