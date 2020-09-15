#pragma once
#include "../DecGraphModification.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;

	class SdaGraphUselessLineOptimization : public SdaGraphModification
	{
	public:
		SdaGraphUselessLineOptimization(SdaCodeGraph* sdaCodeGraph)
			: SdaGraphModification(sdaCodeGraph)
		{}

		void start() override {
			passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
				defineUsedSdaSymbols(topNode->getNode());
				});

			passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
				if (auto seqLine = dynamic_cast<PrimaryTree::Block::SeqLine*>(topNode)) {
					if (isSeqLineUseless(seqLine))
						delete seqLine;
				}
				});
		}

	private:
		std::set<CE::Symbol::ISymbol*> m_usedSdaSymbols;

		void defineUsedSdaSymbols(INode* node) {
			node->iterateChildNodes([&](INode* childNode) {
				defineUsedSdaSymbols(childNode);
				});

			auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(node);
			if (!sdaSymbolLeaf)
				return;
			if (sdaSymbolLeaf->getSdaSymbol()->getType() != CE::Symbol::LOCAL_INSTR_VAR)
				return;
			if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaSymbolLeaf->getParentNode()))
				if(assignmentNode->getDstNode() == sdaSymbolLeaf)
					return;
			m_usedSdaSymbols.insert(sdaSymbolLeaf->getSdaSymbol());
		}

		bool isSeqLineUseless(PrimaryTree::Block::SeqLine* seqLine) {
			auto assignmentNode = dynamic_cast<AssignmentNode*>(dynamic_cast<SdaGenericNode*>(seqLine->getNode())->getNode());
			if (dynamic_cast<SdaFunctionNode*>(assignmentNode->getSrcNode()))
				return false;
			if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(assignmentNode->getDstNode())) {
				if (sdaSymbolLeaf->getSdaSymbol()->getType() == CE::Symbol::LOCAL_INSTR_VAR) {
					if (m_usedSdaSymbols.find(sdaSymbolLeaf->getSdaSymbol()) == m_usedSdaSymbols.end()) {
						return true;
					}
				}
			}

			return false;
		}
	};
};