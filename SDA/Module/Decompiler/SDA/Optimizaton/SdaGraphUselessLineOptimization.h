#pragma once
#include "../SdaGraphModification.h"

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
			//gather all used symbols
			while (m_isFirstPass || m_usedSdaSymbols.size() != m_prevUsedSdaSymbols.size()) {
				if (!m_isFirstPass) {
					m_prevUsedSdaSymbols = m_usedSdaSymbols;
					m_usedSdaSymbols.clear();
				}
				passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
					m_curSeqLine = dynamic_cast<PrimaryTree::Block::SeqAssignmentLine*>(topNode);
					defineUsedSdaSymbols(topNode->getNode());
					});
				m_isFirstPass = false;
			}

			//try deleting all lines that contains unused symbol as destination
			passAllTopNodes([&](PrimaryTree::Block::BlockTopNode* topNode) {
				if (auto seqLine = dynamic_cast<PrimaryTree::Block::SeqAssignmentLine*>(topNode)) {
					if (isSeqLineUseless(seqLine))
						delete seqLine;
				}
				});
		}

	private:
		//set of the symbols that are used appearing in various places
		std::set<CE::Symbol::ISymbol*> m_usedSdaSymbols;
		std::set<CE::Symbol::ISymbol*> m_prevUsedSdaSymbols;
		bool m_isFirstPass = true;
		PrimaryTree::Block::SeqAssignmentLine* m_curSeqLine = nullptr;

		void defineUsedSdaSymbols(INode* node) {
			node->iterateChildNodes([&](INode* childNode) {
				defineUsedSdaSymbols(childNode);
				});

			//we need sda symbol leafs only
			auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(node);
			if (!sdaSymbolLeaf)
				return;
			//memVar, funcVar, localVar
			if (sdaSymbolLeaf->getSdaSymbol()->getType() != CE::Symbol::LOCAL_INSTR_VAR)
				return;
			if (m_curSeqLine) {
				SdaSymbolLeaf* sdaDstSymbolLeaf;
				if (isSeqLineSuit(m_curSeqLine, sdaDstSymbolLeaf)) {
					if (sdaDstSymbolLeaf->getSdaSymbol() == sdaSymbolLeaf->getSdaSymbol())
						return;
					if (!m_isFirstPass)
						if (m_prevUsedSdaSymbols.find(sdaDstSymbolLeaf->getSdaSymbol()) == m_prevUsedSdaSymbols.end())
							return;
				}
			}
			m_usedSdaSymbols.insert(sdaSymbolLeaf->getSdaSymbol());
		}

		bool isSeqLineUseless(PrimaryTree::Block::SeqAssignmentLine* seqLine) {
			SdaSymbolLeaf* sdaDstSymbolLeaf;
			if (isSeqLineSuit(seqLine, sdaDstSymbolLeaf)) {
				//if it is unused anywhere
				if (m_usedSdaSymbols.find(sdaDstSymbolLeaf->getSdaSymbol()) == m_usedSdaSymbols.end()) {
					return true;
				}
			}
			return false;
		}

		bool isSeqLineSuit(PrimaryTree::Block::SeqAssignmentLine* seqLine, SdaSymbolLeaf*& sdaDstSymbolLeaf) {
			if (auto sdaGenericNode = dynamic_cast<SdaGenericNode*>(seqLine->getNode())) {
				if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenericNode->getNode())) {
					if (sdaDstSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(assignmentNode->getDstNode())) {
						if (!dynamic_cast<SdaFunctionNode*>(assignmentNode->getSrcNode()) && //we dont touch function call
							sdaDstSymbolLeaf->getSdaSymbol()->getType() == CE::Symbol::LOCAL_INSTR_VAR) { //memVar, funcVar, localVar
							return true;
						}
					}
				}
			}
			return false;
		}
	};
};