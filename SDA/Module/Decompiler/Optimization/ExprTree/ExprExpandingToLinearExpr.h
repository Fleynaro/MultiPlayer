#pragma once
#include "ExprModification.h"

namespace CE::Decompiler::Optimization
{
	////((y + 3x) + x) * 2 + 5 => (y + 8x) + 5
	class ExprExpandingToLinearExpr : public ExprModification
	{
		std::map<HS::Value, std::pair<INode*, int64_t>> m_terms;
		int64_t m_constTerm;
	public:
		ExprExpandingToLinearExpr(INode* node)
			: ExprModification(node)
		{}

		void start() override {
			defineTerms(getNode());
			if (m_terms.size() >= 1 && m_constTerm != 0x0) {
				process(getNode());
			}
		}
	private:
		void process(INode* node) {
			auto linearExpr = new LinearExpr();
			for (auto termInfo : m_terms) {
				auto multiplier = (uint64_t&)termInfo.second.second;
				auto term = (multiplier == 1 ? termInfo.second.first : new OperationalNode(termInfo.second.first, new NumberLeaf(multiplier), Mul));
				linearExpr->addTerm(term);
			}
			linearExpr->setConstTermValue(m_constTerm);
			replace(linearExpr);
		}

		//(5x - 10y) * 2 + 5 =>	{x: 10, y: -20, constTerm: 5}
		void defineTerms(INode* node, int64_t k = 1) {
			if (auto numberLeaf = dynamic_cast<INumberLeaf*>(node)) {
				m_constTerm += (int64_t)numberLeaf->getValue() * k;
				return;
			}

			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				if (opNode->m_operation == Add) {
					defineTerms(opNode->m_leftNode, k);
					defineTerms(opNode->m_rightNode, k);
					return;
				}
				else if (opNode->m_operation == Mul) {
					if (auto rightNumberLeaf = dynamic_cast<INumberLeaf*>(opNode->m_rightNode)) {
						defineTerms(opNode->m_leftNode, k * rightNumberLeaf->getValue());
						return;
					}
				}
			}

			auto hashVal = node->getHash().getHashValue();
			if (m_terms.find(hashVal) == m_terms.end()) {
				m_terms[hashVal] = std::make_pair(node, 0);
			}
			m_terms[hashVal] = std::make_pair(node, m_terms[hashVal].second + k);
		}
	};
};