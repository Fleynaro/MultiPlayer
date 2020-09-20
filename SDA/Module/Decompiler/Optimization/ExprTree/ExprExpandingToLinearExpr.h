#pragma once
#include "ExprConstCalculating.h"

namespace CE::Decompiler::Optimization
{
	////((y + 3x) + x) * 2 + 5 => (y + 8x) + 5
	//([reg_rbx_64] & 0xffffffff00000000{0} | [var_2_32]) & 0x1f{31} =>	[var_2_32] & 0x1f{31}
	//(x * 2) * 3 => x * 6
	class ExprExpandingToLinearExpr : public ExprModification
	{
		OperationType m_operationAdd = None;
		OperationType m_operationMul = None;
		uint64_t m_invisibleMultiplier;
		std::map<HS::Value, std::pair<INode*, int64_t>> m_terms;
		int64_t m_constTerm;
		bool m_doBuilding = false;
	public:
		ExprExpandingToLinearExpr(OperationalNode* node)
			: ExprModification(node)
		{}

		void start() override {
			if (!defineOperation(getOpNode()->m_operation))
				return;
			defineTerms(getOpNode(), m_invisibleMultiplier);
			if (m_doBuilding) {
				auto linearExpr = buildLinearExpr();
				replace(linearExpr);
				/*if (m_terms.size() == 1 && m_constTerm == 0x0) {
					auto baseTerm = m_terms.begin()->second.first;
					if (baseTerm != getNode())
						replace(baseTerm);
				}*/
			}
		}

		OperationalNode* getOpNode() {
			return dynamic_cast<OperationalNode*>(getNode());
		}
	private:
		LinearExpr* buildLinearExpr() {
			auto linearExpr = new LinearExpr(m_constTerm, m_operationAdd);
			for (auto termInfo : m_terms) {
				auto node = termInfo.second.first;
				auto mask = node->getMask();
				auto multiplier = (uint64_t&)termInfo.second.second;
				INode* term;

				if ((multiplier & mask.getValue()) == (m_invisibleMultiplier & mask.getValue())) {
					term = termInfo.second.first;
				}
				else {
					auto multiplierLeaf = new NumberLeaf(multiplier, mask);
					term = new OperationalNode(node, multiplierLeaf, m_operationMul);
				}
				linearExpr->addTerm(term);
			}
			return linearExpr;
		}

		//(5x - 10y) * 2 + 5 =>	{x: 10, y: -20, constTerm: 5}
		void defineTerms(INode* node, int64_t k, int level = 0) {
			auto size = node->getMask().getSize();
			if (auto numberLeaf = dynamic_cast<INumberLeaf*>(node)) {
				auto constTerm = ExprConstCalculating::Calculate(
					numberLeaf->getValue(),
					k,
					m_operationMul,
					size
				);
				m_constTerm = ExprConstCalculating::Calculate(
					m_constTerm,
					constTerm,
					m_operationAdd,
					size
				);
				m_doBuilding = true;
				return;
			}

			//(x * 2) * 3 => x * 6
			if (level == 2) {
				m_doBuilding = true;
			}

			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				if (opNode->m_operation == m_operationAdd) {
					defineTerms(opNode->m_leftNode, k, level + 1);
					defineTerms(opNode->m_rightNode, k, level + 1);
					return;
				}
				else if (opNode->m_operation == m_operationMul) {
					if (auto rightNumberLeaf = dynamic_cast<INumberLeaf*>(opNode->m_rightNode)) {
						auto newK = ExprConstCalculating::Calculate(
							rightNumberLeaf->getValue(),
							k,
							m_operationMul,
							size
						);
						defineTerms(opNode->m_leftNode, newK, level + 1);
						return;
					}
				}
			}

			auto hashVal = node->getHash().getHashValue();
			if (m_terms.find(hashVal) == m_terms.end()) {
				m_terms[hashVal] = std::make_pair(node, 0);
			}
			auto newK = ExprConstCalculating::Calculate(
				m_terms[hashVal].second,
				k,
				m_operationAdd,
				size
			);
			m_terms[hashVal] = std::make_pair(node, newK);
		}

		bool defineOperation(OperationType op) {
			if (op == Add || op == Mul) {
				m_operationAdd = Add;
				m_operationMul = Mul;
				m_invisibleMultiplier = 1;
				return true;
			}
			if (op == Or || op == And) {
				m_operationAdd = Or;
				m_operationMul = And;
				m_invisibleMultiplier = (int64_t)-1;
				return true;
			}
			//if (op == fAdd || op == fMul) {
			//	m_operationAdd = fAdd;
			//	m_operationMul = fMul;
			//	m_invisibleMultiplier = 0; //todo: for float and double
			//	return true;
			//}
			return false;
		}
	};
};