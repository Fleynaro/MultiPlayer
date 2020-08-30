#pragma once
#include "ExprTreeSdaNode.h"

namespace CE::Decompiler::ExprTree
{
	class GoarNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		DataTypePtr m_dataType;
		AbstractSdaNode* m_base;
		int m_bitOffset; //offset + bitOffset?
		Node* m_index;
		bool m_isReading;

		GoarNode(DataTypePtr dataType, AbstractSdaNode* base, int bitOffset = 0x0, Node* index = nullptr, bool isReading = false)
			: m_dataType(dataType), m_base(base), m_bitOffset(bitOffset), m_index(index), m_isReading(isReading)
		{
			m_base->addParentNode(this);
			if(m_index)
				m_index->addParentNode(this);
		}

		~GoarNode() {
			m_base->removeBy(this);
			if (m_index)
				m_index->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (node == m_base) {
				m_base = dynamic_cast<AbstractSdaNode*>(newNode);
			}
			else if (node == m_index) {
				m_index = node;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_base, m_index };
		}

		BitMask64 getMask() override {
			return BitMask64(m_dataType->getSize());
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new GoarNode(m_dataType, dynamic_cast<AbstractSdaNode*>(m_base->clone(ctx)), m_bitOffset, m_index->clone(ctx), m_isReading);
		}

		bool isFloatingPoint() override {
			return false;
		}

		DataTypePtr getDataType() override {
			return m_dataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_dataType = dataType;
		}

		std::string printDebug() override {
			auto str = printDebugGoar();
			if (!m_isReading)
				str = "&" + str;
			return m_updateDebugInfo = str;
		}

		std::string printDebugGoar() override {
			auto str = m_base->printDebugGoar();
			if (m_bitOffset) {
				if (auto structure = dynamic_cast<DataType::Structure*>(m_base->getDataType()->getType())) {
					str = str + (m_isReading ? "->" : ".") + structure->getField(m_bitOffset)->getName();
				}
				else {
					str = "(" + str + " + " + std::to_string(m_bitOffset / 0x8) + ")[!some error!]";
				}
			}
			else if (m_index) {
				str = str + "[" + m_index->printDebug() + "]";
			}
			return str;
		}
	};
};