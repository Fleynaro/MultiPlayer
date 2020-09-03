#pragma once
#include "ExprTreeSdaAbstractNode.h"

namespace CE::Decompiler::ExprTree
{
	class GoarNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		DataTypePtr m_dataType;
		AbstractSdaNode* m_base;
		int m_bitOffset; //offset + bitOffset?
		AbstractSdaNode* m_indexNode;
		bool m_isReading;

		GoarNode(DataTypePtr dataType, AbstractSdaNode* base, int bitOffset = 0x0, AbstractSdaNode* indexNode = nullptr, bool isReading = false)
			: m_dataType(dataType), m_base(base), m_bitOffset(bitOffset), m_indexNode(indexNode), m_isReading(isReading)
		{
			m_base->addParentNode(this);
			if(m_indexNode)
				m_indexNode->addParentNode(this);
		}

		~GoarNode() {
			m_base->removeBy(this);
			if (m_indexNode)
				m_indexNode->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			auto newSdaNode = dynamic_cast<AbstractSdaNode*>(newNode);
			if (node == m_base) {
				m_base = newSdaNode;
			}
			else if (node == m_indexNode) {
				m_indexNode = newSdaNode;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_base, m_indexNode };
		}

		BitMask64 getMask() override {
			return BitMask64(m_dataType->getSize());
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new GoarNode(m_dataType, dynamic_cast<AbstractSdaNode*>(m_base->clone(ctx)), m_bitOffset, dynamic_cast<AbstractSdaNode*>(m_indexNode->clone(ctx)), m_isReading);
		}

		bool isFloatingPoint() override {
			return false;
		}

		DataTypePtr getSrcDataType() override {
			return m_dataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_dataType = dataType;
		}

		std::string printSdaDebug() override {
			auto str = printDebugGoar();
			if (!m_isReading)
				str = "&" + str;
			return m_updateDebugInfo = str;
		}

		std::string printDebugGoar() override {
			auto str = m_base->printSdaDebug();
			if (m_bitOffset) {
				if (auto structure = dynamic_cast<DataType::Structure*>(m_base->getDataType()->getType())) {
					str = "(*" + str + ")" + "." + structure->getField(m_bitOffset)->getName();
				}
				else {
					str = "(" + str + " + " + std::to_string(m_bitOffset / 0x8) + ")[!some error!]";
				}
			}
			else if (m_indexNode) {
				str = "(*" + str + ")[" + m_indexNode->printDebug() + "]";
			}
			return str;
		}
	};
};