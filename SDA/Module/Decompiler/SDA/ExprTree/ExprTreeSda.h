#pragma once
#include <Code/Type/Type.h>
#include "../../ExprTree/ExprTreeNode.h"
#include <Code/Symbol/Symbol.h>

namespace CE::Decompiler::ExprTree
{
	class AbstractSdaNode : public Node
	{
	public:
		virtual DataTypePtr getDataType() = 0;

		virtual std::string printDebugGoar() {
			return "";
		}
	};

	class SdaNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		Node* m_node;
		DataTypePtr m_calcDataType;
		bool m_explicitCast;

		SdaNode(Node* node)
			: m_node(node)
		{}

		~SdaNode() {
			m_node->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (m_node == node) {
				m_node = newNode;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_node };
		}

		virtual DataTypePtr getDataType() {
			return m_calcDataType;
		}

		BitMask64 getMask() override {
			return m_node->getMask();
		}

		bool isFloatingPoint() override {
			return m_node->isFloatingPoint();
		}

		Node* clone() override {
			return new SdaNode(m_node->clone());
		}

		std::string printDebug() override {
			auto result = m_node->printDebug();
			if (m_calcDataType != nullptr && m_explicitCast) {
				result = "("+ m_calcDataType->getDisplayName() +")" + result + "";
			}
			return m_updateDebugInfo = result;
		}
	};

	class SdaSymbolLeaf : public AbstractSdaNode
	{
	public:
		SdaSymbolLeaf(CE::Symbol::AbstractSymbol* sdaSymbol)
			: m_sdaSymbol(sdaSymbol)
		{}

		CE::Symbol::AbstractSymbol* getSdaSymbol() {
			return m_sdaSymbol;
		}

		BitMask64 getMask() override {
			return BitMask64(m_sdaSymbol->getDataType()->getSize());
		}

		Node* clone() override {
			return nullptr;
		}

		bool isFloatingPoint() override {
			return false;
		}

		DataTypePtr getDataType() override {
			if (m_isGettingAddr) {
				auto dataType = DataType::CloneUnit(m_sdaSymbol->getDataType());
				dataType->addPointerLevelInFront();
				return dataType;
			}
			return m_sdaSymbol->getDataType();
		}

		bool isGettingAddr() {
			return m_isGettingAddr;
		}
	private:
		bool m_isGettingAddr = false;
		CE::Symbol::AbstractSymbol* m_sdaSymbol;
	};
	
	class GoarNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		DataTypePtr m_dataType;
		AbstractSdaNode* m_base;
		int m_bitOffset; //offset + bitOffset?
		Node* m_index;
		int m_readSize = 0x0;
		
		GoarNode(DataTypePtr dataType, AbstractSdaNode* base, int bitOffset, Node* index)
			: m_dataType(dataType), m_base(base), m_bitOffset(bitOffset), m_index(index)
		{}

		BitMask64 getMask() override {
			return BitMask64(m_dataType->getSize());
		}

		Node* clone() override {
			return nullptr;
		}

		bool isFloatingPoint() override {
			return false;
		}

		DataTypePtr getDataType() override {
			return m_dataType;
		}

		std::string printDebug() override {
			auto str = printDebugGoar();
			if (m_readSize == 0x0)
				str = "&" + str;
			return str;
		}

		std::string printDebugGoar() override {
			auto str = m_base->printDebugGoar();
			if (m_bitOffset) {
				if (auto Class = dynamic_cast<DataType::Class*>(m_base->getDataType()->getType())) {
					str = str + (m_readSize == 0x0 ? "." : "->") + Class->getField(m_bitOffset)->getName();
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