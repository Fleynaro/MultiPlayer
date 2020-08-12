#pragma once
#include <Code/Type/Type.h>
#include "../../ExprTree/ExprTreeNode.h"
#include <Code/Symbol/Symbol.h>

namespace CE::Decompiler::ExprTree
{
	class GOAR : public Node, public INumber, public IFloatingPoint
	{
	public:
		virtual DataTypePtr getDataType() = 0;

		virtual bool isAddrGetting() = 0;

		virtual std::string printDebugGoar() = 0;

		std::string printDebug() override {
			auto str = printDebugGoar();
			if (isAddrGetting())
				str = "&" + str;
			return str;
		}
	};

	class GoarSymbol : public GOAR
	{
	public:
		GoarSymbol(CE::Symbol::AbstractSymbol* sdaSymbol)
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

		bool IsFloatingPoint() override {
			return false;
		}

		DataTypePtr getDataType() override {
			return m_sdaSymbol->getDataType();
		}

		bool isAddrGetting() override {
			return false;
		}

		std::string printDebugGoar() override {
			return m_sdaSymbol->getName();
		}

	private:
		CE::Symbol::AbstractSymbol* m_sdaSymbol;
	};

	//GoarSymbol

	class GoarNode : public GOAR, public INodeAgregator
	{
	public:
		DataTypePtr m_dataType;
		GOAR* m_base;
		int m_bitOffset;
		Node* m_index;
		int m_readSize = 0x0;
		
		GoarNode(DataTypePtr dataType, GOAR* base, int bitOffset, Node* index)
			: m_dataType(dataType), m_base(base), m_bitOffset(bitOffset), m_index(index)
		{}

		BitMask64 getMask() override {
			return BitMask64(m_dataType->getSize());
		}

		Node* clone() override {
			return nullptr;
		}

		bool IsFloatingPoint() override {
			return false;
		}

		DataTypePtr getDataType() override {
			return m_dataType;
		}

		bool isAddrGetting() override {
			return m_readSize == 0x0;
		}

		std::string printDebugGoar() override {
			auto str = m_base->printDebugGoar();
			if (m_bitOffset) {
				if (auto Class = dynamic_cast<DataType::Class*>(m_base->getDataType()->getType())) {
					str = str + (m_readSize == 0 ? "." : "->") + Class->getField(m_bitOffset)->getName();
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