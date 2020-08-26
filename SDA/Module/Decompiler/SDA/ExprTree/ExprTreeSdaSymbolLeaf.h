#pragma once
#include "ExprTreeSdaNode.h"
#include <Code/Symbol/Symbol.h>

namespace CE::Decompiler::ExprTree
{
	class SdaSymbolLeaf : public AbstractSdaNode
	{
	public:
		SdaSymbolLeaf(CE::Symbol::AbstractSymbol* sdaSymbol, bool isGettingAddr)
			: m_sdaSymbol(sdaSymbol), m_isGettingAddr(isGettingAddr)
		{}

		CE::Symbol::AbstractSymbol* getSdaSymbol() {
			return m_sdaSymbol;
		}

		BitMask64 getMask() override {
			return BitMask64(m_sdaSymbol->getDataType()->getSize());
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue((int64_t)m_sdaSymbol);
			return hash.getHash();
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new SdaSymbolLeaf(m_sdaSymbol, m_isGettingAddr);
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

		void setDataType(DataTypePtr dataType) override {
			if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(m_sdaSymbol)) {
				autoSdaSymbol->setDataType(dataType);
			}
		}

		bool isGettingAddr() {
			return m_isGettingAddr;
		}

		std::string printDebug() override {
			auto str = printDebugGoar();
			if (m_isGettingAddr)
				str = "&" + str;
			return m_updateDebugInfo = str;
		}

		std::string printDebugGoar() override {
			return m_sdaSymbol->getName();
		}
	private:
		bool m_isGettingAddr = false;
		CE::Symbol::AbstractSymbol* m_sdaSymbol;
	};
};