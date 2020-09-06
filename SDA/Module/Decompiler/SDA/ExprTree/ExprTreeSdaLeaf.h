#pragma once
#include "../AutoSdaSymbol.h"
#include "ExprTreeSdaNode.h"
#include <Code/Symbol/Symbol.h>

namespace CE::Decompiler::ExprTree
{
	class SdaSymbolLeaf : public SdaNode, public ILeaf, public IAddressGetting
	{
	public:
		SdaSymbolLeaf(CE::Symbol::AbstractSymbol* sdaSymbol, Symbol::Symbol* decSymbol, int64_t memOffset = 0x0, bool isAddrGetting = false)
			: m_sdaSymbol(sdaSymbol), m_decSymbol(decSymbol), m_memOffset(memOffset), m_isAddrGetting(isAddrGetting)
		{}

		CE::Symbol::AbstractSymbol* getSdaSymbol() {
			return m_sdaSymbol;
		}

		BitMask64 getMask() override {
			return BitMask64(getDataType()->getSize());
		}

		ObjectHash::Hash getHash() override {
			return m_decSymbol->getHash() + 31 * m_memOffset;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new SdaSymbolLeaf(m_sdaSymbol, m_decSymbol, m_memOffset, m_isAddrGetting);
		}

		bool isFloatingPoint() override {
			return false;
		}

		DataTypePtr getSrcDataType() override {
			if (m_isAddrGetting) {
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

		bool isAddrGetting() override {
			return m_isAddrGetting;
		}

		void setAddrGetting(bool toggle) override {
			m_isAddrGetting = toggle;
		}

		std::string printSdaDebug() override {
			return m_sdaSymbol->getName();
		}
	private:
		Symbol::Symbol* m_decSymbol;
		int64_t m_memOffset;
		CE::Symbol::AbstractSymbol* m_sdaSymbol;
		bool m_isAddrGetting;
	};

	class SdaNumberLeaf : public SdaNode, public INumberLeaf
	{
		DataTypePtr m_calcDataType;
	public:
		uint64_t m_value;

		SdaNumberLeaf(uint64_t value, DataTypePtr calcDataType = nullptr)
			: m_value(value), m_calcDataType(calcDataType)
		{}

		uint64_t getValue() override {
			return m_value;
		}

		void setValue(uint64_t value) override {
			m_value = value;
		}

		DataTypePtr getSrcDataType() override {
			return m_calcDataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_calcDataType = dataType;
		}

		BitMask64 getMask() override {
			return BitMask64(m_value);
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue((int64_t)m_value);
			return hash.getHash();
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new SdaNumberLeaf(m_value, m_calcDataType);
		}

		std::string printSdaDebug() override {
			if (auto sysType = dynamic_cast<DataType::SystemType*>(getSrcDataType()->getBaseType())) {
				if (sysType->isSigned()) {
					return m_updateDebugInfo = std::to_string((int64_t)m_value);
				}
			}
			return "0x" + Generic::String::NumberToHex(m_value);
		}
	};
};