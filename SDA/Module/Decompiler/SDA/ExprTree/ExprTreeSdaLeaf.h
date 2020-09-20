#pragma once
#include "../AutoSdaSymbol.h"
#include "ExprTreeSdaNode.h"
#include <Code/Symbol/Symbol.h>

namespace CE::Decompiler::ExprTree
{
	class SdaSymbolLeaf : public SdaNode, public ILeaf
	{
	public:
		SdaSymbolLeaf(CE::Symbol::ISymbol* sdaSymbol, Symbol::Symbol* decSymbol)
			: m_sdaSymbol(sdaSymbol), m_decSymbol(decSymbol)
		{}

		Symbol::Symbol* getDecSymbol() {
			return m_decSymbol;
		}

		CE::Symbol::ISymbol* getSdaSymbol() {
			return m_sdaSymbol;
		}

		BitMask64 getMask() override {
			return BitMask64(getDataType()->getSize());
		}

		HS getHash() override {
			return m_decSymbol->getHash();
		}

		ISdaNode* cloneSdaNode(NodeCloneContext* ctx) override {
			return new SdaSymbolLeaf(m_sdaSymbol, m_decSymbol);
		}

		bool isFloatingPoint() override {
			return false;
		}

		DataTypePtr getSrcDataType() override {
			return m_sdaSymbol->getDataType();
		}

		void setDataType(DataTypePtr dataType) override {
			if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(m_sdaSymbol)) {
				autoSdaSymbol->setDataType(dataType);
			}
		}

		std::string printSdaDebug() override {
			return m_sdaSymbol->getName();
		}
	protected:
		Symbol::Symbol* m_decSymbol;
		CE::Symbol::ISymbol* m_sdaSymbol;
	};

	class SdaMemSymbolLeaf : public SdaSymbolLeaf, public IMappedToMemory
	{
	public:
		SdaMemSymbolLeaf(CE::Symbol::IMemorySymbol* sdaSymbol, Symbol::Symbol* decSymbol, bool isAddrGetting = false)
			: SdaSymbolLeaf(sdaSymbol, decSymbol), m_isAddrGetting(isAddrGetting)
		{}

		CE::Symbol::IMemorySymbol* getSdaSymbol() {
			return dynamic_cast<CE::Symbol::IMemorySymbol*>(m_sdaSymbol);
		}

		DataTypePtr getSrcDataType() override {
			if (m_isAddrGetting) {
				return MakePointer(SdaSymbolLeaf::getSrcDataType());
			}
			return SdaSymbolLeaf::getSrcDataType();
		}

		HS getHash() override {
			return SdaSymbolLeaf::getHash() << getSdaSymbol()->getOffset();
		}

		ISdaNode* cloneSdaNode(NodeCloneContext* ctx) override {
			return new SdaMemSymbolLeaf(getSdaSymbol(), m_decSymbol, m_isAddrGetting);
		}

		bool isAddrGetting() override {
			return m_isAddrGetting;
		}

		void setAddrGetting(bool toggle) override {
			m_isAddrGetting = toggle;
		}

		void getLocation(MemLocation& location) override {
			location.m_type = (getSdaSymbol()->getType() == CE::Symbol::LOCAL_STACK_VAR ? MemLocation::STACK : MemLocation::GLOBAL);
			location.m_offset = getSdaSymbol()->getOffset();
			location.m_valueSize = m_sdaSymbol->getDataType()->getSize();
		}
	private:
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

		BitMask64 getMask() override {
			return BitMask64(m_calcDataType->getSize());
		}

		DataTypePtr getSrcDataType() override {
			return m_calcDataType;
		}

		void setDataType(DataTypePtr dataType) override {
			m_calcDataType = dataType;
		}

		ISdaNode* cloneSdaNode(NodeCloneContext* ctx) override {
			return new SdaNumberLeaf(m_value, m_calcDataType);
		}

		std::string printSdaDebug() override {
			if (auto sysType = dynamic_cast<DataType::SystemType*>(getSrcDataType()->getBaseType())) {
				if (sysType->isSigned()) {
					auto size = getSrcDataType()->getSize();
					if (size <= 4)
						return m_updateDebugInfo = std::to_string((int32_t)m_value);
					else
						return m_updateDebugInfo = std::to_string((int64_t)m_value);
				}
			}
			return "0x" + Generic::String::NumberToHex(m_value);
		}
	};
};