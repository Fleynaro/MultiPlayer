#pragma once
#include <Code/Type/Type.h>
#include "../../ExprTree/ExprTree.h"
#include "../MemLocation.h"

namespace CE::Decompiler::ExprTree
{
	bool g_MARK_SDA_NODES = false;

	class DataTypeCast
	{
		DataTypePtr m_castDataType;
		bool m_explicitCast = false;
	public:
		DataTypeCast() = default;

		DataTypePtr getCastDataType() {
			return m_castDataType;
		}

		bool hasExplicitCast() {
			return m_explicitCast;
		}

		void setCastDataType(DataTypePtr dataType, bool isExplicit = false) {
			m_castDataType = dataType;
			m_explicitCast = isExplicit;
		}

		void clearCast() {
			setCastDataType(nullptr, false);
		}
	};

	class ISdaNode : public virtual INode
	{
	public:
		DataTypePtr getDataType() {
			return hasCast() ? getCast()->getCastDataType() : getSrcDataType();
		}

		virtual DataTypePtr getSrcDataType() = 0;

		virtual void setDataType(DataTypePtr dataType) = 0;

		bool hasCast() {
			return getCast()->getCastDataType() != nullptr;
		}

		virtual DataTypeCast* getCast() = 0;

		virtual std::string printSdaDebug() {
			return "";
		}
	};

	class IStoredInMemory : public virtual ISdaNode
	{
	public:
		virtual bool isAddrGetting() = 0;

		virtual void setAddrGetting(bool toggle) = 0;

		virtual bool tryToGetLocation(Location& location) = 0;
	};

	class SdaNode : public Node, public virtual ISdaNode
	{
		DataTypeCast m_dataTypeCast;
	public:
		DataTypeCast* getCast() override {
			return &m_dataTypeCast;
		}

		std::string printDebug() override {
			auto result = printSdaDebug();
			if (auto addressGetting = dynamic_cast<IStoredInMemory*>(this))
				if (addressGetting->isAddrGetting())
					result = "&" + result;
			if (hasCast() && getCast()->hasExplicitCast()) {
				result = "(" + getCast()->getCastDataType()->getDisplayName() + ")" + result + "";
			}
			if (g_MARK_SDA_NODES)
				result = "@" + result;
			return m_updateDebugInfo = result;
		}
	};
};