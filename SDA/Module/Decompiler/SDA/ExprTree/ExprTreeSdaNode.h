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

	class ILocatable : public virtual ISdaNode
	{
	public:
		virtual void getLocation(MemLocation& location) = 0;
	};

	class IMappedToMemory : public ILocatable
	{
	public:
		virtual bool isAddrGetting() = 0;

		virtual void setAddrGetting(bool toggle) = 0;
	};

	class SdaNode : public Node, public virtual ISdaNode
	{
		DataTypeCast m_dataTypeCast;
	public:
		DataTypeCast* getCast() override sealed {
			return &m_dataTypeCast;
		}

		INode* clone(NodeCloneContext* ctx) override sealed {
			auto clonedSdaNode = cloneSdaNode(ctx);
			clonedSdaNode->getCast()->setCastDataType(getCast()->getCastDataType(), getCast()->hasExplicitCast());
			return clonedSdaNode;
		}

		std::string printDebug() override sealed {
			auto result = printSdaDebug();
			if (auto addressGetting = dynamic_cast<IMappedToMemory*>(this))
				if (addressGetting->isAddrGetting())
					result = "&" + result;
			if (hasCast() && getCast()->hasExplicitCast()) {
				result = "(" + getCast()->getCastDataType()->getDisplayName() + ")" + result + "";
			}
			if (g_MARK_SDA_NODES)
				result = "@" + result;
			return m_updateDebugInfo = result;
		}

	protected:
		virtual ISdaNode* cloneSdaNode(NodeCloneContext* ctx) = 0;
	};
};