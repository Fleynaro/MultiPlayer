#pragma once
#include <Code/Type/Type.h>
#include "../../ExprTree/ExprTreeNode.h"

namespace CE::Decompiler::ExprTree
{
	bool g_MARK_SDA_NODES = false;

	class AbstractSdaNode : public Node
	{
		DataTypePtr m_castDataType;
		bool m_explicitCast = false;
	public:
		DataTypePtr getDataType() {
			return hasCast() ? m_castDataType : getSrcDataType();
		}

		virtual void setDataType(DataTypePtr dataType) = 0;

		bool hasCast() {
			return m_castDataType != nullptr;
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

		std::string printDebug() override {
			auto result = printSdaDebug();
			if (m_castDataType != nullptr && m_explicitCast) {
				result = "(" + m_castDataType->getDisplayName() + ")" + result + "";
			}
			if (g_MARK_SDA_NODES)
				result = "@" + result;
			return m_updateDebugInfo = result;
		}

		virtual std::string printSdaDebug() {
			return "";
		}

		virtual std::string printDebugGoar() {
			return printSdaDebug();
		}

	protected:
		virtual DataTypePtr getSrcDataType() = 0;
	};
};