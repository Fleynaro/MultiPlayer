#include "PrimaryTreeBlock.h"
#include "../Optimization/ExprOptimization.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::PrimaryTree;

Line::Line(ExprTree::Node* destAddr, ExprTree::Node* srcValue)
	: m_destAddr(destAddr), m_srcValue(srcValue)
{
	destAddr->addParentNode(this);
	srcValue->addParentNode(this);
}
