#include "GenericNodes.h"
#include <Code/Function/FunctionDefinition.h>

using namespace CE;
using namespace CE::CallGraph::Node;

Type Cycle::getGroup() {
	return Type::Cycle;
}



Type Condition::getGroup() {
	return Type::Condition;
}



GlobalVarNode::GlobalVarNode(Variable::Global* gVar, Use use, void* addr)
	: m_gVar(gVar), m_use(use), LeafNode(addr)
{}

Type GlobalVarNode::getGroup() {
	return Type::GlobalVar;
}

Variable::Global* GlobalVarNode::getGVar() {
	return m_gVar;
}

GlobalVarNode::Use GlobalVarNode::getUse() {
	return m_use;
}



VMethodNode::VMethodNode(Function::MethodDecl* decl, void* addr)
	: m_decl(decl), LeafNode(addr)
{}

VMethodNode::VMethodNode(void* addr)
	: LeafNode(addr)
{}

Type VMethodNode::getGroup() {
	return Type::VMethod;
}

bool VMethodNode::isNotCalculated() {
	return getDeclaration() == nullptr;
}

Function::MethodDecl* VMethodNode::getDeclaration() {
	return m_decl;
}



FunctionNode::FunctionNode(Function::FunctionDefinition* function, void* addr)
	: m_function(function), LeafNode(addr)
{}

FunctionNode::FunctionNode(void* addr)
	: LeafNode(addr)
{}

Type FunctionNode::getGroup() {
	return Type::Function;
}

bool FunctionNode::isCalculatedFunction() {
	return !isNotCalculated();
}

bool FunctionNode::isNotCalculated() {
	return getFunction() == nullptr;
}

Function::FunctionDefinition* FunctionNode::getFunction() {
	return m_function;
}



LeafNode::LeafNode(void* addr)
	: m_addr(addr)
{}

void* LeafNode::getAddressLocation() {
	return m_addr;
}
