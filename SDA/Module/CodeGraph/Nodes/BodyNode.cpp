#include "BodyNode.h"

using namespace CE;
using namespace CE::CodeGraph::Node;

FunctionBody::FunctionBody(Function::FunctionDefinition* function)
	: m_function(function)
{}

bool FunctionBody::isSourceTop() {
	if (getFunctionsReferTo().size() == 1) {
		auto it = *getFunctionsReferTo().begin();
		if (it->getFunction() == getFunction()) {
			return true;
		}
	}
	return getFunctionsReferTo().size() == 0;
}

Type FunctionBody::getGroup() {
	return Type::FunctionBody;
}

Function::FunctionDefinition* FunctionBody::getFunction() {
	return m_function;
}

void FunctionBody::setBasicInfo(BasicInfo& info) {
	m_basicInfo = info;
}

FunctionBody::BasicInfo& FunctionBody::getBasicInfo() {
	return m_basicInfo;
}

int FunctionBody::BasicInfo::getAllFunctionsCount() {
	return m_calculatedFuncCount + m_notCalculatedFuncCount + m_vMethodCount;
}

void FunctionBody::BasicInfo::join(BasicInfo info) {
	m_stackMaxDepth = max(m_stackMaxDepth, info.m_stackMaxDepth);
	m_calculatedFuncCount += info.m_calculatedFuncCount;
	m_notCalculatedFuncCount += info.m_notCalculatedFuncCount;
	m_vMethodCount += info.m_vMethodCount;
	m_gVarCount += info.m_gVarCount;
	m_gVarWriteCount += info.m_gVarWriteCount;
}

void FunctionBody::BasicInfo::next() {
	m_stackMaxDepth++;
}


Type GlobalVarBody::getGroup() {
	return Type::GlobalVarBody;
}


void AbstractBodyNode::addReferenceTo(FunctionBody* refFuncBody) {
	m_functionsReferTo.push_back(refFuncBody);
}

std::list<FunctionBody*>& AbstractBodyNode::getFunctionsReferTo() {
	return m_functionsReferTo;
}
