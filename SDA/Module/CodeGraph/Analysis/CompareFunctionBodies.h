#pragma once
#include "../Iterator/FunctionBodyIterator.h"

namespace CE::CallGraph::Analyser
{
	class CompareFunctionBodies
	{
	public:
		CompareFunctionBodies(Node::FunctionBody* funcBody1, Node::FunctionBody* funcBody2);

		//MY TODO: + gVar also
		void doAnalyse();

		const std::list<Node::FunctionBody*>& getMutualFuncBodies();
	private:
		Node::FunctionBody* m_funcBody[2];
		std::list<Node::FunctionBody*> m_mutualFuncBodies;
	};
};