#pragma once
#include "../Iterator/CallGraphIterator.h"

namespace CE {
	class FunctionManager;
};

namespace CE::CallGraph
{
	class ContextDistance
	{
	public:
		const static int m_maxDeepth = 100000;

		struct Result {
			Node::FunctionBody* m_topFuncBody = nullptr;
			int m_fromDist = m_maxDeepth;
			int m_toDist = m_maxDeepth;

			Result() = default;

			Result(Node::FunctionBody* topFuncBody, int fromDist, int toDist);

			int getDist();
		};

		ContextDistance(FunctionManager* funcManager, Node::FunctionBody* funcBody1, Node::FunctionBody* funcBody2);

		void doAnalyse();

		std::pair<int, int> iterateCallTree(Node::FunctionBody* funcBody, int depth);

		Result& getResult();
	private:
		FunctionManager* m_funcManager;
		Node::FunctionBody* m_funcBody[2];
		Result m_result;
	};
};