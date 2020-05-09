#pragma once
#include "GenericNodes.h"

namespace CE::CallGraph::Node
{
	class FunctionBody;
	class AbstractBodyNode : public NodeGroup
	{
	public:
		void addReferenceTo(FunctionBody* refFuncBody);

		std::list<FunctionBody*>& getFunctionsReferTo();
	private:
		std::list<FunctionBody*> m_functionsReferTo;
	};

	class FunctionBody : public AbstractBodyNode
	{
	public:
		struct BasicInfo {
			int m_stackMaxDepth = 0;
			int m_calculatedFuncCount = 0;
			int m_notCalculatedFuncCount = 0;
			int m_vMethodCount = 0;
			int m_gVarCount = 0;
			int m_gVarWriteCount = 0;
			bool m_inited = false;

			int getAllFunctionsCount();

			void join(BasicInfo info);

			void next();
		};

		FunctionBody(Function::FunctionDefinition* function);

		bool isSourceTop();

		Type getGroup() override;

		Function::FunctionDefinition* getFunction();

		void setBasicInfo(BasicInfo& info);

		BasicInfo& getBasicInfo();
	private:
		Function::FunctionDefinition* m_function;
		BasicInfo m_basicInfo;
	};

	class GlobalVarBody : public AbstractBodyNode
	{
	public:
		GlobalVarBody() = default;

		Type getGroup() override;

		//MY TODO: доделать GlobalVarBody как FunctionBody сделана
	};
};