#pragma once
#include "GUI/Windows/ItemLists/FunctionList.h"
#include "Module/Statistic/Function/FunctionStatAnalyser.h"

using namespace CE;

namespace GUI::Window::Statistic
{
	class SignatureAnalyser
		: public PrjWindow
	{
	public:
		SignatureAnalyser(API::Function::Function* function);

		~SignatureAnalyser();

		void initAnalyser();
	protected:
		API::Function::Function* m_function;
		Stat::Function::BufferLoader* m_loader = nullptr;
		Stat::Function::Analyser::Analyser* m_analyser = nullptr;
		Stat::Function::Analyser::SignatureAnalysisProvider* m_provider = nullptr;

		bool isAnalyserInit();
	};

};