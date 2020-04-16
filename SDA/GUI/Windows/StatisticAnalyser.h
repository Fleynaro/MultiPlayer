#pragma once
#include "GUI/Windows/ItemLists/FunctionList.h"
#include "Module/Statistic/Function.h"

using namespace CE;

namespace GUI::Window::Statistic
{
	class SignatureAnalyser
		: public PrjWindow
	{
	public:
		SignatureAnalyser(API::Function::Function* function)
			: PrjWindow("Siganture analyser"), m_function(function)
		{
			//select buffers
			initAnalyser();

			getMainContainer()
				.addItem(
					new Elements::Button::ButtonStd(
						"Analyse",
						Events::Listener(
							std::function([&](Events::ISender* sender) {
								if (!isAnalyserInit())
									return;
								m_analyser->startAnalysis();
							})
						)
					)
				);
		}

		~SignatureAnalyser() {
			if (isAnalyserInit()) {
				delete m_loader;
				delete m_analyser;
				delete m_provider;
			}
		}

		void initAnalyser() {
			m_loader = new Stat::Function::BufferLoader(getProject()->getProgramExe()->getStatManager()->getCollector()->getBufferManager());
			m_loader->loadAllBuffers();
			m_provider = new Stat::Function::Analyser::SignatureAnalysisProvider;
			m_analyser = new Stat::Function::Analyser::Analyser(m_provider, m_loader);
		}
	protected:
		API::Function::Function* m_function;
		Stat::Function::BufferLoader* m_loader = nullptr;
		Stat::Function::Analyser::Analyser* m_analyser = nullptr;
		Stat::Function::Analyser::SignatureAnalysisProvider* m_provider = nullptr;

		bool isAnalyserInit() {
			return m_analyser != nullptr;
		}
	};

};