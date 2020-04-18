#include "StatisticAnalyser.h"

using namespace GUI::Window::Statistic;

SignatureAnalyser::SignatureAnalyser(API::Function::Function* function)
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

SignatureAnalyser::~SignatureAnalyser() {
	if (isAnalyserInit()) {
		delete m_loader;
		delete m_analyser;
		delete m_provider;
	}
}

void SignatureAnalyser::initAnalyser() {
	m_loader = new Stat::Function::BufferLoader(getProject()->getProgramExe()->getStatManager()->getCollector()->getBufferManager());
	m_loader->loadAllBuffers();
	m_provider = new Stat::Function::Analyser::SignatureAnalysisProvider;
	m_analyser = new Stat::Function::Analyser::Analyser(m_provider, m_loader);
}

bool SignatureAnalyser::isAnalyserInit() {
	return m_analyser != nullptr;
}
