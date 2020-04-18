#pragma once
#include "FunctionStatCollector.h"

namespace CE::Stat::Function::Analyser
{
	class IAnalysisProvider {
	public:
		virtual void handle(Record::Header& header, Buffer::Stream& bufferStream) = 0;
	};
};