#pragma once
#include "IAnalysisProvider.h"

namespace CE::Stat::Function::Analyser
{
	//here result of analysis
	class SignatureAnalysisProvider : public IAnalysisProvider
	{
	public:

		void handle(Record::Header& header, Buffer::Stream& bufferStream) override {
			auto type = (Record::Type)header.m_type;
			if (type == Record::Type::BeforeCallInfo) {
				handleBeforeCallInfo(bufferStream);
			}
			else {
				handleAfterCallInfo(bufferStream);
			}
		}

		void handleBeforeCallInfo(Buffer::Stream& bufferStream) {
			Record::BeforeCallInfo::Reader reader(&bufferStream);
			auto& argHeader = reader.getArgHeader();

			for (int i = 0; i < argHeader.m_argCount; i++)
			{
				auto argInfo = reader.readArgument();
				auto value = argInfo.m_value;
				float val = (float&)argInfo.m_xmmValue;
				val = 0.0;
			}
		}

		void handleAfterCallInfo(Buffer::Stream& bufferStream) {

		}
	private:
		std::mutex m_dataMutex;
		//result data
	};
};