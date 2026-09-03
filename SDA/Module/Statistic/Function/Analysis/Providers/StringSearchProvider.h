#pragma once
#include "../IAnalysisProvider.h"

namespace CE::Stat::Function::Analyser
{
	//here result of analysis
	class StringSearchProvider : public IAnalysisProvider
	{
	public:
		StringSearchProvider(const std::string& text)
			: m_text(text)
		{}

		void handle(Record::Header& header, Buffer::Stream& bufferStream) override {
			Record::BeforeCallInfo::Reader reader(&bufferStream);
			auto& argHeader = reader.getArgHeader();

			for (int i = 0; i < argHeader.m_argCount; i++) {
				auto argInfo = reader.readArgument();
				if (argInfo.m_extraData.IsString) {
					std::string origText((char*)argInfo.m_extraData.Data, argInfo.m_extraData.Size);
					if (origText.find(m_text) != std::string::npos) {
						m_dataMutex.lock();
						m_foundRecords.push_back(header);
						m_dataMutex.unlock();
					}
				}
			}
		}

		std::list<Record::Header>& getFoundRecords() {
			return m_foundRecords;
		}

	private:
		std::string m_text;
		std::list<Record::Header> m_foundRecords;
		std::mutex m_dataMutex;
	};
};