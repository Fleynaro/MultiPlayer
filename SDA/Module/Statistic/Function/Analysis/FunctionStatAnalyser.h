#pragma once
#include "SignatureAnalysisProvider.h"
#include <Utility/FileWrapper.h>
#include <Utils/ITaskMonitor.h>

using namespace SQLite;

namespace CE::Stat::Function
{
	class BufferLoader
	{
	public:
		BufferLoader(BufferManager* bufferManager)
			: m_bufferManager(bufferManager)
		{}

		void loadAllBuffers() {
			m_bufferFiles = m_bufferManager->m_dir.getItems();
		}

		Buffer* getBuffer() {
			if (m_bufferFiles.empty())
				return nullptr;
			auto file = *m_bufferFiles.begin();
			m_bufferFiles.pop_front();

			if (file->getName().find("buffer_tr") == std::string::npos) {
				return getBuffer();
			}

			std::ifstream fs(file->getPath());
			if (fs.is_open()) {
				auto size = fs.tellg();
				auto buffer = Buffer::Create((int)size);
				fs.read((char*)buffer, size);
				fs.close();
				return buffer;
			}
			return nullptr;
		}
	private:
		BufferManager* m_bufferManager;
		FS::Directory::itemList m_bufferFiles;
	};

	namespace Analyser
	{
		class BufferAnalyser : public ITaskMonitor {
		public:
			BufferAnalyser(Buffer* buffer)
				: m_buffer(buffer)
			{}

			void startAnalysis() {
				m_progress = 0.0;
				m_thread = std::thread(&BufferAnalyser::analyse, this);
				m_thread.detach();
			}

			void setAnalysisProvider(IAnalysisProvider* analysisProvider) {
				m_analysisProvider = analysisProvider;
			}

			float getProgress() override {
				return m_progress;
			}

			int getSize() {
				return m_buffer->getSize();
			}
		private:
			Buffer* m_buffer;
			IAnalysisProvider* m_analysisProvider;
			std::thread m_thread;
			std::atomic<float> m_progress = 1.0;

			void analyse() {
				BufferIterator it(m_buffer);
				while (it.hasNext()) {
					auto stream = it.getStream();
					auto& header = stream.read<Record::Header>();
					m_analysisProvider->handle(header, stream);
					m_progress = float(it.getOffset()) / m_buffer->getContentOffset();
				}
				m_progress = 1.0;
			}
		};

		class Analyser : public ITaskMonitor {
		public:
			Analyser(IAnalysisProvider* analysisProvider, BufferLoader* bufferLoader)
				: m_analysisProvider(analysisProvider), m_bufferLoader(bufferLoader)
			{}

			void startAnalysis() {
				m_threadManager = std::thread(&Analyser::manager, this);
				m_threadManager.detach();
			}

			void manager() {

				while (auto buffer = m_bufferLoader->getBuffer())
				{
					auto bufferAnalyser = new BufferAnalyser(buffer);
					m_mutex.lock();
					m_bufferAnaylysers.push_back(bufferAnalyser);
					m_mutex.unlock();
					bufferAnalyser->startAnalysis();

					while (getTotalSize() > 1024 * 1024 * 100) {
						Sleep(100);
					}
				}
			}

			float getProgress() override {
				float totalPorgress = 0.0;
				m_mutex.lock();
				for (auto it : m_bufferAnaylysers) {
					totalPorgress += it->getProgress();
				}
				m_mutex.unlock();
				return totalPorgress / m_bufferAnaylysers.size();
			}

			int getTotalSize() {
				int size = 0;
				for (auto it : m_bufferAnaylysers) {
					if(it->isWorking())
						size += it->getSize();
				}
				return size;
			}
		private:
			BufferLoader* m_bufferLoader;
			std::thread m_threadManager;
			std::mutex m_mutex;
			std::list<BufferAnalyser*> m_bufferAnaylysers;
			IAnalysisProvider* m_analysisProvider;
		};
	};
};