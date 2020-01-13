#pragma once

#include <thread>
#include <atomic>

namespace GUI
{
	class ILoadContentThreaded
	{
	public:
		virtual void loadingCheckUpdate() = 0;
	};

	template<typename T>
	class LoadedContent
	{
	public:
		std::atomic<bool> m_loaded = false;
		std::atomic<bool> m_noLongerNeeded = false;
		LoadedContent() = default;

		T& getData() {
			return m_data;
		}

		void setData(const T& data) {
			m_data = data;
		}

		void markAsLoaded() {
			m_loaded = true;
			removeIfNeed();
		}

		void markAsNoLongerNeeded() {
			m_noLongerNeeded = true;
			removeIfNeed();
		}

		void removeIfNeed() {
			if (m_noLongerNeeded && m_loaded)
				delete this;
		}

		bool isLoadedAndNeeded() {
			return !m_noLongerNeeded && m_loaded;
		}

		void load(void(*fn)(LoadedContent<T>*)) {
			std::thread(fn, this).detach();
		}
	private:
		T m_data;
	};
};