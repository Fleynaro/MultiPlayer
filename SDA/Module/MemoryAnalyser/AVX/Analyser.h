#pragma once

#include "main.h"

/*
	TODO:
	1) AVX for double, int, ... (разобраться с масками или придумать что-то другое)
	2) Метод prepare. Граничные случаи
	3) Протестить Rel
	4) Недоступные страницы памяти
	5) Итоговый GetResultOfAddress
	6) Многопоточность
*/

namespace CE
{
	namespace Memory
	{
		using ListOfAddresses = std::vector<std::pair<std::uintptr_t, uint64_t>>;

		namespace Filter
		{
			constexpr int
				cmp_flag_eq = _CMP_EQ_OQ,	//==
				cmp_flag_neq = _CMP_NEQ_OQ,	//!=
				cmp_flag_lt = _CMP_LT_OQ,	//<
				cmp_flag_le = _CMP_LE_OQ,	//<=
				cmp_flag_gt = _CMP_GT_OQ,	//>
				cmp_flag_ge = _CMP_GE_OQ;	//>=
			template<int cmp_flag, typename T1, typename T2>
			constexpr bool compare(T1 op1, T2 op2)
			{
				if constexpr (cmp_flag == cmp_flag_eq) {
					return op1 == op2;
				}
				else if constexpr (cmp_flag == cmp_flag_neq) {
					return op1 != op2;
				}
				else if constexpr (cmp_flag == cmp_flag_lt) {
					return op1 < op2;
				}
				else if constexpr (cmp_flag == cmp_flag_le) {
					return op1 <= op2;
				}
				else if constexpr (cmp_flag == cmp_flag_gt) {
					return op1 > op2;
				}
				else if constexpr (cmp_flag == cmp_flag_ge) {
					return op1 >= op2;
				}
			}

			class IFilter
			{
			public:
				virtual void Default_passFirst(byte* data, uint64_t size, ListOfAddresses& list, uint64_t& addrCount) = 0;
				virtual void Default_passInList(ListOfAddresses& list, uint64_t& addrCount) = 0;
				
				virtual void AVX_passFirst(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) = 0;
				virtual void AVX_passInBuffer(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) = 0;


				template<int cmp_flag, bool cmp_flag_prev_val = false, bool cmp_flag_percent = false, typename T>
				static void Default_passInList_cmp(T value, ListOfAddresses& list, uint64_t& addrCount, float percent = 0.0)
				{
					for (auto& it : list)
					{
						bool cmp;
						if constexpr (cmp_flag_prev_val) {
							if constexpr (cmp_flag_percent) {
								cmp = compare<cmp_flag>(*(T*)it.first - *(T*)& it.second, percent * *(T*)& it.second);
							}
							else {
								cmp = compare<cmp_flag>(*(T*)it.first - *(T*)& it.second, value);
							}
						}
						else {
							cmp = compare<cmp_flag>(*(T*)& it.second, value);
						}
						if (!cmp) {
							it.first = 0;
							addrCount--;
						}
					}
				}

				template<int cmp_flag, typename T>
				static void Default_passFirst_cmp(T value, byte* data, uint64_t size, ListOfAddresses& list, uint64_t& addrCount)
				{
					for (int i = 0; i < size; i += sizeof(T))
					{
						if (compare<cmp_flag>(*(T*)& data[i], value)) {
							list.push_back(std::make_pair((std::uintptr_t) &data[i], *(uint64_t*) &data[i]));
							addrCount++;
						}
					}
				}

				template<int cmp_flag, bool isFirst = false, bool cmp_flag_prev_val = false, bool cmp_flag_percent = false, typename T>
				static void AVX_pass_cmp(T value, byte* data, byte* buffer, uint64_t size, __m256i& vecAcc, float percent = 0.0)
				{
					__m256i vecUnit = _mm256_set1_epi32(1);

					if constexpr (std::is_same<T, float>::value)
					{
						__m256 vecValue = _mm256_set1_ps(value);
						__m256 vecNull = _mm256_set1_ps(-103.5386);

						for (int i = 0; i < size; i += sizeof(__m256))
						{
							__m256 vecCur = _mm256_load_ps((float*)& data[i]);
							__m256 vecMask;
							if constexpr (cmp_flag_prev_val) {
								__m256 vecPrev = _mm256_load_ps((float*)& buffer[i]);
								
								if constexpr (cmp_flag_percent) {
									vecValue = _mm256_mul_ps(vecPrev, _mm256_set1_ps(percent));
								}

								vecMask = _mm256_and_ps(
									_mm256_cmp_ps(vecPrev, vecNull, _CMP_NEQ_OQ),
									_mm256_cmp_ps(_mm256_sub_ps(vecCur, vecPrev), vecValue, cmp_flag)
								);
							}
							else {
								vecMask = _mm256_cmp_ps(vecCur, vecValue, cmp_flag);
	
								if constexpr (!isFirst) {
									vecMask = _mm256_and_ps(
										_mm256_cmp_ps(vecCur, vecNull, _CMP_NEQ_OQ),
										vecMask
									);
								}
							}

							_mm256_store_ps((float*)& buffer[i],
								_mm256_or_ps(
									_mm256_and_ps(vecMask, vecCur),
									_mm256_andnot_ps(vecMask, vecNull)
								)
							);

							vecAcc = _mm256_add_epi32(
								vecAcc,
								_mm256_and_si256(_mm256_castps_si256(vecMask), vecUnit)
							);
						}
					} else if constexpr (std::is_same<T, int>::value)
					{
						/*__m256i vecValue = _mm256_set1_epi32(value);
						__m256i vecNull = _mm256_set1_epi32(-10335718);

						for (int i = 0; i < size; i += sizeof(__m256))
						{
							__m256i vecCur = _mm256_castps_si256(_mm256_load_ps((float*)& data[i]));
							__m256i vecMask;
							if constexpr (cmp_flag_prev_val) {
								__m256 vecPrev = _mm256_castps_si256(_mm256_load_ps((float*)& buffer[i]));

								if constexpr (cmp_flag_percent) {
									vecValue = _mm256_mul_ps(vecPrev, _mm256_set1_ps(percent));
								}

								vecMask = _mm256_and_si256(
									_mm256_cmp_ps(vecPrev, vecNull, _CMP_NEQ_OQ),
									_mm256_cmp_ps(_mm256_sub_epi32(vecCur, vecPrev), vecValue, cmp_flag)
								);
							}
							else {
								vecMask = _mm256_cmp_epi32_mask(vecCur, vecValue, cmp_flag);
								_mm256_mask
								if constexpr (!isFirst) {
									vecMask = _mm256_and_si256(
										_mm256_cmp_ps(vecCur, vecNull, _CMP_NEQ_OQ),
										vecMask
									);
								}
							}

							_mm256_store_ps((float*)& buffer[i],
								_mm256_castsi256_ps(
									_mm256_or_si256(
										_mm256_and_si256(vecMask, vecCur),
										_mm256_andnot_si256(vecMask, vecNull)
									)
								)
							);

							vecAcc = _mm256_add_epi32(
								vecAcc,
								_mm256_and_si256(vecMask, vecUnit)
							);
						}*/
					}
				}
			};

			template<typename T>
			class IFilterValue : public IFilter
			{
			public:
				IFilterValue(T value)
					: m_value(value)
				{}

				void setValue(T value) {
					m_value = value;
				}
			protected:
				T m_value;
			};
			
			class IFilterRel : public IFilter
			{
			public:
				IFilterRel(float value)
					: m_percent(value)
				{}

				void setPercent(float value) {
					m_percent = value;
				}
			protected:
				float m_percent;
			};

			template<typename T>
			class IFilterRange : public IFilter
			{
			public:
				IFilterRange(T minValue, T maxValue)
					: m_minValue(minValue), m_maxValue(maxValue)
				{}

				void setRange(T min, T max) {
					m_minValue = min;
					m_maxValue = max;
				}
			protected:
				T m_minValue;
				T m_maxValue;
			};

			namespace CompareOne
			{
				template<typename T, int cmp_flag>
				class BaseCmp : public IFilterValue<T>
				{
				public:
					BaseCmp(T value)
						: IFilterValue<T>(value)
					{}

					void Default_passFirst(byte* data, uint64_t size, ListOfAddresses& list, uint64_t& addrCount) override
					{
						IFilter::Default_passFirst_cmp<cmp_flag>(IFilterValue<T>::m_value, data, size, list, addrCount);
					}

					void Default_passInList(ListOfAddresses& list, uint64_t& addrCount) override
					{
						IFilter::Default_passInList_cmp<cmp_flag>(IFilterValue<T>::m_value, list, addrCount);
					}

					void AVX_passFirst(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) override
					{
						IFilter::AVX_pass_cmp<cmp_flag, true>(IFilterValue<T>::m_value, data, buffer, size, vecAcc);
					}

					void AVX_passInBuffer(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) override
					{
						IFilter::AVX_pass_cmp<cmp_flag, false>(IFilterValue<T>::m_value, buffer, buffer, size, vecAcc);
					}
				};
			};

			namespace CompareTwo
			{
				namespace Abs
				{
					template<typename T, int cmp_flag>
					class BaseCmp : public IFilterValue<T>
					{
					public:
						BaseCmp(T value)
							: IFilterValue<T>(value)
						{}

						void Default_passFirst(byte* data, uint64_t size, ListOfAddresses& list, uint64_t& addrCount) override
						{
							IFilter::Default_passFirst_cmp<cmp_flag>(IFilterValue<T>::m_value, data, size, list, addrCount);
						}

						void Default_passInList(ListOfAddresses& list, uint64_t& addrCount) override
						{
							IFilter::Default_passInList_cmp<cmp_flag, true>(IFilterValue<T>::m_value, list, addrCount);
						}

						void AVX_passFirst(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) override
						{
							IFilter::AVX_pass_cmp<cmp_flag, true>(IFilterValue<T>::m_value, data, buffer, size, vecAcc);
						}

						void AVX_passInBuffer(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) override
						{
							IFilter::AVX_pass_cmp<cmp_flag, false, true>(IFilterValue<T>::m_value, data, buffer, size, vecAcc);
						}
					};
				};

				namespace Rel
				{
					template<typename T, int cmp_flag>
					class BaseCmp : public IFilterRel
					{
					public:
						BaseCmp(T value)
							: IFilterValue<T>(value)
						{}

						void Default_passFirst(byte* data, uint64_t size, ListOfAddresses& list, uint64_t& addrCount) override
						{
							IFilter::Default_passFirst_cmp<cmp_flag>(IFilterValue<T>::m_value, data, size, list, addrCount);
						}

						void Default_passInList(ListOfAddresses& list, uint64_t& addrCount) override
						{
							IFilter::Default_passInList_cmp<cmp_flag, true, true>(IFilterValue<T>::m_value, list, addrCount, m_percent);
						}

						void AVX_passFirst(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) override
						{
							IFilter::AVX_pass_cmp<cmp_flag, true>(IFilterValue<T>::m_value, data, buffer, size, vecAcc);
						}

						void AVX_passInBuffer(byte* data, byte* buffer, uint64_t size, __m256i& vecAcc) override
						{
							IFilter::AVX_pass_cmp<cmp_flag, false, true, true>(IFilterValue<T>::m_value, data, buffer, size, vecAcc, m_percent);
						}
					};
				};
			};
		};

		class Region
		{
		public:
			Region(byte* base, std::uintptr_t size)
				: m_base(base), m_size(size)
			{}

			byte* m_base;
			std::uintptr_t m_size;
		};

		class Analyser;
		class ThreadRegion
		{
		public:
			ThreadRegion(Analyser* analyser)
				: m_analyser(analyser)
			{}
			virtual ~ThreadRegion() {}

			std::vector<Region> m_regions;
			bool m_procceed = false;
			Analyser* m_analyser;

			virtual void doFirstAnalyse() = 0;
			virtual void doNextAnalyse() = 0;
			virtual std::vector<std::uintptr_t> getAddrList() = 0;
			virtual uint64_t getAddrListSize() = 0;
		};

		class ThreadRegionDefault : public ThreadRegion
		{
		public:
			ThreadRegionDefault(Analyser* analyser)
				: ThreadRegion(analyser)
			{}

			void doFirstAnalyse() override;
			void doNextAnalyse() override;

			std::vector<std::uintptr_t> getAddrList() override
			{
				std::vector<std::uintptr_t> list;
				return list;
			}

			uint64_t getAddrListSize() override
			{
				return m_addrCount;
			}
		private:
			uint64_t m_addrCount = 0;
			ListOfAddresses m_addrList;
		};

		class ThreadRegionAVX : public ThreadRegion
		{
		public:
			ThreadRegionAVX(Analyser* analyser)
				: ThreadRegion(analyser)
			{}

			~ThreadRegionAVX() override {
				for (int i = 0; i < m_buffers.size(); i++) {
					delete m_buffers[i];
				}
			}

			uint64_t getSumOfVecAcc(__m256i& vecAcc) {
				uint64_t acc = 0;
				acc += _mm256_extract_epi32(vecAcc, 0);
				acc += _mm256_extract_epi32(vecAcc, 1);
				acc += _mm256_extract_epi32(vecAcc, 2);
				acc += _mm256_extract_epi32(vecAcc, 3);
				acc += _mm256_extract_epi32(vecAcc, 4);
				acc += _mm256_extract_epi32(vecAcc, 5);
				acc += _mm256_extract_epi32(vecAcc, 6);
				acc += _mm256_extract_epi32(vecAcc, 7);
				return acc;
			}

			void doFirstAnalyse() override;
			void doNextAnalyse() override;

			std::vector<std::uintptr_t> getAddrList() override
			{
				std::vector<std::uintptr_t> list;
				return list;
			}

			uint64_t getAddrListSize() override
			{
				return m_addrCount;
			}

		private:
			uint64_t m_addrCount = 0;
			std::vector<byte*> m_buffers;
		};

		enum class AnalyseMethod
		{
			Default,
			AVX
		};
		
		class Analyser
		{
		public:
			Analyser() {
				m_thread_regions = std::vector<ThreadRegion*>(m_thread_amount, nullptr);
			}

			void setFilter(Filter::IFilter* filter) {
				m_filter = filter;
			}

			Filter::IFilter* getFilter() {
				return m_filter;
			}

			void setThreadAmount(int amount) {
				m_thread_amount = amount;
				m_thread_regions.resize(amount);
			}

			std::vector<Region>& getUserRegionList() {
				return m_user_regions;
			}

			void initThreadRegions() {
				for (auto& it : m_thread_regions) {
					switch (m_analyseMethod)
					{
					case AnalyseMethod::Default:
						it = new ThreadRegionDefault(this);
						break;
					case AnalyseMethod::AVX:
						it = new ThreadRegionAVX(this);
						break;
					}
				}
			}

			void clearThreadRegions() {
				for (auto& it : m_thread_regions) {
					if (it != nullptr) {
						delete it;
						it = nullptr;
					}
				}
			}

			void startFirstAnalyse() {
				for (auto const& it : m_thread_regions) {
					std::thread t(&ThreadRegion::doFirstAnalyse, it);

					t.join();
				}
			}

			void startNextAnalyse() {
				for (auto const& it : m_thread_regions) {
					std::thread t(&ThreadRegion::doNextAnalyse, it);

					t.join();
				}
			}

			uint64_t getAddrListSize()
			{
				uint64_t size = 0;
				for (auto const& it : m_thread_regions) {
					size += it->getAddrListSize();
				}
				return size;
			}
			
			void prepare()
			{
				initThreadRegions();

				uint64_t tRegionSize = getTotalSize() / m_thread_amount;
				uint64_t sizeOfThreadReg = tRegionSize;
				int curThread = 0;

				for (auto const& uRegion : m_user_regions)
				{
					uint64_t baseOfUserReg = (uint64_t)uRegion.m_base;
					uint64_t sizeOfUserReg = uRegion.m_size;
					while (sizeOfUserReg > 0 && curThread < m_thread_amount)
					{
						if (sizeOfUserReg < sizeOfThreadReg) {
							m_thread_regions[curThread]->m_regions.push_back(Region((byte*)baseOfUserReg, sizeOfUserReg));
							sizeOfThreadReg -= sizeOfUserReg;
							break;
						}
						else {
							m_thread_regions[curThread]->m_regions.push_back(Region((byte*)baseOfUserReg, sizeOfThreadReg));
							baseOfUserReg += sizeOfThreadReg;
							sizeOfUserReg -= sizeOfThreadReg;
							sizeOfThreadReg = tRegionSize;
							curThread++;
						}
					}
				}
			}

			uint64_t getTotalSize() {
				uint64_t size = 0;
				for (auto const& region : m_user_regions) {
					size += region.m_size;
				}
				return size;
			}

			void setMethod(AnalyseMethod method)
			{
				m_analyseMethod = method;
			}
		private:
			Filter::IFilter* m_filter = nullptr;
			int m_thread_amount = 1;

			std::vector<Region> m_user_regions;
			std::vector<ThreadRegion*> m_thread_regions;

			std::vector<std::uintptr_t> m_addrList;
			AnalyseMethod m_analyseMethod;
		};
	};
};
