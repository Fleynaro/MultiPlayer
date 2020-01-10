#include "avx.h"




struct Test1
{
	int a = 0;
	int b = 0;
	int c = 0;

	struct
	{
		float pos[3] = {0,0,0};
		float direction = 0.0;
	} position;

	double r = 10.0;

	long long n = 1;
};

struct Test2
{
	Test1* ptr1;
	float f1;
	long long b = 0;
	float f2;
};

float* gVar = nullptr;
void fillMemoryWithStructs(void *ptr, uint64_t size)
{
	Test1 s1;
	s1.a = 1002;
	s1.b = -1;
	s1.position.pos[0] = 1.245;
	s1.position.pos[1] = 1023.1444;
	s1.position.pos[2] = 1027.1464;

	gVar = (float*)(((uint64_t)ptr + 8000) + (uint64_t)&s1.position.pos[1] - (uint64_t)&s1);

	memcpy_s((void*)((uint64_t)ptr + 8000), size, &s1, sizeof(s1));


	//and fill with float values
	for (int i = 0; i < 10000; i++)
	{
		*(float*)((uint64_t)ptr + 10000 + 4 * i) = 1.245;
	}
}

void pass1(BYTE* data, uint64_t size, BYTE** buffer_out)
{
	BYTE* buffer = *buffer_out = new BYTE[size];
	//memcpy_s(*buffer, size, data, size);
	//return;

	/*
		Макросы сравнения:


	*/
	
	float value = 1.245;
	const int cmp = _CMP_EQ_OQ;

	__m256 vecValue = _mm256_set1_ps(value);
	__m256 vecNull = _mm256_set1_ps(0.0);
	__m256i vecUnit = _mm256_set1_epi32(1);
	__m256i vecAcc = _mm256_set1_epi32(0);

	for (int i = 0; i < size; i += 32)
	{
		__m256 vecCur = _mm256_load_ps((float*)&data[i]);
		__m256 mask = _mm256_cmp_ps(vecCur, vecValue, cmp);
		
		_mm256_store_ps((float*)&buffer[i],
			_mm256_or_ps(
				_mm256_and_ps(mask, vecCur),
				_mm256_andnot_ps(mask, vecNull)
			)
		);

		vecAcc = _mm256_add_epi32(
			vecAcc,
			_mm256_and_si256(_mm256_castps_si256(mask), vecUnit)
		);
	}

	//Test1* s1 = (Test1*)buffer;

	uint32_t acc = 0;
	acc += _mm256_extract_epi32(vecAcc, 0);
	acc += _mm256_extract_epi32(vecAcc, 1);
	acc += _mm256_extract_epi32(vecAcc, 2);
	acc += _mm256_extract_epi32(vecAcc, 3);
	acc += _mm256_extract_epi32(vecAcc, 4);
	acc += _mm256_extract_epi32(vecAcc, 5);
	acc += _mm256_extract_epi32(vecAcc, 6);
	acc += _mm256_extract_epi32(vecAcc, 7);
	
	printf("\nfound %i hits\n", acc);
}


//example https://github.com/kshitijl/avx2-examples/blob/master/examples
void module_avx()
{
	const int mb = 1024 * 2 / 4;
	const uint64_t size = 1024 * 1024 * mb - 1;
	BYTE* data;

	//allocate memory with the size of
	{
		TIMER_INIT
		TIMER_START
			data = new BYTE[size];
			ZeroMemory(data, size);
			fillMemoryWithStructs(data, size);	
		TIMER_STOP("allocate memory and fill it with values")
	}


	{
		TIMER_INIT
			TIMER_START

			//_mm256_set1_ps(0.0);	
			/*__m256 zeroVec = _mm256_set_ps(0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0);
			for (int i = 0; i < size; i += 32)
			{
				_mm256_store_ps((float*)&data[i],
					_mm256_set_ps(0.0, 1.0, 0.0 + float(i), 0.0, 0.0, 1.0, 0.0, 0.0)
				);
			}*/

			//ZeroMemory(data, size);

			using namespace CE::Memory;
			Analyser analyser;
			analyser.setMethod(AnalyseMethod::Default);
			analyser.setThreadAmount(1);

			analyser.getUserRegionList().push_back(Region(data, size));
			analyser.prepare();

			auto filter1 = new Filter::CompareOne::BaseCmp<float, Filter::cmp_flag_neq>(10010);
			auto filter2 = new Filter::CompareOne::BaseCmp<float, Filter::cmp_flag_lt>(1003);
			auto filter3 = new Filter::CompareTwo::Abs::BaseCmp<float, Filter::cmp_flag_eq>(0.0);

			analyser.setFilter(filter1);
			analyser.startFirstAnalyse();

			printf("(1)hits = %i\n", analyser.getAddrListSize());
			//*gVar = *gVar + 1.00;

			analyser.setFilter(filter3);
			analyser.startNextAnalyse();

			//analyser.setFilter(new Filter::Float::FilterEQ(1.246));
			//analyser.startNextAnalyse();

			printf("(2)hits = %i\n", analyser.getAddrListSize());

		//	BYTE* buffer = nullptr;
		//	pass1(data, size, &buffer);

		TIMER_STOP("anaylis of this memory")
	}
}