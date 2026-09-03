#include "Analyser.h"

using namespace CE::Memory;

void ThreadRegionDefault::doFirstAnalyse()
{
	for (int i = 0; i < m_regions.size(); i++) {
		m_analyser->getFilter()->Default_passFirst(m_regions[i].m_base, m_regions[i].m_size, m_addrList, m_addrCount);
	}
}

void ThreadRegionDefault::doNextAnalyse()
{
	m_analyser->getFilter()->Default_passInList(m_addrList, m_addrCount);
}

void ThreadRegionAVX::doFirstAnalyse()
{
	__m256i vecAcc = _mm256_set1_epi32(0);
	m_buffers.resize(m_regions.size());

	for (int i = 0; i < m_regions.size(); i++) {
		m_buffers[i] = new byte[m_regions[i].m_size];
		ZeroMemory(m_buffers[i], m_regions[i].m_size);

		m_analyser->getFilter()->AVX_passFirst(m_regions[i].m_base, m_buffers[i], m_regions[i].m_size, vecAcc);
	}

	m_addrCount = getSumOfVecAcc(vecAcc);
}

void ThreadRegionAVX::doNextAnalyse()
{
	__m256i vecAcc = _mm256_set1_epi32(0);

	for (int i = 0; i < m_regions.size(); i++) {
		m_analyser->getFilter()->AVX_passInBuffer(m_regions[i].m_base, m_buffers[i], m_regions[i].m_size, vecAcc);
	}

	m_addrCount = getSumOfVecAcc(vecAcc);
}
