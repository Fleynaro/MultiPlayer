#pragma once
#include "PrimaryTree/PrimaryTreeBlock.h"

namespace CE::Decompiler
{
	class Register
	{
	public:
		ZydisRegister m_reg;
		uint64_t m_mask = 0x0;
		bool m_isVector = false;
		std::list<std::pair<ZydisRegister, uint64_t>> m_sameRegisters;

		Register(ZydisRegister reg)
			: m_reg(reg)
		{
			GetRegInfo();
		}

		int getId() const {
			return m_sameRegisters.begin()->first;
		}

		static int GetShiftValueOfMask(uint64_t mask) {
			int result = 0;
			for (auto m = mask; int(m & 0xF) == 0; m = m >> 4) {
				result += 4;
			}
			return result;
		}

		static int GetBitCountOfMask(uint64_t mask) {
			int result = 0;
			for (auto m = mask; m != 0; m = m >> 1) {
				result ++;
			}
			return result;
		}
	private:
		void GetRegInfo() {
			if (m_reg >= ZYDIS_REGISTER_AL && m_reg <= ZYDIS_REGISTER_BL) {
				m_mask = 0xFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AL);
			}
			else if (m_reg >= ZYDIS_REGISTER_AH && m_reg <= ZYDIS_REGISTER_BH) {
				m_mask = 0xFF00;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AH);
			}
			else if (m_reg >= ZYDIS_REGISTER_SPL && m_reg <= ZYDIS_REGISTER_R15B) {
				m_mask = 0xFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AH);
			}
			else if (m_reg >= ZYDIS_REGISTER_AX && m_reg <= ZYDIS_REGISTER_R15W) {
				m_mask = 0xFFFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AX);
			}
			else if (m_reg >= ZYDIS_REGISTER_EAX && m_reg <= ZYDIS_REGISTER_R15D) {
				m_mask = 0xFFFFFFFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_EAX);
			}
			else if (m_reg >= ZYDIS_REGISTER_RAX && m_reg <= ZYDIS_REGISTER_R15) {
				m_mask = 0xFFFFFFFFFFFFFFFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_RAX);
			}
			else if (m_reg >= ZYDIS_REGISTER_MM0 && m_reg <= ZYDIS_REGISTER_MM7) {
				m_mask = 0xF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_MM0);
			}
			else if (m_reg >= ZYDIS_REGISTER_XMM0 && m_reg <= ZYDIS_REGISTER_XMM31) {
				m_mask = 0xFF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_XMM0);
			}
			else if (m_reg >= ZYDIS_REGISTER_YMM0 && m_reg <= ZYDIS_REGISTER_YMM31) {
				m_mask = 0xFFFF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_YMM0);
			}
			else if (m_reg >= ZYDIS_REGISTER_ZMM0 && m_reg <= ZYDIS_REGISTER_ZMM31) {
				m_mask = 0xFFFFFFFF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_ZMM0);
			}
			else {
				m_mask = 0xFFFFFFFFFFFFFFFF;
			}
		}

		static std::list<std::pair<ZydisRegister, uint64_t>> GetListOfSameGenRegisters(int idx) {
			std::list result = {
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_AH + idx), (uint64_t)0xFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_AX + idx), (uint64_t)0xFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_EAX + idx), (uint64_t)0xFFFFFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_RAX + idx), (uint64_t)0xFFFFFFFFFFFFFFFF)
			};
			if (idx <= 3) {
				result.begin()->second <<= 8;
				result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_AL + idx), (uint64_t)0xFF));
			}
			return result;
		}

		static std::list<std::pair<ZydisRegister, uint64_t>> GetListOfSameVectorRegisters(int idx) {
			std::list result = {
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_XMM0 + idx), (uint64_t)0xFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_YMM0 + idx), (uint64_t)0xFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_ZMM0 + idx), (uint64_t)0xFFFFFFFF)
			};
			if (idx <= 7)
				result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_MM0 + idx), (uint64_t)0xF));
			return result;
		}
	};
};