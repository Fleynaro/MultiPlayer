#pragma once
#include "DecPCode.h"

namespace CE::Decompiler
{
	using namespace PCode;

	class AbstractRegisterFactory
	{
	public:
		virtual Register createRegister(int regId, int size, int64_t offset = 0x0) = 0;

		virtual Register createFlagRegister(int flag) = 0;

		virtual Register createInstructionPointerRegister() = 0;

		virtual Register createStackPointerRegister() = 0;
	};

	class RegisterFactoryX86 : public AbstractRegisterFactory
	{
	public:
		Register createRegister(int regId, int size, int64_t offset = 0x0) override {
			return CreateRegister(ZydisRegister(regId), size, offset);
		}

		Register createFlagRegister(int flag) override {
			return CreateFlagRegister(ZydisCPUFlag(flag));
		}

		Register createInstructionPointerRegister() override {
			return createRegister(ZYDIS_REGISTER_RIP, 0x8);
		}

		Register createStackPointerRegister() override {
			return createRegister(ZYDIS_REGISTER_RSP, 0x8);
		}

	private:
		static Register CreateRegister(ZydisRegister reg, int size, int64_t offset = 0x0) {
			auto mask = ExtBitMask(size, (int)offset);
			if (reg == ZYDIS_REGISTER_RIP)
				return Register(reg, mask, Register::Type::InstructionPointer);
			if (reg == ZYDIS_REGISTER_RSP)
				return Register(reg, mask, Register::Type::StackPointer);

			if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_BL) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AL, mask);
			}
			else if (reg >= ZYDIS_REGISTER_AH && reg <= ZYDIS_REGISTER_BH) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AH, mask);
			}
			else if (reg >= ZYDIS_REGISTER_SPL && reg <= ZYDIS_REGISTER_R15B) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AH, mask);
			}
			else if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AX, mask);
			}
			else if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_EAX, mask);
			}
			else if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
				return Register(reg, mask);
			}
			else if (reg >= ZYDIS_REGISTER_MM0 && reg <= ZYDIS_REGISTER_MM7) {
				return Register(reg, mask, Register::Type::Vector);
			}
			else if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
				return Register(ZYDIS_REGISTER_ZMM0 + reg - ZYDIS_REGISTER_XMM0, mask, Register::Type::Vector);
			}
			else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
				return Register(ZYDIS_REGISTER_ZMM0 + reg - ZYDIS_REGISTER_YMM0, mask, Register::Type::Vector);
			}
			else if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
				return Register(reg, mask, Register::Type::Vector);
			}

			return Register();
		}

		static Register CreateFlagRegister(ZydisCPUFlag flag) {
			BitMask64 mask = (uint64_t)1 << flag;
			return Register(ZYDIS_REGISTER_RFLAGS, ExtBitMask(mask, uint8_t(0)), Register::Type::Flag);
		}
	};
};