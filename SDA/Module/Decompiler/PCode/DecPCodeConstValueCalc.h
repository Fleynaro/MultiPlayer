#pragma once
#include "DecPCodeVirtualMachine.h"
#include "DecRegisterFactory.h"

namespace CE::Decompiler::PCode
{
	class ConstValueCalculating
	{
		std::list<Instruction*>* m_pInstructions;
		PCode::VirtualMachineContext* m_vmCtx;
		AbstractRegisterFactory* m_registerFactory;
	public:
		ConstValueCalculating(std::list<Instruction*>* pInstructions, PCode::VirtualMachineContext* vmCtx, AbstractRegisterFactory* registerFactory)
			: m_pInstructions(pInstructions), m_vmCtx(vmCtx), m_registerFactory(registerFactory)
		{}

		void start(std::map<PCode::Instruction*, DataValue>& constValues) {
			PCode::VirtualMachine vm(m_vmCtx);
			m_vmCtx->setConstantValue(m_registerFactory->createInstructionPointerRegister(), 0);
			m_vmCtx->setConstantValue(m_registerFactory->createStackPointerRegister(), 0);
			for (auto instr : *m_pInstructions) {
				vm.execute(instr);
				DataValue value;
				if (Instruction::IsBranching(instr->m_id)) {
					if (!dynamic_cast<ConstantVarnode*>(instr->m_input0)) {
						if (m_vmCtx->tryGetConstantValue(instr->m_input0, value)) {
							constValues[instr] = value;
						}
					}
				}
				else if (instr->m_id == InstructionId::LOAD) {
					if (m_vmCtx->tryGetConstantValue(instr->m_output, value)) {
						constValues[instr] = value;
					}
				}
			}
		}

	private:
	};
};