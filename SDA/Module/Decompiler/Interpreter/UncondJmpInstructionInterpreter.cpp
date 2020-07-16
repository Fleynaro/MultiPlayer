#include "UncondJmpInstructionInterpreter.h"
#include "../Decompiler.h"

using namespace CE::Decompiler;

UncondJmpInstructionInterpreter::UncondJmpInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
	: AbstractInstructionInterpreter(block, ctx, instruction)
{}

void UncondJmpInstructionInterpreter::execute() {
	if (m_instruction->mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		int dstLocOffset = 0;
		auto& operand = m_instruction->operands[0];
		if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (operand.imm.is_relative) {
				dstLocOffset = (int)m_instruction->length +
					(operand.imm.is_signed ? (m_ctx->m_offset + (int)operand.imm.value.s) : (m_ctx->m_offset + (unsigned int)operand.imm.value.u));
			}
		}

		Operand op(m_ctx, &operand);
		ExprTree::Node* dstExpr = nullptr;
		auto dstLocExpr = op.getExpr();
		auto funcCallInfo = m_ctx->m_decompiler->m_funcCallInfoCallback(dstLocOffset, dstLocExpr);
		auto funcCallCtx = new ExprTree::FunctionCallContext(dstLocOffset, dstLocExpr);

		for (auto paramReg : funcCallInfo.m_paramRegisters) {
			auto reg = m_ctx->requestRegisterExpr(paramReg);
			funcCallCtx->addRegisterParam(paramReg, reg);
		}

		auto dstRegister = funcCallInfo.m_resultRegister != ZYDIS_REGISTER_NONE ? funcCallInfo.m_resultRegister : funcCallInfo.m_resultVectorRegister;
		if (dstRegister != ZYDIS_REGISTER_NONE) {
			auto reg = Register(dstRegister);
			auto funcResultVar = new Symbol::FunctionResultVar(funcCallCtx, reg.getSize());
			dstExpr = new ExprTree::SymbolLeaf(funcResultVar);
			setExprToRegisterDst(reg, dstExpr);
		}

		if (dstExpr == nullptr) {
			dstExpr = new ExprTree::NumberLeaf(0x0);
		}
		m_block->addSeqLine(dstExpr, funcCallCtx);
	}
}
