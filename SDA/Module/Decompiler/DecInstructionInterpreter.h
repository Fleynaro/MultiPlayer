#pragma once
#include "DecExecutionContext.h"

namespace CE::Decompiler::PCode
{
	class InstructionInterpreter
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionBlockContext* ctx, Instruction* instr) {
			m_block = block;
			m_ctx = ctx;
			m_instr = instr;

			switch (m_instr->m_id)
			{
			case InstructionId::COPY:
			{
				auto expr = requestVarnode(m_instr->m_input0);
				m_ctx->setVarnode(m_instr->m_output, expr, true);
				break;
			}

			case InstructionId::LOAD:
			{
				auto expr = requestVarnode(m_instr->m_input0);
				m_ctx->setVarnode(m_instr->m_output, new ExprTree::ReadValueNode(expr, m_instr->m_output->getSize()), true);
				break;
			}

			case InstructionId::STORE:
			{
				auto dstExpr = requestVarnode(m_instr->m_input0);
				auto srcExpr = requestVarnode(m_instr->m_input1);
				m_block->addSeqLine(dstExpr, srcExpr);
				break;
			}

			case InstructionId::INT_ADD:
			case InstructionId::INT_SUB:
			case InstructionId::INT_MULT:
			case InstructionId::INT_DIV:
			case InstructionId::INT_SDIV:
			case InstructionId::INT_AND:
			case InstructionId::INT_OR:
			case InstructionId::INT_XOR:
			case InstructionId::INT_LEFT:
			case InstructionId::INT_RIGHT:
			case InstructionId::INT_SRIGHT:
			{
				auto op1 = requestVarnode(m_instr->m_input0);
				auto op2 = requestVarnode(m_instr->m_input1);
				auto opType = ExprTree::None;

				switch (opType)
				{
				case InstructionId::INT_ADD:
					opType = ExprTree::Add;
					break;
				case InstructionId::INT_SUB:
					opType = ExprTree::Add;
					op2 = new ExprTree::OperationalNode(op2, new ExprTree::NumberLeaf(-1 & m_instr->m_input1->getMask()), ExprTree::Mul);
					break;
				case InstructionId::INT_MULT:
					opType = ExprTree::Mul;
					break;
				case InstructionId::INT_DIV:
				case InstructionId::INT_SDIV:
					opType = ExprTree::Div;
					break;
				case InstructionId::INT_REM:
				case InstructionId::INT_SREM:
					opType = ExprTree::Mod;
					break;
				case InstructionId::INT_AND:
					opType = ExprTree::And;
					break;
				case InstructionId::INT_OR:
					opType = ExprTree::Or;
					break;
				case InstructionId::INT_XOR:
					opType = ExprTree::Xor;
					break;
				case InstructionId::INT_LEFT:
					opType = ExprTree::Shl;
					break;
				case InstructionId::INT_RIGHT:
				case InstructionId::INT_SRIGHT:
					opType = ExprTree::Shr;
					break;
				}

				auto result = new ExprTree::OperationalNode(op1, op2, opType);
				m_ctx->setVarnode(m_instr->m_output, result, true);
				break;
			}

			case InstructionId::INT_NEGATE:
			case InstructionId::INT_2COMP:
			{
				auto expr = requestVarnode(m_instr->m_input0);
				auto nodeMask = new ExprTree::NumberLeaf(-1 & m_instr->m_input0->getMask());
				auto opType = (m_instr->m_id._to_index() == InstructionId::INT_2COMP) ? ExprTree::Mul : ExprTree::Xor;
				m_ctx->setVarnode(m_instr->m_output, new ExprTree::OperationalNode(expr, nodeMask, opType), true);
				break;
			}

			case InstructionId::INT_ZEXT:
			case InstructionId::INT_SEXT:
			{
				auto expr = requestVarnode(m_instr->m_input0);
				m_ctx->setVarnode(m_instr->m_output, expr, true);
				break;
			}
			}
		}

		ExprTree::Node* requestVarnode(PCode::Varnode* varnode) {
			if (auto varnodeRegister = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
				return m_ctx->requestRegisterExpr(varnodeRegister);
			}
			if (auto varnodeSymbol = dynamic_cast<PCode::SymbolVarnode*>(varnode)) {
				return m_ctx->requestSymbolExpr(varnodeSymbol);
			}
			if (auto varnodeConstant = dynamic_cast<PCode::ConstantVarnode*>(varnode)) {
				return new ExprTree::NumberLeaf(varnodeConstant->m_value);
			}
		}

	private:
		PrimaryTree::Block* m_block;
		ExecutionBlockContext* m_ctx;
		Instruction* m_instr;
	};
};
