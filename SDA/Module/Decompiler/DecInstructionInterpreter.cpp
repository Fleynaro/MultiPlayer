#include "DecInstructionInterpreter.h"
#include "Decompiler.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::PCode;

void InstructionInterpreter::execute(PrimaryTree::Block* block, ExecutionBlockContext* ctx, Instruction* instr) {
	m_block = block;
	m_ctx = ctx;
	m_instr = instr;

	switch (m_instr->m_id)
	{
	case InstructionId::COPY:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		m_ctx->setVarnode(m_instr->m_output, expr);
		break;
	}

	case InstructionId::LOAD:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		m_ctx->setVarnode(m_instr->m_output, new ExprTree::ReadValueNode(expr, m_instr->m_output->getSize()));
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

		switch (m_instr->m_id)
		{
		case InstructionId::INT_ADD:
		case InstructionId::INT_SUB:
			opType = ExprTree::Add;
			if (m_instr->m_id == InstructionId::INT_SUB)
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
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::INT_NEGATE:
	case InstructionId::INT_2COMP:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		auto nodeMask = new ExprTree::NumberLeaf(-1 & m_instr->m_input0->getMask());
		auto opType = (m_instr->m_id == InstructionId::INT_2COMP) ? ExprTree::Mul : ExprTree::Xor;
		m_ctx->setVarnode(m_instr->m_output, new ExprTree::OperationalNode(expr, nodeMask, opType));
		break;
	}

	case InstructionId::INT_ZEXT:
	case InstructionId::INT_SEXT:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		m_ctx->setVarnode(m_instr->m_output, expr);
		break;
	}

	case InstructionId::INT_EQUAL:
	case InstructionId::INT_NOTEQUAL:
	case InstructionId::INT_SLESS:
	case InstructionId::INT_SLESSEQUAL:
	case InstructionId::INT_LESS:
	case InstructionId::INT_LESSEQUAL:
	{
		auto op1 = requestVarnode(m_instr->m_input0);
		auto op2 = requestVarnode(m_instr->m_input1);
		auto condType = ExprTree::Condition::None;
		switch (m_instr->m_id)
		{
		case InstructionId::INT_EQUAL:
			condType = ExprTree::Condition::Eq;
			break;
		case InstructionId::INT_NOTEQUAL:
			condType = ExprTree::Condition::Ne;
			break;
		case InstructionId::INT_LESS:
		case InstructionId::INT_SLESS:
			condType = ExprTree::Condition::Lt;
			break;
		case InstructionId::INT_LESSEQUAL:
		case InstructionId::INT_SLESSEQUAL:
			condType = ExprTree::Condition::Le;
			break;
		}

		auto result = new ExprTree::Condition(op1, op2, condType);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::BOOL_NEGATE:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		if (auto cond = dynamic_cast<ExprTree::ICondition*>(expr)) {
			auto result = new ExprTree::CompositeCondition(cond, nullptr, ExprTree::CompositeCondition::Not);
			m_ctx->setVarnode(m_instr->m_output, result);
		}
		break;
	}

	case InstructionId::BOOL_AND:
	case InstructionId::BOOL_OR:
	case InstructionId::BOOL_XOR:
	{
		auto op1 = requestVarnode(m_instr->m_input0);
		auto op2 = requestVarnode(m_instr->m_input1);
		if (auto condOp1 = dynamic_cast<ExprTree::ICondition*>(op1)) {
			if (auto condOp2 = dynamic_cast<ExprTree::ICondition*>(op2)) {
				ExprTree::CompositeCondition* result;
				if (m_instr->m_id == InstructionId::BOOL_XOR) {
					auto notCondOp1 = new ExprTree::CompositeCondition(condOp1, nullptr, ExprTree::CompositeCondition::Not);
					auto notCondOp2 = new ExprTree::CompositeCondition(condOp2, nullptr, ExprTree::CompositeCondition::Not);
					auto case1 = new ExprTree::CompositeCondition(notCondOp1, condOp2, ExprTree::CompositeCondition::And);
					auto case2 = new ExprTree::CompositeCondition(condOp1, notCondOp2, ExprTree::CompositeCondition::And);
					result = new ExprTree::CompositeCondition(case1, case2, ExprTree::CompositeCondition::Or);
				}
				else {
					auto condType = ExprTree::CompositeCondition::And;
					if (m_instr->m_id == InstructionId::BOOL_OR)
						condType = ExprTree::CompositeCondition::Or;
					result = new ExprTree::CompositeCondition(condOp1, condOp2, condType);
				}
				m_ctx->setVarnode(m_instr->m_output, result);
			}
		}
		break;
	}

	case InstructionId::INT_CARRY:
	case InstructionId::INT_SCARRY:
	case InstructionId::INT_SBORROW:
	{
		auto op1 = requestVarnode(m_instr->m_input0);
		auto op2 = requestVarnode(m_instr->m_input1);
		auto funcId = ExprTree::FunctionalNode::Id::CARRY;
		if(m_instr->m_id == InstructionId::INT_SCARRY)
			funcId = ExprTree::FunctionalNode::Id::SCARRY;
		else if (m_instr->m_id == InstructionId::INT_SBORROW)
			funcId = ExprTree::FunctionalNode::Id::SBORROW;

		auto result = new ExprTree::FunctionalNode(op1, op2, funcId);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::CBRANCH:
	{
		auto op2 = requestVarnode(m_instr->m_input1);
		if (auto flagCond = dynamic_cast<ExprTree::ICondition*>(op2)) {
			auto notFlagCond = new ExprTree::CompositeCondition(flagCond, nullptr, ExprTree::CompositeCondition::Not);
			m_block->setNoJumpCondition(notFlagCond);
		}
		break;
	}

	case InstructionId::CALL:
	case InstructionId::CALLIND:
	{
		int dstLocOffset = 0;
		auto dstLocExpr = requestVarnode(m_instr->m_input0);
		if (auto dstLocExprNum = dynamic_cast<ExprTree::NumberLeaf*>(dstLocExpr)) {
			dstLocOffset = int(dstLocExprNum->m_value >> 8);
		}

		auto funcCallInfo = m_ctx->m_decompiler->m_funcCallInfoCallback(dstLocOffset, dstLocExpr);
		auto funcCallCtx = new ExprTree::FunctionCallContext(dstLocOffset, dstLocExpr);

		for (auto paramReg : funcCallInfo.m_paramRegisters) {
			auto reg = m_ctx->requestRegisterExpr(paramReg);
			funcCallCtx->addRegisterParam(paramReg, reg);
		}

		ExprTree::Node* dstExpr = nullptr;
		auto& dstRegister = funcCallInfo.m_resultRegister.getGenericId() != 0 ? funcCallInfo.m_resultRegister : funcCallInfo.m_resultVectorRegister;
		if (dstRegister.getGenericId() != 0) {
			auto funcResultVar = new Symbol::FunctionResultVar(funcCallCtx, dstRegister.getSize());
			dstExpr = new ExprTree::SymbolLeaf(funcResultVar);
			m_ctx->setVarnode(dstRegister, dstExpr);
		}

		if (dstExpr == nullptr) {
			dstExpr = new ExprTree::NumberLeaf(0x0);
		}
		m_block->addSeqLine(dstExpr, funcCallCtx);
		break;
	}

	case InstructionId::RETURN:
	{
		if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(m_block)) {
			auto& resultReg = m_ctx->m_decompiler->m_functionCallInfo.m_resultRegister;
			endBlock->setReturnNode(m_ctx->requestRegisterExpr(resultReg));
		}
		break;
	}
	}
}

ExprTree::Node* InstructionInterpreter::requestVarnode(PCode::Varnode* varnode) {
	if (auto varnodeRegister = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
		return m_ctx->requestRegisterExpr(varnodeRegister);
	}
	if (auto varnodeSymbol = dynamic_cast<PCode::SymbolVarnode*>(varnode)) {
		return m_ctx->requestSymbolExpr(varnodeSymbol);
	}
	if (auto varnodeConstant = dynamic_cast<PCode::ConstantVarnode*>(varnode)) {
		return new ExprTree::NumberLeaf(varnodeConstant->m_value);
	}
	return nullptr;
}
