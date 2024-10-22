#include "PCodeInterpreter.h"
#include "Decompiler.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::PCode;

void InstructionInterpreter::execute(Instruction* instr) {
	m_instr = instr;

	switch (m_instr->m_id)
	{
	case InstructionId::COPY:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		m_ctx->setVarnode(m_instr->m_output, new ExprTree::MirrorNode(expr, m_instr));
		break;
	}

	case InstructionId::LOAD:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		auto readSize = m_instr->m_output->getSize();
		auto readValueNode = new ExprTree::ReadValueNode(expr, readSize, m_instr);
		auto memSymbolLeaf = createMemSymbol(readValueNode, m_instr);
		m_ctx->setVarnode(m_instr->m_output, memSymbolLeaf);
		break;
	}

	case InstructionId::STORE:
	{
		auto dstExpr = requestVarnode(m_instr->m_input0);
		auto srcExpr = requestVarnode(m_instr->m_input1);
		dstExpr = new ExprTree::ReadValueNode(dstExpr, m_instr->m_input1->getSize(), m_instr);
		m_block->addSeqLine(dstExpr, srcExpr, m_instr);
		break;
	}

	case InstructionId::INT_ADD:
	case InstructionId::INT_SUB:
	case InstructionId::INT_MULT:
	case InstructionId::INT_DIV:
	case InstructionId::FLOAT_ADD:
	case InstructionId::FLOAT_SUB:
	case InstructionId::FLOAT_MULT:
	case InstructionId::FLOAT_DIV:
	case InstructionId::INT_SDIV:
	case InstructionId::INT_REM:
	case InstructionId::INT_SREM:
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
			if (m_instr->m_id == InstructionId::INT_SUB) {
				auto numberLeaf = new ExprTree::NumberLeaf((uint64_t)(int64_t)-1, m_instr->m_input1->getMask().getSize());
				op2 = new ExprTree::OperationalNode(op2, numberLeaf, ExprTree::Mul);
			}
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
		case InstructionId::FLOAT_ADD:
		case InstructionId::FLOAT_SUB:
			opType = ExprTree::fAdd;
			if (m_instr->m_id == InstructionId::FLOAT_SUB) {
				auto numberLeaf = new ExprTree::NumberLeaf(-1.0, m_instr->m_input1->getMask().getSize());
				op2 = new ExprTree::OperationalNode(op2, numberLeaf, ExprTree::fMul);
			}
			break;
		case InstructionId::FLOAT_MULT:
			opType = ExprTree::fMul;
			break;
		case InstructionId::FLOAT_DIV:
			opType = ExprTree::fDiv;
			break;
		}

		auto result = new ExprTree::OperationalNode(op1, op2, opType, m_instr);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::INT_NEGATE:
	case InstructionId::INT_2COMP:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		auto nodeMask = new ExprTree::NumberLeaf((uint64_t)(int64_t)-1, m_instr->m_input0->getMask().getSize());
		auto opType = (m_instr->m_id == InstructionId::INT_2COMP) ? ExprTree::Mul : ExprTree::Xor;
		m_ctx->setVarnode(m_instr->m_output, new ExprTree::OperationalNode(expr, nodeMask, opType, m_instr));
		break;
	}

	case InstructionId::INT_ZEXT:
	case InstructionId::INT_SEXT:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		if (m_instr->m_output->getSize() <= 8) {
			// todo: increase from 8 to 16 bytes (it requires 128-bit arithmetic implementation)
			expr = new ExprTree::CastNode(expr, m_instr->m_output->getSize(), m_instr->m_id == InstructionId::INT_SEXT);
		}
		m_ctx->setVarnode(m_instr->m_output, expr);
		break;
	}

	case InstructionId::SUBPIECE:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		auto shiftExpr = requestVarnode(m_instr->m_input1);
		shiftExpr = new ExprTree::OperationalNode(shiftExpr, new ExprTree::NumberLeaf((uint64_t)0x8, shiftExpr->getSize()), ExprTree::Mul);
		expr = new ExprTree::OperationalNode(expr, shiftExpr, ExprTree::Shr);
		auto numberLeaf = new ExprTree::NumberLeaf((uint64_t)-1, m_instr->m_output->getMask().getSize());
		expr = new ExprTree::OperationalNode(expr, numberLeaf, ExprTree::And, m_instr);
		m_ctx->setVarnode(m_instr->m_output, expr);
		break;
	}

	case InstructionId::FLOAT_NEG:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		auto result = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(-1.0, m_instr->m_input0->getMask().getSize()), ExprTree::fMul, m_instr);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::FLOAT_ABS:
	case InstructionId::FLOAT_SQRT:
	case InstructionId::INT2FLOAT:
	case InstructionId::FLOAT2INT:
	case InstructionId::FLOAT2FLOAT:
	case InstructionId::TRUNC:
	case InstructionId::CEIL:
	case InstructionId::FLOOR:
	case InstructionId::ROUND:
	{
		auto expr = requestVarnode(m_instr->m_input0);
		auto id = ExprTree::FloatFunctionalNode::Id::FABS;
		switch (m_instr->m_id)
		{
		case InstructionId::FLOAT_SQRT:
			id = ExprTree::FloatFunctionalNode::Id::FSQRT;
			break;
		case InstructionId::INT2FLOAT:
		case InstructionId::FLOAT2FLOAT:
			id = ExprTree::FloatFunctionalNode::Id::TOFLOAT;
			break;
		case InstructionId::FLOAT2INT:
			id = ExprTree::FloatFunctionalNode::Id::TOINT;
			break;
		case InstructionId::TRUNC:
			id = ExprTree::FloatFunctionalNode::Id::TRUNC;
			break;
		case InstructionId::CEIL:
			id = ExprTree::FloatFunctionalNode::Id::CEIL;
			break;
		case InstructionId::FLOOR:
			id = ExprTree::FloatFunctionalNode::Id::FLOOR;
			break;
		case InstructionId::ROUND:
			id = ExprTree::FloatFunctionalNode::Id::ROUND;
			break;
		}

		m_ctx->setVarnode(m_instr->m_output, new ExprTree::FloatFunctionalNode(expr, id, m_instr->m_input0->getSize(), m_instr));
		break;
	}

	case InstructionId::INT_EQUAL:
	case InstructionId::INT_NOTEQUAL:
	case InstructionId::INT_SLESS:
	case InstructionId::INT_SLESSEQUAL:
	case InstructionId::INT_LESS:
	case InstructionId::INT_LESSEQUAL:
	case InstructionId::FLOAT_EQUAL:
	case InstructionId::FLOAT_NOTEQUAL:
	case InstructionId::FLOAT_LESS:
	case InstructionId::FLOAT_LESSEQUAL:
	{
		//notice: the size(mask) of the left and the right part of a condition must be equal: if([sym]{4 bytes} == 0x0{4 bytes too})
		auto op1 = requestVarnode(m_instr->m_input0);
		auto op2 = requestVarnode(m_instr->m_input1);

		auto condType = ExprTree::Condition::None;
		switch (m_instr->m_id)
		{
		case InstructionId::INT_EQUAL:
		case InstructionId::FLOAT_EQUAL:
			condType = ExprTree::Condition::Eq;
			break;
		case InstructionId::INT_NOTEQUAL:
		case InstructionId::FLOAT_NOTEQUAL:
			condType = ExprTree::Condition::Ne;
			break;
		case InstructionId::INT_LESS:
		case InstructionId::INT_SLESS:
		case InstructionId::FLOAT_LESS:
			condType = ExprTree::Condition::Lt;
			break;
		case InstructionId::INT_LESSEQUAL:
		case InstructionId::INT_SLESSEQUAL:
		case InstructionId::FLOAT_LESSEQUAL:
			condType = ExprTree::Condition::Le;
			break;
		}

		bool isFloatingPoint = (InstructionId::FLOAT_EQUAL <= m_instr->m_id && m_instr->m_id <= InstructionId::FLOAT_LESSEQUAL);
		auto result = new ExprTree::Condition(op1, op2, condType, m_instr);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::FLOAT_NAN:
	{
		auto op1 = requestVarnode(m_instr->m_input0);
		auto result = new ExprTree::Condition(op1, new ExprTree::FloatNanLeaf(), ExprTree::Condition::Eq, m_instr);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::BOOL_NEGATE:
	{
		auto cond = toBoolean(requestVarnode(m_instr->m_input0));
		if (cond) {
			auto result = new ExprTree::CompositeCondition(cond, nullptr, ExprTree::CompositeCondition::Not, m_instr);
			m_ctx->setVarnode(m_instr->m_output, result);
		}
		break;
	}

	case InstructionId::BOOL_AND:
	case InstructionId::BOOL_OR:
	case InstructionId::BOOL_XOR:
	{
		auto condOp1 = toBoolean(requestVarnode(m_instr->m_input0));
		auto condOp2 = toBoolean(requestVarnode(m_instr->m_input1));
		if (condOp1) {
			if (condOp2) {
				ExprTree::CompositeCondition* result;
				if (m_instr->m_id == InstructionId::BOOL_XOR) {
					auto notCondOp1 = new ExprTree::CompositeCondition(condOp1, nullptr, ExprTree::CompositeCondition::Not);
					auto notCondOp2 = new ExprTree::CompositeCondition(condOp2, nullptr, ExprTree::CompositeCondition::Not);
					auto case1 = new ExprTree::CompositeCondition(notCondOp1, condOp2, ExprTree::CompositeCondition::And);
					auto case2 = new ExprTree::CompositeCondition(condOp1, notCondOp2, ExprTree::CompositeCondition::And);
					result = new ExprTree::CompositeCondition(case1, case2, ExprTree::CompositeCondition::Or, m_instr);
				}
				else {
					auto condType = ExprTree::CompositeCondition::And;
					if (m_instr->m_id == InstructionId::BOOL_OR)
						condType = ExprTree::CompositeCondition::Or;
					result = new ExprTree::CompositeCondition(condOp1, condOp2, condType, m_instr);
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

		auto result = new ExprTree::FunctionalNode(op1, op2, funcId, m_instr);
		m_ctx->setVarnode(m_instr->m_output, result);
		break;
	}

	case InstructionId::CBRANCH:
	{
		auto flagCond = toBoolean(requestVarnode(m_instr->m_input1));
		if (flagCond) {
			auto notFlagCond = new ExprTree::CompositeCondition(flagCond, nullptr, ExprTree::CompositeCondition::Not, m_instr);
			m_block->setNoJumpCondition(notFlagCond);
		}
		break;
	}

	case InstructionId::CALL:
	case InstructionId::CALLIND:
	{
		auto dstLocExpr = requestVarnode(m_instr->m_input0);

		int dstLocOffset = 0;
		auto& constValues = m_block->m_decompiledGraph->getFuncGraph()->getConstValues();
		auto it = constValues.find(m_instr);
		if (it != constValues.end())
			dstLocOffset = (int)it->second;

		auto funcCallInfo = m_decompiler->m_funcCallInfoCallback(dstLocOffset, dstLocExpr);
		auto funcCallCtx = new ExprTree::FunctionCall(dstLocExpr, m_instr);

		for (int paramIdx = 1; paramIdx <= 100; paramIdx++) {
			auto paramInfo = funcCallInfo.findParamInfoByIndex(paramIdx);
			if (paramInfo.m_storage.getType() != Storage::STORAGE_NONE) {
				auto node = buildParameterInfoExpr(paramInfo);
				funcCallCtx->addParamNode(node);
			}
			else {
				break;
			}
		}

		PCode::Register dstRegister;
		auto retInfo = funcCallInfo.getReturnInfo();
		if (retInfo.m_storage.getType() != Storage::STORAGE_NONE) {
			dstRegister = m_decompiler->getRegisterFactory()->createRegister(retInfo.m_storage.getRegisterId(), retInfo.m_size, retInfo.m_storage.getOffset());
		}

		auto funcResultVar = new Symbol::FunctionResultVar(m_instr, dstRegister.getSize());
		funcCallCtx->m_functionResultVar = funcResultVar;
		m_block->m_decompiledGraph->addSymbol(funcResultVar);
		auto symbolLeaf = new ExprTree::SymbolLeaf(funcResultVar);
		m_block->addSeqLine(symbolLeaf, funcCallCtx);
		if (dstRegister.isValid()) {
			m_ctx->m_registerExecCtx.setRegister(dstRegister, symbolLeaf);
		}
		break;
	}

	case InstructionId::RETURN:
	{
		if (auto endBlock = dynamic_cast<PrimaryTree::EndBlock*>(m_block)) {
			auto& retInfo = m_decompiler->m_returnInfo;
			if (retInfo.m_storage.getType() != Storage::STORAGE_NONE) {
				auto dstRegister = m_decompiler->getRegisterFactory()->createRegister(retInfo.m_storage.getRegisterId(), retInfo.m_size, retInfo.m_storage.getOffset());
				endBlock->setReturnNode(m_ctx->m_registerExecCtx.requestRegister(dstRegister));
			}
		}
		break;
	}
	}
}

ExprTree::INode* InstructionInterpreter::buildParameterInfoExpr(ParameterInfo& paramInfo) {
	auto& storage = paramInfo.m_storage;

	// memory
	if (storage.getType() == Storage::STORAGE_STACK || storage.getType() == Storage::STORAGE_GLOBAL) {
		auto reg = m_decompiler->getRegisterFactory()->createRegister(storage.getRegisterId(), 0x8); // RIP or RSP (8 bytes = size of pointer)
		auto regSymbol = m_ctx->m_registerExecCtx.requestRegister(reg);
		auto offsetNumber = new ExprTree::NumberLeaf((uint64_t)storage.getOffset() - 0x8, regSymbol->getSize());
		auto opAddNode = new ExprTree::OperationalNode(regSymbol, offsetNumber, ExprTree::Add);
		auto readValueNode = new ExprTree::ReadValueNode(opAddNode, paramInfo.m_size);
		return createMemSymbol(readValueNode);
	}

	// register
	auto reg = m_decompiler->getRegisterFactory()->createRegister(storage.getRegisterId(), paramInfo.m_size, storage.getOffset());
	auto regSymbol = m_ctx->m_registerExecCtx.requestRegister(reg);
	return regSymbol;
}

ExprTree::INode* InstructionInterpreter::requestVarnode(PCode::Varnode* varnode) {
	return m_ctx->requestVarnode(varnode);
}

ExprTree::AbstractCondition* InstructionInterpreter::toBoolean(ExprTree::INode* node) {
	if (!node)
		return nullptr;
	if (auto cond = dynamic_cast<ExprTree::AbstractCondition*>(node)) { // condition always returns boolean value
		return cond;
	}
	// otherwise make condition yourself: x != 0
	return new ExprTree::Condition(node, new ExprTree::NumberLeaf((uint64_t)0x0, 1), ExprTree::Condition::Ne);
}

ExprTree::SymbolLeaf* PCode::InstructionInterpreter::createMemSymbol(ExprTree::ReadValueNode* readValueNode, PCode::Instruction* instr) {
	auto memVar = new Symbol::MemoryVariable(instr, readValueNode->getSize());
	readValueNode->m_memVar = memVar;
	m_block->m_decompiledGraph->addSymbol(memVar);
	auto memSymbolLeaf = new ExprTree::SymbolLeaf(memVar);
	m_block->addSeqLine(memSymbolLeaf, readValueNode, instr);
	return memSymbolLeaf;
}
