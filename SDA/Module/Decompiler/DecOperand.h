#pragma once
#include "DecRegister.h"

namespace CE::Decompiler
{
	class Operand
	{
	public:
		Operand(ExecutionBlockContext* ctx, const ZydisDecodedOperand* operand)
			: m_ctx(ctx), m_operand(operand)
		{}

		ExprTree::Node* getExpr()
		{
			if (m_operand->type == ZYDIS_OPERAND_TYPE_REGISTER) {
				return Register::GetOrCreateExprRegLeaf(m_ctx, m_operand->reg.value);
			}
			else if (m_operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				return CreateExprNumLeaf(m_ctx, m_operand->imm.value.u);
			}
			else if (m_operand->type == ZYDIS_OPERAND_TYPE_MEMORY) {
				auto expr = CreateExprMemLocation(m_ctx, m_operand->mem);
				if (m_operand->actions != 0) {
					expr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(m_operand->size / 0x8), ExprTree::readValue);
				}
				return expr;
			}
			return nullptr;
		}

		bool isValid() {
			return m_operand->type == ZYDIS_OPERAND_TYPE_REGISTER ||
				m_operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
				m_operand->type == ZYDIS_OPERAND_TYPE_MEMORY;
		}

		bool isDst() {
			return m_operand->type == ZYDIS_OPERAND_TYPE_REGISTER ||
				m_operand->type == ZYDIS_OPERAND_TYPE_MEMORY;
		}
	private:
		ExecutionBlockContext* m_ctx;
		const ZydisDecodedOperand* m_operand;

		static ExprTree::Node* CreateExprNumLeaf(ExecutionBlockContext* ctx, uint64_t value) {
			auto leaf = new ExprTree::NumberLeaf(value);
			return leaf;
		}

		static ExprTree::Node* CreateExprMemLocation(ExecutionBlockContext* ctx, const ZydisDecodedOperand_::ZydisDecodedOperandMem_& mem) {
			ExprTree::Node* expr = nullptr;
			ExprTree::Node* baseReg = nullptr;

			if (mem.base != ZYDIS_REGISTER_NONE) {
				baseReg = Register::GetOrCreateExprRegLeaf(ctx, mem.base);
			}

			if (mem.index != ZYDIS_REGISTER_NONE) {
				expr = Register::GetOrCreateExprRegLeaf(ctx, mem.index);
				if (mem.scale != 1) {
					expr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(mem.scale), ExprTree::Mul);
				}
				if (baseReg != nullptr) {
					expr = new ExprTree::OperationalNode(baseReg, expr, ExprTree::Add);
				}
			}
			else {
				expr = baseReg;
			}

			if (mem.disp.has_displacement) {
				auto number = new ExprTree::NumberLeaf((uint64_t&)mem.disp.value);
				if (expr != nullptr) {
					expr = new ExprTree::OperationalNode(expr, number, ExprTree::Add);
				}
				else {
					expr = number;
				}
			}
			return expr;
		}
	};
};