#pragma once
#include "DecAsmGraph.h"
#include <Utility/Generic.h>

namespace CE::Decompiler
{
	namespace Symbol
	{
		class Symbol
		{
		public:
			virtual std::string printDebug() = 0;
		};

		class GlobalObject : public Symbol
		{
		public:
			int m_offset;

			GlobalObject(int offset)
				: m_offset(offset)
			{}

			std::string printDebug() override {
				return "[global:" + std::to_string(m_offset) + "]";
			}
		};

		class LocalStackTop : public Symbol
		{
		public:
			LocalStackTop()
			{}

			std::string printDebug() override {
				return "[stack top]";
			}
		};

		class LocalStackVar : public Symbol
		{
		public:
			int m_stackOffset;

			LocalStackVar(int stackOffset)
				: m_stackOffset(stackOffset)
			{}

			std::string printDebug() override {
				return "[stack]";
			}
		};

		class LocalRegVar : public Symbol
		{
		public:
			ZydisRegister m_register;

			LocalRegVar(ZydisRegister reg)
				: m_register(reg)
			{}

			std::string printDebug() override {
				return "[reg_" + std::string(ZydisRegisterGetString(m_register)) + "]";
			}
		};

		class Parameter : public Symbol
		{
		public:
			int m_idx = 0;
			bool m_isVector;
			Parameter(int idx, bool isVector = false)
				: m_idx(idx), m_isVector(isVector)
			{}

			std::string printDebug() override {
				return "[param_"+ std::to_string(m_idx) +"]";
			}
		};
	};

	namespace ExprTree
	{
		class Node
		{
		public:
			Node* m_parentNode;

			Node()
			{}

			void setSigned(bool toggle) {
				m_isSigned = toggle;
			}

			bool isSigned() {
				return m_isSigned;
			}

			virtual bool isLeaf() = 0;

			virtual std::string printDebug() = 0;

		private:
			bool m_isSigned = false;
		};

		enum OperationType
		{
			None,

			//Arithmetic
			Add,
			Sub,
			Mul,
			Div,

			//Logic
			And,
			Or,
			Xor,
			Shr,
			Shl,

			//Memory
			readValue
		};

		static std::string ShowOperation(OperationType opType) {
			switch (opType)
			{
			case Add: return "+";
			case Sub: return "-";
			case Mul: return "*";
			case Div: return "/";
			case And: return "&";
			case Or: return "|";
			case Xor: return "^";
			case Shr: return ">>";
			case Shl: return "<<";
			case readValue: return "&";
			}
			return "_";
		}

		class SymbolLeaf : public Node
		{
		public:
			Symbol::Symbol* m_symbol;

			SymbolLeaf(Symbol::Symbol* symbol)
				: m_symbol(symbol)
			{}

			bool isLeaf() override {
				return true;
			}

			std::string printDebug() override {
				return m_symbol->printDebug();
			}
		};

		class NumberLeaf : public Node
		{
		public:
			uint64_t m_value;

			NumberLeaf(uint64_t value)
				: m_value(value)
			{}

			bool isLeaf() override {
				return true;
			}

			std::string printDebug() override {
				return "0x" + Generic::String::NumberToHex(m_value);
			}
		};

		class OperationalNode : public Node
		{
		public:
			Node* m_leftNode;
			Node* m_rightNode;
			OperationType m_operation;

			OperationalNode(Node* leftNode, Node* rightNode, OperationType operation)
				: m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation)
			{
				leftNode->m_parentNode = this;
				if (rightNode != nullptr) {
					rightNode->m_parentNode = this;
				}
			}

			bool isLeaf() override {
				return false;
			}

			std::string printDebug() override {
				if (m_operation == readValue) {
					return "*(uint_"+ std::to_string(8 * static_cast<NumberLeaf*>(m_rightNode)->m_value) +"t*)" + m_leftNode->printDebug();
				}
				return "(" + m_leftNode->printDebug() + " " + ShowOperation(m_operation) + " " + m_rightNode->printDebug() + ")";
			}
		};
	};

	namespace PrimaryTree
	{
		class Line
		{
		public:
			ExprTree::Node* m_destAddr;
			ExprTree::Node* m_srcValue;

			Line(ExprTree::Node* destAddr, ExprTree::Node* srcValue)
				: m_destAddr(destAddr), m_srcValue(srcValue)
			{}
		};

		class Block
		{
		public:
			Block()

			{}

			std::list<Line*>& getLines() {
				return m_lines;
			}

			std::string printDebug() {
				std::string result = "";
				for (auto line : m_lines) {
					result += line->m_destAddr->printDebug() + " = " + line->m_srcValue->printDebug() + "\n";
				}
				return result;
			}
		private:
			std::list<Line*> m_lines;
		};
	};

	class ExpressionManager
	{
	public:
		ExpressionManager()

		{}

		std::list<Symbol::Symbol*>& getSymbols() {
			return m_symbols;
		}

		std::list<ExprTree::Node*>& getExprNodes() {
			return m_exprNodes;
		}
	private:
		std::list<Symbol::Symbol*> m_symbols;
		std::list<ExprTree::Node*> m_exprNodes;
	};

	class ExecutionContext
	{
	public:
		ExpressionManager* m_expressionManager;
		int m_offset;
		std::map<std::string, ExprTree::Node*> m_memory;

		ExecutionContext(ExpressionManager* expressionManager, int startOffset = 0)
			: m_expressionManager(expressionManager), m_offset(startOffset)
		{}
	};

	class Register
	{
	public:
		struct RegInfo {
			uint64_t m_mask = 0x0;
			bool m_isVector = false;
			std::list<std::pair<ZydisRegister, uint64_t>> m_sameRegisters;
		};

		static RegInfo GetRegInfo(ZydisRegister reg) {
			RegInfo info;
			if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_BL) {
				info.m_mask = 0xFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AL);
			}
			else if (reg >= ZYDIS_REGISTER_AH && reg <= ZYDIS_REGISTER_BH) {
				info.m_mask = 0xFF00;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AH);
				info.m_sameRegisters.begin()->first = reg;
			}
			else if (reg >= ZYDIS_REGISTER_SPL && reg <= ZYDIS_REGISTER_R15B) {
				info.m_mask = 0xFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AH);
			}
			else if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
				info.m_mask = 0xFFFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AX);
			}
			else if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
				info.m_mask = 0xFFFFFFFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_EAX);
			}
			else if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
				info.m_mask = 0xFFFFFFFFFFFFFFFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_RAX);
			}
			else if (reg >= ZYDIS_REGISTER_MM0 && reg <= ZYDIS_REGISTER_MM7) {
				info.m_mask = 0xF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_MM0);
			}
			else if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
				info.m_mask = 0xFF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_XMM0);
			}
			else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
				info.m_mask = 0xFFFF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_YMM0);
			}
			else if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
				info.m_mask = 0xFFFFFFFF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_ZMM0);
			}
			else {
				info.m_mask = 0xFFFFFFFFFFFFFFFF;
			}
			return info;
		}

		static int GetRegisterParamIdx(ZydisRegister reg) {
			static std::set paramRegs_1 = {
				ZYDIS_REGISTER_CL,
				ZYDIS_REGISTER_CH,
				ZYDIS_REGISTER_CX,
				ZYDIS_REGISTER_ECX,
				ZYDIS_REGISTER_RCX,
				ZYDIS_REGISTER_XMM0,
				ZYDIS_REGISTER_YMM0,
				ZYDIS_REGISTER_ZMM0
			};
			static std::set paramRegs_2 = {
				ZYDIS_REGISTER_DL,
				ZYDIS_REGISTER_DH,
				ZYDIS_REGISTER_DX,
				ZYDIS_REGISTER_EDX,
				ZYDIS_REGISTER_RDX,
				ZYDIS_REGISTER_XMM1,
				ZYDIS_REGISTER_YMM1,
				ZYDIS_REGISTER_ZMM1
			};
			static std::set paramRegs_3 = {
				ZYDIS_REGISTER_R8B,
				ZYDIS_REGISTER_R8W,
				ZYDIS_REGISTER_R8D,
				ZYDIS_REGISTER_R8,
				ZYDIS_REGISTER_XMM2,
				ZYDIS_REGISTER_YMM2,
				ZYDIS_REGISTER_ZMM2
			};
			static std::set paramRegs_4 = {
				ZYDIS_REGISTER_R9B,
				ZYDIS_REGISTER_R9W,
				ZYDIS_REGISTER_R9D,
				ZYDIS_REGISTER_R9,
				ZYDIS_REGISTER_XMM3,
				ZYDIS_REGISTER_YMM3,
				ZYDIS_REGISTER_ZMM3
			};

			if (paramRegs_1.find(reg) != paramRegs_1.end()) {
				return 1;
			}

			if (paramRegs_2.find(reg) != paramRegs_2.end()) {
				return 2;
			}

			if (paramRegs_3.find(reg) != paramRegs_3.end()) {
				return 3;
			}

			if (paramRegs_4.find(reg) != paramRegs_4.end()) {
				return 4;
			}

			return 0;
		}

		static std::string GetAddress(ZydisRegister reg) {
			return "reg:" + std::to_string(reg);
		}

		static int GetShiftValueOfMask(uint64_t mask) {
			int result = 0;
			for (auto m = mask; int(m & 0xF) == 0; m = m >> 4) {
				result += 4;
			}
			return result;
		}

		static ExprTree::Node* CreateExprRegLeaf(ExecutionContext* ctx, ZydisRegister reg) {
			Symbol::Symbol* symbol = new Symbol::LocalRegVar(reg);
			auto leaf = new ExprTree::SymbolLeaf(symbol);
			ctx->m_expressionManager->getSymbols().push_back(symbol);
			ctx->m_expressionManager->getExprNodes().push_back(leaf);
			return leaf;
		}

		static ExprTree::Node* GetOrCreateExprRegLeaf(ExecutionContext* ctx, ZydisRegister reg) {
			auto addr = Register::GetAddress(reg);
			if (ctx->m_memory.find(addr) != ctx->m_memory.end()) {
				return ctx->m_memory[addr];
			}

			auto regInfo = Register::GetRegInfo(reg);
			ExprTree::Node* node = nullptr;
			for (auto it = regInfo.m_sameRegisters.rbegin(); it != regInfo.m_sameRegisters.rend(); it ++) {
				auto sameReg = *it;
				if (sameReg.first != reg) {
					auto it = ctx->m_memory.find(Register::GetAddress(sameReg.first));
					if (it != ctx->m_memory.end()) {
						node = it->second;
						if (sameReg.second > regInfo.m_mask) {
							node = new ExprTree::OperationalNode(node, new ExprTree::NumberLeaf(sameReg.second & regInfo.m_mask), ExprTree::And);
							int rightBitShift = Register::GetShiftValueOfMask(regInfo.m_mask);
							if (rightBitShift != 0) {
								node = new ExprTree::OperationalNode(node, new ExprTree::NumberLeaf(rightBitShift), ExprTree::Shr);
							}
						}
						break;
					}
				}
			}

			if (!node) {
				node = CreateExprRegLeaf(ctx, reg);
			}
			ctx->m_memory.insert(std::make_pair(addr, node));
			return node;
		}
		
	private:
		static std::list<std::pair<ZydisRegister, uint64_t>> GetListOfSameGenRegisters(int idx) {
			std::list result = {
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_AX + idx), (uint64_t)0xFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_EAX + idx), (uint64_t)0xFFFFFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_RAX + idx), (uint64_t)0xFFFFFFFFFFFFFFFF)
			};
			if (idx <= 3)
				result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_AL + idx), (uint64_t)0xFF));
			else result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_AH + idx), (uint64_t)0xFF));
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

	class Operand
	{
	public:
		Operand(ExecutionContext* ctx, const ZydisDecodedOperand* operand)
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
		ExecutionContext* m_ctx;
		const ZydisDecodedOperand* m_operand;

		static ExprTree::Node* CreateExprNumLeaf(ExecutionContext* ctx, uint64_t value) {
			auto leaf = new ExprTree::NumberLeaf(value);
			ctx->m_expressionManager->getExprNodes().push_back(leaf);
			return leaf;
		}

		static ExprTree::Node* CreateExprMemLocation(ExecutionContext* ctx, const ZydisDecodedOperand_::ZydisDecodedOperandMem_& mem) {
			ExprTree::Node* expr = nullptr;
			ExprTree::Node* baseReg = nullptr;

			if (mem.base != ZYDIS_REGISTER_NONE) {
				baseReg = Register::GetOrCreateExprRegLeaf(ctx, mem.base);
			}

			if (mem.index != ZYDIS_REGISTER_NONE) {
				expr = new ExprTree::OperationalNode(
					Register::GetOrCreateExprRegLeaf(ctx, mem.index), new ExprTree::NumberLeaf(mem.scale), ExprTree::Mul);
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

			ctx->m_expressionManager->getExprNodes().push_back(expr);
			return expr;
		}
	};

	class AbstractInstructionInterpreter
	{
	public:
		AbstractInstructionInterpreter(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: m_block(block), m_ctx(ctx), m_instruction(instruction)
		{}

		virtual void execute() = 0;

	protected:
		PrimaryTree::Block* m_block;
		ExecutionContext* m_ctx;
		const ZydisDecodedInstruction* m_instruction;

		void unaryOperation(ExprTree::OperationType opType, ExprTree::Node* srcExpr, ExprTree::Node* dstExpr = nullptr) {
			Operand op(m_ctx, &m_instruction->operands[0]);
			if (!op.isDst())
				return;

			if (!dstExpr) {
				dstExpr = op.getExpr();
			}
			assignment(m_instruction->operands[0], new ExprTree::OperationalNode(dstExpr, srcExpr, opType), dstExpr);
		}

		void binOperation(ExprTree::OperationType opType, bool isSigned = false) {
			Operand op1(m_ctx, &m_instruction->operands[0]);
			Operand op2(m_ctx, &m_instruction->operands[1]);
			if (!op1.isDst() || !op2.isValid())
				return;

			ExprTree::Node* dstExpr = nullptr;
			ExprTree::Node* srcExpr = op2.getExpr();
			if (opType != ExprTree::None) {
				dstExpr = op1.getExpr();
				srcExpr = new ExprTree::OperationalNode(dstExpr, srcExpr, opType);
			}

			srcExpr->setSigned(isSigned);
			assignment(m_instruction->operands[0], srcExpr, dstExpr);
		}

		void tripleOperation(ExprTree::OperationType opType, bool isSigned = false) {
			Operand op1(m_ctx, &m_instruction->operands[0]);
			Operand op2(m_ctx, &m_instruction->operands[1]);
			Operand op3(m_ctx, &m_instruction->operands[1]);
			if (!op1.isDst() || !op2.isValid() || !op2.isValid())
				return;

			auto srcExpr = new ExprTree::OperationalNode(op2.getExpr(), op3.getExpr(), opType);
			srcExpr->setSigned(isSigned);
			assignment(m_instruction->operands[0], srcExpr);
		}

		void assignment(const ZydisDecodedOperand& dstOperand, ExprTree::Node* srcExpr, ExprTree::Node* dstExpr = nullptr) {
			if (dstOperand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				if (!dstExpr) {
					Operand op(m_ctx, &dstOperand);
					dstExpr = op.getExpr();
				}
				auto line = new PrimaryTree::Line(dstExpr, srcExpr);
				m_block->getLines().push_back(line);
			}
			else {
				setExprToRegisterDst(dstOperand.reg.value, srcExpr);
			}
		}

		void setExprToRegisterDst(ZydisRegister dstReg, ExprTree::Node* srcExpr) {
			auto regInfo = Register::GetRegInfo(dstReg);
			m_ctx->m_memory[Register::GetAddress(dstReg)] = srcExpr;

			//if these are ah, bh, ch, dh registers
			int leftBitShift = Register::GetShiftValueOfMask(regInfo.m_mask);

			for (auto sameReg : regInfo.m_sameRegisters) {
				if (sameReg.first == dstReg)
					continue;
				auto it = m_ctx->m_memory.find(Register::GetAddress(sameReg.first));
				if (it != m_ctx->m_memory.end()) {
					if (regInfo.m_mask <= sameReg.second) {
						auto srcExprShl = srcExpr;
						if (srcExprShl->isSigned()) {
							//хранить число байт для каста через энд
							srcExprShl = new ExprTree::OperationalNode(srcExprShl, , ExprTree::And);
						}
						if (leftBitShift != 0) {
							srcExprShl = new ExprTree::OperationalNode(srcExprShl, new ExprTree::NumberLeaf(leftBitShift), ExprTree::Shl);
						}

						auto maskNumber = new ExprTree::NumberLeaf(~(sameReg.second & regInfo.m_mask));
						auto maskMultipleOperation = new ExprTree::OperationalNode(it->second, maskNumber, ExprTree::And);
						it->second = new ExprTree::OperationalNode(maskMultipleOperation, srcExprShl, ExprTree::Or);
					}
					else {
						m_ctx->m_memory.erase(it);
					}
				}
			}
		}
	};

	class MovementInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		MovementInstructionInterpreter(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_MOV:
			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
			case ZYDIS_MNEMONIC_MOVSXD:
			case ZYDIS_MNEMONIC_LEA: {
				bool isSigned = false;
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_MOVSX || m_instruction->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
					isSigned = true;
				}
				binOperation(ExprTree::None, isSigned);
				break;
			}
			}
		}
	};

	class ArithmeticInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		ArithmeticInstructionInterpreter(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_ADD:
				binOperation(ExprTree::Add);
				break;
			case ZYDIS_MNEMONIC_SUB:
				binOperation(ExprTree::Sub);
				break;
			case ZYDIS_MNEMONIC_MUL:
			case ZYDIS_MNEMONIC_IMUL:
			case ZYDIS_MNEMONIC_DIV:
			case ZYDIS_MNEMONIC_IDIV:
			{
				auto opType = ExprTree::Mul;
				bool isSigned = false;
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_DIV || m_instruction->mnemonic == ZYDIS_MNEMONIC_IDIV) {
					opType = ExprTree::Div;
				}
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_IMUL || m_instruction->mnemonic == ZYDIS_MNEMONIC_IDIV) {
					isSigned = true;
				}

				if (m_instruction->operand_count == 1)
				{
					ZydisRegister reg;
					switch (m_instruction->operands[0].size)
					{
					case 1:
						reg = ZYDIS_REGISTER_AL;
						break;
					case 2:
						reg = ZYDIS_REGISTER_AX;
						break;
					case 4:
						reg = ZYDIS_REGISTER_EAX;
						break;
					default:
						reg = ZYDIS_REGISTER_RAX;
					}

					Operand op(m_ctx, &m_instruction->operands[0]);
					auto srcExpr = new ExprTree::OperationalNode(Register::GetOrCreateExprRegLeaf(m_ctx, reg), op.getExpr(), opType);
					srcExpr->setSigned(isSigned);
					setExprToRegisterDst(reg, srcExpr);
				}
				else if (m_instruction->operand_count == 2)
				{
					binOperation(opType, isSigned);
				}
				else if (m_instruction->operand_count == 3)
				{
					tripleOperation(opType, isSigned);
				}
				break;
			}
			case ZYDIS_MNEMONIC_INC:
				unaryOperation(ExprTree::Add, new ExprTree::NumberLeaf(1));
				break;
			case ZYDIS_MNEMONIC_DEC:
				unaryOperation(ExprTree::Sub, new ExprTree::NumberLeaf(1));
				break;
			case ZYDIS_MNEMONIC_NEG:
				unaryOperation(ExprTree::Mul, new ExprTree::NumberLeaf(-1));
				break;
			}
		}
	};

	class InstructionDispatcher
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction& instruction) {
			{
				MovementInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}

			{
				ArithmeticInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}
		}
	};

	class Interpreter
	{
	public:
		Interpreter()
		{}

		void execute(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction& instruction) {
			m_dispatcher.execute(block, ctx, instruction);
		}

	private:
		InstructionDispatcher m_dispatcher;
	};
};