#pragma once
#include "DecAsmGraph.h"
#include <Utility/Generic.h>

namespace CE::Decompiler
{
	static uint64_t GetMaskBySize(int size) {
		uint64_t mask = 0x0;
		while (size != 0) {
			mask |= 0xFF << size;
			size --;
		}
		return mask;
	}

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
		class Node;
		class IParentNode
		{
		public:
			virtual void removeNode(Node* node) = 0;
		};

		class Node
		{
		public:
			Node()
			{}

			virtual ~Node() {
				for (auto parentNode : m_parentNodes) {
					parentNode->removeNode(this);
				}
			}

			void removeBy(IParentNode* node) {
				m_parentNodes.remove(node);
				if (getUserCount() == 0)
					delete this;
			}

			void addParentNode(IParentNode* node) {
				m_parentNodes.push_back(node);
			}

			void setSigned(bool toggle) {
				m_isSigned = toggle;
			}

			bool isSigned() {
				return m_isSigned;
			}

			int getUserCount() {
				return (int)m_parentNodes.size();
			}

			virtual bool isLeaf() = 0;

			virtual std::string printDebug() = 0;

		private:
			bool m_isSigned = false;
			std::list<IParentNode*> m_parentNodes;
		};

		enum OperationType
		{
			None,

			//Arithmetic
			Add,
			Sub,
			Mul,
			Div,
			Mod,

			//Logic
			And,
			Or,
			Xor,
			Shr,
			Shl,

			//Memory
			readValue,

			//Flags
			getBits
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

		class OperationalNode : public Node, public IParentNode
		{
		public:
			Node* m_leftNode;
			Node* m_rightNode;
			OperationType m_operation;

			OperationalNode(Node* leftNode, Node* rightNode, OperationType operation)
				: m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation)
			{
				leftNode->addParentNode(this);
				if (rightNode != nullptr) {
					rightNode->addParentNode(this);
				}
			}

			~OperationalNode() {
				if (m_leftNode != nullptr)
					m_leftNode->removeBy(this);
				if (m_rightNode != nullptr)
					m_rightNode->removeBy(this);
			}

			bool isLeaf() override {
				return false;
			}

			void removeNode(Node* node) override {
				if (m_leftNode == node) {
					m_leftNode = nullptr;
				} else if (m_rightNode == node) {
					m_rightNode = nullptr;
				}
			}

			std::string printDebug() override {
				if (m_operation == readValue) {
					return "*(uint_"+ std::to_string(8 * static_cast<NumberLeaf*>(m_rightNode)->m_value) +"t*)" + m_leftNode->printDebug();
				}
				return "(" + m_leftNode->printDebug() + " " + ShowOperation(m_operation) + " " + m_rightNode->printDebug() + ")";
			}
		};

		class Condition : public Node, public IParentNode
		{
		public:
			enum ConditionType
			{
				None,
				Eq,
				Ne,
				Lt,
				Le,
				Gt,
				Ge
			};

			static std::string ShowConditionType(ConditionType condType) {
				switch (condType)
				{
				case Eq: return "==";
				case Ne: return "!=";
				case Lt: return "<";
				case Le: return "<=";
				case Gt: return ">";
				case Ge: return ">=";
				}
				return "_";
			}

			Node* m_leftNode;
			Node* m_rightNode;
			ConditionType m_cond;

			Condition(Node* leftNode, Node* rightNode, ConditionType cond)
				: m_leftNode(leftNode), m_rightNode(rightNode), m_cond(cond)
			{
				leftNode->addParentNode(this);
				rightNode->addParentNode(this);
			}

			void removeNode(Node* node) override {
				if (m_leftNode == node) {
					m_leftNode = nullptr;
				}
				else if (m_rightNode == node) {
					m_rightNode = nullptr;
				}
			}

			bool isLeaf() override {
				return false;
			}

			std::string printDebug() override {
				return "(" + m_leftNode->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightNode->printDebug() + ")";
			}
		};

		class CompositeCondition : public Node
		{
		public:
			enum CompositeConditionType
			{
				None,
				Not,
				And,
				Or
			};

			static std::string ShowConditionType(CompositeConditionType condType) {
				switch (condType)
				{
				case And: return "&&";
				case Or: return "||";
				}
				return "_";
			}

			Node* m_leftNode;
			Node* m_rightNode;
			CompositeConditionType m_cond;

			CompositeCondition(Node* leftNode, Node* rightNode = nullptr, CompositeConditionType cond = None)
				: m_leftNode(leftNode), m_rightNode(rightNode), m_cond(cond)
			{}

			bool isLeaf() override {
				return false;
			}

			std::string printDebug() override {
				if (m_cond == None) {
					return m_leftNode->printDebug();
				}
				if (m_cond == Not) {
					return "!(" + m_leftNode->printDebug() + ")";
				}
				return "(" + m_leftNode->printDebug() + " " + ShowConditionType(m_cond) + " " + m_rightNode->printDebug() + ")";
			}
		};

		class TernaryOperationalNode : public OperationalNode
		{
		public:
			CompositeCondition* m_condition;

			TernaryOperationalNode(CompositeCondition* condition, Node* leftNode, Node* rightNode)
				: m_condition(condition), OperationalNode(leftNode, rightNode, ExprTree::None)
			{}

			~TernaryOperationalNode() {
				m_condition->removeBy(this);
			}

			void removeNode(Node* node) override {
				OperationalNode::removeNode(node);
				if (m_condition == node) {
					delete this;
				}
			}

			std::string printDebug() override {
				return "(" + m_condition->printDebug() + ") ? " + "(" + m_leftNode->printDebug() + ") : (" + m_rightNode->printDebug() + ")";
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
			ExprTree::Condition* m_jmpCond = nullptr;

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
				if (m_jmpCond != nullptr) {
					result += "\nCondition: " + m_jmpCond->printDebug();
				}
				return result;
			}
		private:
			std::list<Line*> m_lines;
		};
	};

	enum class RegisterFlags {
		None,
		CF = 1 << 1,
		PF = 1 << 2,
		AF = 1 << 3,
		ZF = 1 << 4,
		SF = 1 << 5,
		OF = 1 << 6,

		TEST = ZF | SF | PF,
		CMP = TEST | CF | OF
	};

	class ExecutionContext
	{
	public:
		int m_offset;

		std::map<ZydisRegister, ExprTree::Node*> m_registers;
		std::map<ZydisCPUFlag, ExprTree::Condition*> m_flags;

		struct {
			RegisterFlags flags = RegisterFlags::None;
			ExprTree::Node* leftNode = nullptr;
			ExprTree::Node* rightNode = nullptr;
		} m_lastCond;

		ExecutionContext(int startOffset = 0)
			: m_offset(startOffset)
		{}

		void setLastCond(ExprTree::Node* leftNode, ExprTree::Node* rightNode, RegisterFlags flags) {
			if (m_lastCond.leftNode != nullptr) {
				m_lastCond.leftNode->removeBy(nullptr);
			}
			if (m_lastCond.rightNode != nullptr) {
				m_lastCond.rightNode->removeBy(nullptr);
			}
			m_lastCond.leftNode = leftNode;
			m_lastCond.rightNode = rightNode;
			m_lastCond.flags = flags;
		}

		void clearLastCond() {
			setLastCond(nullptr, nullptr, RegisterFlags::None);
		}
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
			return leaf;
		}

		static ExprTree::Node* GetOrCreateExprRegLeaf(ExecutionContext* ctx, ZydisRegister reg) {
			if (ctx->m_registers.find(reg) != ctx->m_registers.end()) {
				return ctx->m_registers[reg];
			}

			auto regInfo = Register::GetRegInfo(reg);
			ExprTree::Node* node = nullptr;
			for (auto it = regInfo.m_sameRegisters.rbegin(); it != regInfo.m_sameRegisters.rend(); it ++) {
				auto sameReg = *it;
				if (sameReg.first != reg) {
					auto it = ctx->m_registers.find(sameReg.first);
					if (it != ctx->m_registers.end()) {
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
			ctx->m_registers.insert(std::make_pair(reg, node));
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
		ExecutionContext* m_ctx;
		const ZydisDecodedOperand* m_operand;

		static ExprTree::Node* CreateExprNumLeaf(ExecutionContext* ctx, uint64_t value) {
			auto leaf = new ExprTree::NumberLeaf(value);
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

		void unaryOperation(ExprTree::OperationType opType, ExprTree::Node* srcExpr, ExprTree::Node* dstExpr = nullptr, bool isSettingFlags = true) {
			Operand op(m_ctx, &m_instruction->operands[0]);
			if (!op.isDst())
				return;

			if (!dstExpr) {
				dstExpr = op.getExpr();
			}
			assignment(m_instruction->operands[0], new ExprTree::OperationalNode(dstExpr, srcExpr, opType), dstExpr, isSettingFlags);
		}

		void binOperation(ExprTree::OperationType opType, bool isSigned = false, bool isSettingFlags = true) {
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
			assignment(m_instruction->operands[0], srcExpr, dstExpr, isSettingFlags);
		}

		void tripleOperation(ExprTree::OperationType opType, bool isSigned = false, bool isSettingFlags = true) {
			Operand op1(m_ctx, &m_instruction->operands[0]);
			Operand op2(m_ctx, &m_instruction->operands[1]);
			Operand op3(m_ctx, &m_instruction->operands[1]);
			if (!op1.isDst() || !op2.isValid() || !op2.isValid())
				return;

			auto srcExpr = new ExprTree::OperationalNode(op2.getExpr(), op3.getExpr(), opType);
			srcExpr->setSigned(isSigned);
			assignment(m_instruction->operands[0], srcExpr, nullptr, isSettingFlags);
		}

		void assignment(const ZydisDecodedOperand& dstOperand, ExprTree::Node* srcExpr, ExprTree::Node* dstExpr, bool isSettingFlags) {
			if (dstOperand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				if (!dstExpr) {
					Operand op(m_ctx, &dstOperand);
					dstExpr = op.getExpr();
				}
				if(isSettingFlags)
					setFlags(srcExpr, GetMaskBySize(dstOperand.size));
				auto line = new PrimaryTree::Line(dstExpr, srcExpr);
				m_block->getLines().push_back(line);
			}
			else {
				setExprToRegisterDst(dstOperand.reg.value, srcExpr, isSettingFlags);
			}
		}

		void setExprToRegisterDst(ZydisRegister dstReg, ExprTree::Node* srcExpr, bool isSettingFlags = true) {
			auto regInfo = Register::GetRegInfo(dstReg);
			if (m_ctx->m_registers.find(dstReg) != m_ctx->m_registers.end()) {
				m_ctx->m_registers[dstReg]->removeBy(nullptr);
			}
			m_ctx->m_registers[dstReg] = srcExpr;
			if (isSettingFlags)
				setFlags(srcExpr, regInfo.m_mask);

			//if these are ah, bh, ch, dh registers
			int leftBitShift = Register::GetShiftValueOfMask(regInfo.m_mask);

			for (auto sameReg : regInfo.m_sameRegisters) {
				if (sameReg.first == dstReg)
					continue;
				auto it = m_ctx->m_registers.find(sameReg.first);
				if (it != m_ctx->m_registers.end()) {
					if (regInfo.m_mask <= sameReg.second) {
						auto srcExprShl = srcExpr;
						//if (srcExprShl->isSigned()) {
						srcExprShl = new ExprTree::OperationalNode(srcExprShl, new ExprTree::NumberLeaf(regInfo.m_mask), ExprTree::And);
						if (leftBitShift != 0) {
							srcExprShl = new ExprTree::OperationalNode(srcExprShl, new ExprTree::NumberLeaf(leftBitShift), ExprTree::Shl);
						}

						auto maskNumber = new ExprTree::NumberLeaf(~(sameReg.second & regInfo.m_mask));
						auto maskMultipleOperation = new ExprTree::OperationalNode(it->second, maskNumber, ExprTree::And);
						it->second = new ExprTree::OperationalNode(maskMultipleOperation, srcExprShl, ExprTree::Or);
					}
					else {
						m_ctx->m_registers.erase(it);
					}
				}
			}
		}

		void setFlags(ExprTree::Node* expr, uint64_t mask = -1) {
			auto maskedExpr = expr;
			if (mask != -1) {
				maskedExpr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(mask), ExprTree::And);
			}
			m_ctx->m_flags[ZYDIS_CPUFLAG_ZF] = new ExprTree::Condition(maskedExpr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Eq);
			m_ctx->m_flags[ZYDIS_CPUFLAG_SF] = new ExprTree::Condition(maskedExpr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Lt);

			auto bitsAmountExpr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(0x8), ExprTree::getBits);
			auto evenOfBitsAmountExpr = new ExprTree::OperationalNode(bitsAmountExpr, new ExprTree::NumberLeaf(2), ExprTree::Mod);
			m_ctx->m_flags[ZYDIS_CPUFLAG_PF] = new ExprTree::Condition(evenOfBitsAmountExpr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Eq);
			//flags CF and OF...
			m_ctx->clearLastCond();
		}
	};

	class CondJmpInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		CondJmpInstructionInterpreter(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			auto cond = ExprTree::Condition::None;
			if (m_ctx->m_lastCond.flags != RegisterFlags::None) {
				switch (m_instruction->mnemonic)
				{
				case ZYDIS_MNEMONIC_JZ:
					cond = ExprTree::Condition::Eq;
					break;
				case ZYDIS_MNEMONIC_JNZ:
					cond = ExprTree::Condition::Ne;
					break;
				case ZYDIS_MNEMONIC_JL:
					cond = ExprTree::Condition::Lt;
					break;
				case ZYDIS_MNEMONIC_JLE:
					cond = ExprTree::Condition::Le;
					break;
				case ZYDIS_MNEMONIC_JNLE:
					cond = ExprTree::Condition::Gt;
					break;
				case ZYDIS_MNEMONIC_JNL:
					cond = ExprTree::Condition::Ge;
					break;
				}
			}

			if (cond != ExprTree::Condition::None)
			{
				m_block->m_jmpCond = new ExprTree::Condition(m_ctx->m_lastCond.leftNode, m_ctx->m_lastCond.rightNode, cond);
			}
			else {
				//сделать movsnz и тернарный оператор
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
				bool isSettingFlag = false;
				binOperation(ExprTree::None, isSigned, isSettingFlag);
				break;
			}

			//https://www.jaist.ac.jp/iscenter-new/mpc/altix/altixdata/opt/intel/vtune/doc/users_guide/mergedProjects/analyzer_ec/mergedProjects/reference_olh/mergedProjects/instructions/instruct32_hh/vc35.htm
			case ZYDIS_MNEMONIC_CMOVZ:
			case ZYDIS_MNEMONIC_CMOVNZ:
			case ZYDIS_MNEMONIC_CMOVL:
			case ZYDIS_MNEMONIC_CMOVLE:
			case ZYDIS_MNEMONIC_CMOVNL:
			case ZYDIS_MNEMONIC_CMOVNLE:
			{
				auto cond = ExprTree::Condition::None;
				if (m_ctx->m_lastCond.flags != RegisterFlags::None) {
					switch (m_instruction->mnemonic)
					{
					case ZYDIS_MNEMONIC_CMOVZ:
						cond = ExprTree::Condition::Eq;
						break;
					case ZYDIS_MNEMONIC_CMOVNZ:
						cond = ExprTree::Condition::Ne;
						break;
					case ZYDIS_MNEMONIC_CMOVL:
						cond = ExprTree::Condition::Lt;
						break;
					case ZYDIS_MNEMONIC_CMOVLE:
						cond = ExprTree::Condition::Le;
						break;
					case ZYDIS_MNEMONIC_CMOVNL:
						cond = ExprTree::Condition::Gt;
						break;
					case ZYDIS_MNEMONIC_CMOVNLE:
						cond = ExprTree::Condition::Ge;
						break;
					}
				}

				if (cond != ExprTree::Condition::None)
				{
					Operand op1(m_ctx, &m_instruction->operands[0]);
					Operand op2(m_ctx, &m_instruction->operands[1]);
					auto dstExpr = op1.getExpr();
					auto srcExpr = op2.getExpr();
					auto condExpr = new ExprTree::CompositeCondition(new ExprTree::Condition(m_ctx->m_lastCond.leftNode, m_ctx->m_lastCond.rightNode, cond));
					auto ternaryCondExpr = new ExprTree::TernaryOperationalNode(condExpr, srcExpr, dstExpr);
					setExprToRegisterDst(m_instruction->operands[0].reg.value, ternaryCondExpr);
				}
				else {
					
				}

				break;
			}
			}
		}
	};

	class LogicInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		LogicInstructionInterpreter(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_AND:
				binOperation(ExprTree::And);
				break;
			case ZYDIS_MNEMONIC_OR:
				binOperation(ExprTree::Or);
				break;
			case ZYDIS_MNEMONIC_XOR:
				binOperation(ExprTree::Xor);
				break;
			case ZYDIS_MNEMONIC_SHR:
				binOperation(ExprTree::Shr);
				break;
			case ZYDIS_MNEMONIC_SHL:
				binOperation(ExprTree::Shl);
				break;
			case ZYDIS_MNEMONIC_NOT:
				unaryOperation(ExprTree::Xor, new ExprTree::NumberLeaf(-1));
				break;

			case ZYDIS_MNEMONIC_TEST: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);
				auto dstExpr = op1.getExpr();
				auto srcExpr = op2.getExpr();
				auto expr = new ExprTree::OperationalNode(dstExpr, srcExpr, ExprTree::And);
				setFlags(srcExpr, GetMaskBySize(m_instruction->operands[0].size));

				if (m_instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					if (m_instruction->operands[0].reg.value == m_instruction->operands[1].reg.value) {
						m_ctx->setLastCond(dstExpr, new ExprTree::NumberLeaf(0), RegisterFlags::TEST);
					}
				}
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
			/*case ZYDIS_MNEMONIC_MOD:
				binOperation(ExprTree::Mod);
				break;*/
			case ZYDIS_MNEMONIC_INC:
				unaryOperation(ExprTree::Add, new ExprTree::NumberLeaf(1));
				break;
			case ZYDIS_MNEMONIC_DEC:
				unaryOperation(ExprTree::Sub, new ExprTree::NumberLeaf(1));
				break;
			case ZYDIS_MNEMONIC_NEG:
				unaryOperation(ExprTree::Mul, new ExprTree::NumberLeaf(-1));
				break;


			case ZYDIS_MNEMONIC_CMP: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);
				auto dstExpr = op1.getExpr();
				auto srcExpr = op2.getExpr();
				auto expr = new ExprTree::OperationalNode(dstExpr, srcExpr, ExprTree::Sub);
				setFlags(srcExpr, GetMaskBySize(m_instruction->operands[0].size));
				m_ctx->setLastCond(dstExpr, srcExpr, RegisterFlags::CMP);
				break;
			}
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