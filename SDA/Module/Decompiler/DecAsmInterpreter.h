#pragma once
#include "DecAsmGraph.h"

namespace CE::Decompiler
{
	namespace Symbol
	{
		class Symbol
		{
			
		};

		class GlobalObject : public Symbol
		{
		public:
			int m_offset;

			GlobalObject(int offset)
				: m_offset(offset)
			{}
		};

		class LocalStackTop : public Symbol
		{
		public:
			LocalStackTop()
			{}
		};

		class LocalStackVar : public Symbol
		{
		public:
			int m_stackOffset;

			LocalStackVar(int stackOffset)
				: m_stackOffset(stackOffset)
			{}
		};

		class LocalRegVar : public Symbol
		{
		public:
			ZydisRegister m_register;

			LocalRegVar(ZydisRegister reg)
				: m_register(reg)
			{}
		};

		class Parameter : public Symbol
		{
		public:
			int m_idx = 0;
			Parameter(int idx)
				: m_idx(idx)
			{}
		};
	};

	namespace ExprTree
	{
		class Node
		{
		public:
			Node* m_parentNode;

			Node(Node* parentNode)
				: m_parentNode(parentNode)
			{}

			virtual bool isLeaf() = 0;
		};

		enum OperationType
		{
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

		class OperationalNode : public Node
		{
		public:
			Node* m_leftNode;
			Node* m_rightNode;
			OperationType m_operation;

			OperationalNode(Node* parentNode, Node* leftNode, Node* rightNode, OperationType operation)
				: Node(parentNode), m_leftNode(leftNode), m_rightNode(rightNode), m_operation(operation)
			{}

			bool isLeaf() override {
				return false;
			}
		};

		class SymbolLeaf : public Node
		{
		public:
			Symbol::Symbol* m_symbol;

			SymbolLeaf(Node* parentNode, Symbol::Symbol* symbol)
				: Node(parentNode), m_symbol(symbol)
			{}

			bool isLeaf() override {
				return true;
			}
		};

		class NumberLeaf : public Node
		{
		public:
			uint64_t m_value;

			NumberLeaf(Node* parentNode, uint64_t value)
				: Node(parentNode), m_value(value)
			{}

			bool isLeaf() override {
				return true;
			}
		};
	};

	/*struct Symbol {
		enum LocationType : byte {
			Global,
			Stack,
			Register
		};

		LocationType m_locationType;

		union {
			ZydisRegister m_register;
			int m_globalOffset;
			int m_stackOffset;
		};
	};

	struct Expression {
		struct Node {
			enum NodeType : byte {
				Expression,
				Symbol,
				Number
			};

			union {
				int m_expressionId;
				int m_symbolId;
				uint64_t m_value;
			};
		};

		Node m_leftNode;
		Node m_rightNode;
	};
	
	class ExecutionContext
	{
	public:
		ExecutionContext(int startOffset = 0)
			: m_offset(startOffset)
		{}

	private:
		int m_offset;
		std::vector<Symbol> m_symbols;
		std::vector<Expression> m_expressions;
		std::map<std::string, int> m_memory;
	};
	*/

	namespace PrimaryTree
	{
		class Block
		{
		public:
			Block()

			{}


		private:
			
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

	namespace Registers
	{
		enum Register {
			ZYDIS_REGISTER_RAX,
			ZYDIS_REGISTER_RCX,
			ZYDIS_REGISTER_RDX,
			ZYDIS_REGISTER_RBX,
			ZYDIS_REGISTER_RSP,
			ZYDIS_REGISTER_RBP,
			ZYDIS_REGISTER_RSI,
			ZYDIS_REGISTER_RDI,
			ZYDIS_REGISTER_R8,
			ZYDIS_REGISTER_R9,
			ZYDIS_REGISTER_R10,
			ZYDIS_REGISTER_R11,
			ZYDIS_REGISTER_R12,
			ZYDIS_REGISTER_R13,
			ZYDIS_REGISTER_R14,
			ZYDIS_REGISTER_R15,
		};

		std::map<ZydisRegister, std::string>  = {

		};
	};

	class AbstractInstructionInterpreter
	{
	public:
		AbstractInstructionInterpreter(ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: m_ctx(ctx), m_instruction(instruction)
		{}

		virtual void execute() = 0;

	protected:
		ExecutionContext* m_ctx;
		const ZydisDecodedInstruction* m_instruction;

		static std::string getRegisterAddress(ZydisRegister reg) {
			return "reg:" + std::to_string(reg);
		}

		ExprTree::Node* createExprNumLeaf(uint64_t value) {
			auto leaf = new ExprTree::NumberLeaf(nullptr, value);
			m_ctx->m_expressionManager->getExprNodes().push_back(leaf);
			return leaf;
		}

		ExprTree::Node* createExprRegLeaf(ZydisRegister reg) {
			auto symbol = new Symbol::LocalRegVar(reg);
			auto leaf = new ExprTree::SymbolLeaf(nullptr, symbol);
			//параметр ли
			m_ctx->m_expressionManager->getSymbols().push_back(symbol);
			m_ctx->m_expressionManager->getExprNodes().push_back(leaf);
			return leaf;
		}

		ExprTree::Node* getExprRegLeaf(ZydisRegister reg) {
			auto addr = getRegisterAddress(reg);
			if (m_ctx->m_memory.find(addr) != m_ctx->m_memory.end()) {
				return m_ctx->m_memory[addr];
			}
			return createExprRegLeaf(reg);
		}

		ExprTree::Node* getOperand(int idx) {
			auto& operand = m_instruction->operands[idx];
			if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				return getExprRegLeaf(operand.reg.value);
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				return createExprNumLeaf(operand.imm.value.u);
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {

			}
		}

	private:

	};

	class MovementInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		MovementInstructionInterpreter(ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_MOV:
				if (m_instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

				}
				break;
			}
		}
	};

	class ArithmeticInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		ArithmeticInstructionInterpreter(ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(ctx, instruction)
		{}

		void execute() override {
			
		}
	};

	class InstructionDispatcher
	{
	public:
		void execute(ExecutionContext* ctx, const ZydisDecodedInstruction& instruction) {
			switch (instruction.mnemonic)
			{
			case ZYDIS_MNEMONIC_MOV:
				MovementInstructionInterpreter interpreter(ctx, &instruction);
				interpreter.execute();
				break;

			case ZYDIS_MNEMONIC_ADD:
			case ZYDIS_MNEMONIC_SUB:
			case ZYDIS_MNEMONIC_MUL:
			case ZYDIS_MNEMONIC_DIV:
				
				break;
			}
		}
	};

	class Interpreter
	{
	public:
		Interpreter(int startOffset = 0)
		{}

		void execute(ExecutionContext* ctx, const ZydisDecodedInstruction& instruction) {
			m_dispatcher.execute(ctx, instruction);
		}

	private:
		InstructionDispatcher m_dispatcher;
	};
};