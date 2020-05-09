#include "FunctionBodyBuilder.h"
#include <Disassembler/Disassembler.h>
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::CallGraph;

FunctionBodyBuilder::FunctionBodyBuilder(Function::Function* function)
	: m_function(function)
{}

void FunctionBodyBuilder::build()
{
	for (auto& range : m_function->getRangeList()) {
		build(range);
	}
}

Node::FunctionBody* FunctionBodyBuilder::getFunctionBody() {
	return m_function->getBody();
}

void FunctionBodyBuilder::build(Function::AddressRange& range)
{
	using namespace CE::Disassembler;
	using namespace CE::CallGraph::Node;
	auto nodeGroup = getFunctionBody();

	Decoder decoder(range.getMinAddress(), static_cast<int>(range.getSize()));
	decoder.decode([&](Code::Instruction& instruction)
		{
			void* curAddr = (void*)decoder.getCurrentAddress();

			if (instruction.isGeneric()) {
				auto& instr = (Code::Instructions::Generic&)instruction;
				if (instr.getOperandCount() > 0) {
					auto& instr = (Code::Instructions::GenericWithOperands&)instruction;
					if (instr.getOperand(0).isCalculatedAddress()) {
						nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Write, curAddr));
					}
					else if (instr.getOperand(1).isCalculatedAddress()) {
						nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
					}
				}
			}
			else if (instruction.isBasicManipulating()) {
				auto& instr = (Code::Instructions::BasicManipulation&)instruction;
				if (instr.getOperand(0).isCalculatedAddress()) {
					nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Write, curAddr));
				}
				else if (instr.getOperand(1).isCalculatedAddress()) {
					nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
				}
			}
			else if (instruction.isJumping()) {
				auto& instr = (Code::Instructions::JumpInstruction&)instruction;
				if (instr.hasAbsoluteAddr()) {
					auto calledFunc = m_function->getManager()->getFunctionAt(instr.getAbsoluteAddr());

					if (instruction.getMnemonicId() != ZYDIS_MNEMONIC_CALL) {
						if (calledFunc != nullptr) {
							if (calledFunc == m_function) {
								calledFunc = nullptr;
							}
						}
					}
					else {
						if (calledFunc == nullptr) {
							nodeGroup->addNode(new FunctionNode(curAddr));
						}
					}

					if (calledFunc != nullptr) {
						nodeGroup->addNode(new FunctionNode(calledFunc, curAddr));
					}
				}
				else if (instruction.getMnemonicId() == ZYDIS_MNEMONIC_CALL) {
					nodeGroup->addNode(new VMethodNode(curAddr));
				}
			}

			return true;
		});
}
