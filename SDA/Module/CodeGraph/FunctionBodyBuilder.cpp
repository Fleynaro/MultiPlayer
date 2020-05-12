#include "FunctionBodyBuilder.h"
#include <Disassembler/DisasmDecoder.h>
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::CodeGraph;

FunctionBodyBuilder::FunctionBodyBuilder(Node::FunctionBody* body, AddressRangeList addressRangeList, FunctionManager* funcManager)
	: m_funcBody(body), m_addressRangeList(addressRangeList), m_funcManager(funcManager)
{}

void FunctionBodyBuilder::build()
{
	for (auto& range : m_addressRangeList) {
		build(range);
	}
}

void FunctionBodyBuilder::build(AddressRange& range)
{
	using namespace CE::Disassembler;
	using namespace CE::CodeGraph::Node;
	auto nodeGroup = m_funcBody;

	Decoder decoder(range.getMinAddress(), static_cast<int>(range.getSize()));
	decoder.decode([&](Code::Instruction* instruction)
		{
			void* curAddr = (void*)decoder.getCurrentAddress();

			if (auto instr = dynamic_cast<Code::Instructions::Generic*>(instruction))
			{
				if (auto instr = dynamic_cast<Code::Instructions::GenericWithOperands*>(instruction))
				{
					if (instr->getOperand(0).isCalculatedAddress()) {
						nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Write, curAddr));
					}
					else if (instr->getOperand(1).isCalculatedAddress()) {
						nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
					}
				}
			}
			else if (auto instr = dynamic_cast<Code::Instructions::BasicManipulation*>(instruction))
			{
				if (instr->getOperand(0).isCalculatedAddress()) {
					nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Write, curAddr));
				}
				else if (instr->getOperand(1).isCalculatedAddress()) {
					nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
				}
			}
			else if (auto instr = dynamic_cast<Code::Instructions::JumpInstruction*>(instruction))
			{
				if (instr->hasAbsoluteAddr()) {
					auto calledFunc = m_funcManager->getFunctionAt(instr->getAbsoluteAddr());

					if (instruction->getMnemonicId() != ZYDIS_MNEMONIC_CALL) {
						//if it is the same function within the function address range
						if (calledFunc != nullptr && calledFunc->isContainingAddress(curAddr)) {
							calledFunc = nullptr;
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
				else if (instruction->getMnemonicId() == ZYDIS_MNEMONIC_CALL) {
					//if it has not an absoulte address then marked as virtual call
					nodeGroup->addNode(new VMethodNode(curAddr));
				}
			}

			return true;
		});
}
