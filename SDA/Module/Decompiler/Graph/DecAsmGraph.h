#pragma once
#include "../PCode/DecPCode.h"

namespace CE::Decompiler
{
	class AsmGraph;
	class AsmGraphBlock
	{
	public:
		int ID = 0;
		int m_level = 0;
		std::list<AsmGraphBlock*> m_blocksReferencedTo;

		AsmGraphBlock(AsmGraph* asmGraph, int64_t minOffset, int64_t maxOffset)
			: m_asmGraph(asmGraph), m_minOffset(minOffset), m_maxOffset(maxOffset), ID((int)(minOffset >> 8))
		{}

		std::list<PCode::Instruction*>& getInstructions() {
			return m_instructions;
		}

		int64_t getMinOffset() {
			return m_minOffset;
		}

		int64_t getMaxOffset() {
			return m_maxOffset;
		}

		void setNextNearBlock(AsmGraphBlock* nextBlock) {
			m_nextNearBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		void setNextFarBlock(AsmGraphBlock* nextBlock) {
			m_nextFarBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		AsmGraphBlock* getNextNearBlock() {
			return m_nextNearBlock;
		}

		AsmGraphBlock* getNextFarBlock() {
			return m_nextFarBlock;
		}

		PCode::Instruction* getLastInstruction() {
			return *std::prev(m_instructions.end());
		}

		void printDebug(void* addr, const std::string& tabStr, bool extraInfo, bool pcode) {
			ZydisFormatter formatter;
			ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

			ZyanU64 runtime_address = (ZyanU64)addr;
			for (auto instr : m_instructions) {
				std::string prefix = tabStr + "0x" + Generic::String::NumberToHex(runtime_address + instr->getOriginalInstructionOffset());
				if (!instr->m_originalView.empty())
					printf("%s %s\n", prefix.c_str(), instr->m_originalView.c_str());
				if (pcode) {
					prefix += ":" + std::to_string(instr->getOrderId()) + "(" + Generic::String::NumberToHex(instr->getOffset()).c_str() + ")";
					printf("\t%s %s", prefix.c_str(), instr->printDebug().c_str());
					if(instr->m_id == PCode::InstructionId::UNKNOWN)
						printf(" <------------------------------------------------ ");
					printf("\n");
				}
			}

			if (extraInfo) {
				printf("Level: %i\n", m_level);
				if (m_nextNearBlock != nullptr)
					printf("Next near: %s\n", Generic::String::NumberToHex(m_nextNearBlock->getMinOffset()).c_str());
				if (m_nextFarBlock != nullptr)
					printf("Next far: %s\n", Generic::String::NumberToHex(m_nextFarBlock->getMinOffset()).c_str());
			}
		}
	private:
		AsmGraph* m_asmGraph;
		int64_t m_minOffset;
		int64_t m_maxOffset;
		std::list<PCode::Instruction*> m_instructions;
		AsmGraphBlock* m_nextNearBlock = nullptr;
		AsmGraphBlock* m_nextFarBlock = nullptr;
	};

	// asm graph contains asm blocks with pCode instructions
	class AsmGraph
	{
		friend class AsmGraphBlock;
		std::list<PCode::Instruction*> m_instructions;
		std::map<int64_t, AsmGraphBlock> m_offsetToAsmBlock;
		std::map<PCode::Instruction*, PCode::DataValue> m_constValues;
		//regions which contains PCode::InstructionId::NONE (by instructions of this type you can define empty address space where there're not instructions)
		std::map<int64_t, int> m_emptyRegions;
	public:
		AsmGraph(std::list<PCode::Instruction*> instructions, std::map<PCode::Instruction*, PCode::DataValue> constValues)
			: m_instructions(instructions), m_constValues(constValues)
		{
			createEmptyRegionsAndRemoveNoneInstructions();
		}

		void build() {
			enum Direction {
				None	= 0,
				In		= 1, // from some instruction into the current instruction
				Out		= 2, // from the current instruction into some instruction
			};
			std::map<int64_t, Direction> split_offsets; // list of labels (in/out) which split the list of instructions into asm blocks
			std::list<std::pair<int64_t, int64_t>> jumps_offsets; // list of jumps which contains start offset(from) and end offset(to)

			// 1) Find all jumps and set labels (in/out) for creating asm blocks
			for (auto instr : m_instructions) {
				if (PCode::Instruction::IsBranching(instr->m_id)) {
					int64_t targetOffset;
					if (auto varnodeConst = dynamic_cast<PCode::ConstantVarnode*>(instr->m_input0)) {
						// if this input contains hardcoded constant
						targetOffset = varnodeConst->m_value;
					}
					else {
						// if this input could be constantly calculated by pcode virtual machine
						auto it = m_constValues.find(instr);
						if (it == m_constValues.end())
							continue;
						targetOffset = it->second << 8;
					}

					if (!doesOffsetBelongToEmptyRegion(targetOffset)) {
						auto offset = instr->getOffset();
						for (auto pair : { std::pair(offset, Direction::Out), std::pair(targetOffset, Direction::In) } ) {
							auto dir = Direction::None;
							auto it = split_offsets.find(pair.first);
							if (it != split_offsets.end()) {
								dir = it->second;
								split_offsets.erase(it);
							}
							split_offsets.insert(std::make_pair(pair.first, Direction(dir | pair.second)));
						}

						jumps_offsets.push_back(std::make_pair(offset, targetOffset));
					}
				}
				
			}

			// 2) Create asm blocks using found jumps and labels
			int64_t offset = 0;
			for (const auto& it : split_offsets) {
				auto minOffset = offset;
				auto maxOffset = it.first;
				auto dirs = it.second;
				
				// IN: dont grab the last instruction on maxOffset ( [minOffset, maxOffset) interval )
				if (dirs & Direction::In) {
					if (minOffset < maxOffset) {
						createBlockAtOffset(minOffset, maxOffset);
						offset = maxOffset;
					}
				}

				// OUT: need grabbing the last instruction on maxOffset ( [minOffset, maxOffset + 1) interval )
				if (dirs & Direction::Out) {
					int64_t nextInstrOffset;
					// need to get the NEXT instruction following the one on maxOffset
					auto instrIt = std::next(getInstructionByOffset(maxOffset));
					if (instrIt != m_instructions.end())
						nextInstrOffset = (*instrIt)->getOffset();
					else nextInstrOffset = getMaxOffset();

					createBlockAtOffset(offset, nextInstrOffset);
					offset = nextInstrOffset;
				}
			}
			if (offset < getMaxOffset()) {
				// create last remaining asm block
				createBlockAtOffset(offset, getMaxOffset());
			}

			// 3) Just associate blocks one with another
			for (auto it = m_offsetToAsmBlock.begin(); it != std::prev(m_offsetToAsmBlock.end()); it++) {
				auto& curBlock = *it;
				auto& nextBlock = *std::next(it);
				auto lastInstrId = curBlock.second.getLastInstruction()->m_id;
				if (lastInstrId != PCode::InstructionId::BRANCHIND && lastInstrId != PCode::InstructionId::BRANCH && lastInstrId != PCode::InstructionId::RETURN) {
					//in the case of condition jump (e.g. CBRANCH) we make reference to the next block
					curBlock.second.setNextNearBlock(&nextBlock.second);
				}
			}
			for (const auto& jmp_dir : jumps_offsets) { // the current block just associated with the next block
				auto curBlock = getBlockAtOffset(jmp_dir.first);
				auto nextFarBlock = getBlockAtOffset(jmp_dir.second);
				//in any case (including CBRANCH) we make reference to the far block that defined in the parameter of the jmp instruction
				curBlock->setNextFarBlock(nextFarBlock);
			}

			// 4) Calculate levels for asm blocks (level = max path length from the root to the block)
			std::list<AsmGraphBlock*> path;
			CalculateLevelsForAsmGrapBlocks(getStartBlock(), path);
		}

		std::map<int64_t, AsmGraphBlock>& getBlocks() {
			return m_offsetToAsmBlock;
		}

		AsmGraphBlock* getBlockAtOffset(int64_t offset) {
			auto it = std::prev(m_offsetToAsmBlock.upper_bound(offset));
			if (it != m_offsetToAsmBlock.end()) {
				if (offset >= it->second.getMinOffset() && offset < it->second.getMaxOffset()) {
					return &it->second;
				}
			}
			return nullptr;
		}

		AsmGraphBlock* getStartBlock() {
			return &(m_offsetToAsmBlock.begin()->second);
		}

		std::map<PCode::Instruction*, PCode::DataValue>& getConstValues() {
			return m_constValues;
		}

		void printDebug(void* addr) {
			for (auto block : m_offsetToAsmBlock) {
				block.second.printDebug(addr, "", true, true);
				puts("==================");
			}
		}
	private:
		void createEmptyRegionsAndRemoveNoneInstructions() {
			for (auto it = m_instructions.begin(); it != m_instructions.end(); it ++) {
				auto instr = *it;
				if (instr->m_id == PCode::InstructionId::NONE) {
					m_emptyRegions[instr->getOriginalInstructionOffset()] = instr->getOriginalInstructionLength(); // original offset used!
					m_instructions.erase(it);
				}
			}
		}

		// check if the offset is within some empty memory region (offset => origOffset!)
		bool doesOffsetBelongToEmptyRegion(int64_t offset) {
			if (offset < 0 || offset >= getMaxOffset())
				return true;
			auto origOffset = offset >> 8;
			auto it = std::prev(m_emptyRegions.upper_bound(origOffset));
			if (it != m_emptyRegions.end())
				return origOffset < it->first + it->second;
			return false;
		}

		std::list<PCode::Instruction*>::iterator getInstructionByOffset(int64_t offset) {
			for (auto it = m_instructions.begin(); it != m_instructions.end(); it ++) {
				if ((*it)->getOffset() == offset) //todo: binary search
					return it;
			}
			return m_instructions.end();
		}

		// create asm graph block for asm graph (half-interval [minOffset, maxOffset) used!)
		void createBlockAtOffset(int64_t minOffset, int64_t maxOffset) {
			AsmGraphBlock block(this, minOffset, maxOffset);
			for (auto instr : m_instructions) {
				if (instr->getOffset() >= minOffset && instr->getOffset() < maxOffset) {
					block.getInstructions().push_back(instr);
				}
			}
			m_offsetToAsmBlock.insert(std::make_pair(minOffset, block));
		}

		// get offset of the next instruction following the last instruction
		int64_t getMaxOffset() {
			auto lastInstr = *std::prev(m_instructions.end());
			return lastInstr->getFirstInstrOffsetInNextOrigInstr();
		}

		// pass asm graph and calculate max distance from root to each node (asm graph block)
		static void CalculateLevelsForAsmGrapBlocks(AsmGraphBlock* block, std::list<AsmGraphBlock*>& path) {
			if (block == nullptr)
				return;

			//check if there's a loop
			for (auto it = path.rbegin(); it != path.rend(); it++) {
				if (block == *it) {
					return;
				}
			}

			path.push_back(block);
			block->m_level = max(block->m_level, (int)path.size());
			CalculateLevelsForAsmGrapBlocks(block->getNextNearBlock(), path);
			CalculateLevelsForAsmGrapBlocks(block->getNextFarBlock(), path);
			path.pop_back();
		}
	};
};

