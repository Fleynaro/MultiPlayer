#pragma once
#include "PCode/DecPCode.h"
#include "PCode/Decoders/DecPCodeDecoderX86.h"
#include "PCode/DecPCodeConstValueCalc.h"

namespace CE
{
	class IImage {
	public:
		virtual byte* getData() = 0;
		virtual int getSize() = 0;
		virtual int getOffsetOfEntryPoint() = 0;
	};

	class PEImage : public IImage
	{
		byte* m_data;
		int m_size;
		PIMAGE_NT_HEADERS m_pImgNtHeaders;
		PIMAGE_SECTION_HEADER m_pImgSecHeader;
	public:
		PEImage(byte* data, int size)
			: m_data(data), m_size(size)
		{
			parse();
		}

		byte* getData() override {
			return m_data;
		}

		int getSize() override {
			return m_size;
		}

		int getOffsetOfEntryPoint() override {
			return (int)rvaToOffset(m_pImgNtHeaders->OptionalHeader.AddressOfEntryPoint);
		}

		static void LoadPEImage(const std::string& filename, char** buffer, int* size) {
			//open file
			std::ifstream infile(filename, std::ios::binary);

			//get length of file
			infile.seekg(0, std::ios::end);
			*size = infile.tellg();
			infile.seekg(0, std::ios::beg);

			*buffer = new char[*size];

			//read file
			infile.read(*buffer, *size);
		}

	private:
		void parse() {
			auto& dos_header = *(IMAGE_DOS_HEADER*)m_data;
			auto e_magic = (char*)&dos_header.e_magic;
			if (std::string(e_magic, 2) != "MZ")
				throw std::exception();

			m_pImgNtHeaders = (PIMAGE_NT_HEADERS)(m_data + dos_header.e_lfanew);

			auto signature = (char*)&m_pImgNtHeaders->Signature;
			if (std::string(signature, 2) != "PE")
				throw std::exception();

			m_pImgSecHeader = (PIMAGE_SECTION_HEADER)(m_pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
		}

		DWORD rvaToOffset(DWORD rva)
		{
			size_t i = 0;
			PIMAGE_SECTION_HEADER pSeh;
			if (rva == 0) {
				return (rva);
			}
			pSeh = m_pImgSecHeader;
			for (i = 0; i < m_pImgNtHeaders->FileHeader.NumberOfSections; i++) {
				if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
					pSeh->Misc.VirtualSize) {
					break;
				}
				pSeh++;
			}
			return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
		}
	};
};

namespace CE::Decompiler
{
	class FunctionPCodeGraph;
	class PCodeBlock
	{
		FunctionPCodeGraph* m_asmGraph;
		int64_t m_minOffset;
		int64_t m_maxOffset;
		std::list<PCode::Instruction*> m_instructions;
		PCodeBlock* m_nextNearBlock = nullptr;
		PCodeBlock* m_nextFarBlock = nullptr;
	public:
		int ID = 0;
		int m_level = 0;
		std::list<PCodeBlock*> m_blocksReferencedTo;

		PCodeBlock(FunctionPCodeGraph* asmGraph, int64_t minOffset, int64_t maxOffset)
			: m_asmGraph(asmGraph), m_minOffset(minOffset), m_maxOffset(maxOffset), ID((int)(minOffset >> 8))
		{}

		std::list<PCode::Instruction*>& getInstructions() {
			return m_instructions;
		}

		int64_t getMinOffset() {
			return m_minOffset;
		}

		int64_t getMaxOffset() { // todo: auto-calculated?
			return m_maxOffset;
		}

		void setMaxOffset(int64_t offset) {
			m_maxOffset = offset;
		}

		void setNextNearBlock(PCodeBlock* nextBlock) {
			m_nextNearBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		void setNextFarBlock(PCodeBlock* nextBlock) {
			m_nextFarBlock = nextBlock;
			nextBlock->m_blocksReferencedTo.push_back(this);
		}

		PCodeBlock* getNextNearBlock() {
			return m_nextNearBlock;
		}

		PCodeBlock* getNextFarBlock() {
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
					if (instr->m_id == PCode::InstructionId::UNKNOWN)
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
	};

	class FunctionPCodeGraph
	{
		std::map<int64_t, PCodeBlock> m_offsetToAsmBlock;
	public:
	};

	class ImagePCodeGraph
	{
		std::list<FunctionPCodeGraph*> m_funcGraphList;
		std::map<int64_t, PCodeBlock> m_offsetToBlock;
	public:
		std::map<PCode::Instruction*, DataValue> m_constValues;

		ImagePCodeGraph()
		{}

		FunctionPCodeGraph* createFunctionGraph() {
			auto graph = new FunctionPCodeGraph;
			m_funcGraphList.push_back(graph);
			return graph;
		}

		PCodeBlock* createBlock(FunctionPCodeGraph* graph, int64_t offset) {
			m_offsetToBlock.insert(std::make_pair(offset, PCodeBlock(graph, offset, offset + 1)));
			return &m_offsetToBlock[offset];
		}

		std::list<FunctionPCodeGraph*>& getFunctionGraphList() {
			return m_funcGraphList;
		}

		PCodeBlock* getBlockAtOffset(int64_t offset) {
			auto it = std::prev(m_offsetToBlock.upper_bound(offset));
			if (it != m_offsetToBlock.end()) {
				if (offset >= it->second.getMinOffset() && offset < it->second.getMaxOffset()) {
					return &it->second;
				}
			}
			return nullptr;
		}
	};

	class ImageAnalyzerX86
	{
		friend class PCodeBlock;
		IImage* m_image;
		RegisterFactoryX86 m_registerFactoryX86;
		PCode::DecoderX86 m_decoder;

		ImagePCodeGraph* m_imageGraph = nullptr;
		//FunctionPCodeGraph* m_curFuncGraph = nullptr;
		//PCodeBlock* m_curBlock = nullptr;
	public:
		ImageAnalyzerX86(IImage* image)
			: m_image(image), m_decoder(&m_registerFactoryX86)
		{}

		void start() {
			auto entryPointOffset = m_image->getOffsetOfEntryPoint();
			m_imageGraph = new ImagePCodeGraph;
		}

		void buildGraphAtOffset(int64_t startOffset) {
			auto curFuncGraph = m_imageGraph->createFunctionGraph();
			auto curBlock = m_imageGraph->createBlock(curFuncGraph, startOffset << 8);
			std::list<PCodeBlock*> nextBlocksToVisitLater;

			auto data = m_image->getData();
			auto offset = startOffset;

			while (true) {
				m_decoder.clear();
				if (curBlock != nullptr)
					if (offset < m_image->getSize())
						m_decoder.decode(&data[offset], offset, m_image->getSize());
				if (m_decoder.getInstructionLength() == 0) {
					break;
				}

				for (auto instr : m_decoder.getDecodedPCodeInstructions()) {
					curBlock->getInstructions().push_back(instr);
					auto nextInstrOffset = instr->getOffset() + 1;
					if (instr == *std::prev(m_decoder.getDecodedPCodeInstructions().end()))
						nextInstrOffset = instr->getFirstInstrOffsetInNextOrigInstr();
					curBlock->setMaxOffset(nextInstrOffset);

					if (PCode::Instruction::IsBranching(instr->m_id)) {
						PCode::VirtualMachineContext vmCtx;
						PCode::ConstValueCalculating constValueCalculating(curBlock->getInstructions(), &vmCtx, &m_registerFactoryX86);
						constValueCalculating.start(m_imageGraph->m_constValues);

						int64_t targetOffset;
						if (auto varnodeConst = dynamic_cast<PCode::ConstantVarnode*>(instr->m_input0)) {
							// if this input contains hardcoded constant
							targetOffset = varnodeConst->m_value;
						}
						else {
							// if this input could be constantly calculated by pcode virtual machine
							auto it = m_imageGraph->m_constValues.find(instr);
							if (it == m_imageGraph->m_constValues.end())
								continue;
							targetOffset = it->second << 8;
						}

						auto prevBlock = curBlock;
						auto nextFarBlock = curBlock = nullptr;
						auto targetBlock = m_imageGraph->getBlockAtOffset(targetOffset);
						if (targetBlock != nullptr) {
							// split the existing block into 2 blocks
							if (targetOffset > targetBlock->getMinOffset() && targetOffset < targetBlock->getMaxOffset() - 1) {
								auto block1 = m_imageGraph->createBlock(curFuncGraph, targetOffset);
								auto block2 = targetBlock;
								std::list<PCode::Instruction*> instrOfBlock1;
								std::list<PCode::Instruction*> instrOfBlock2;
								for (auto instr : targetBlock->getInstructions()) {
									if (instr->getOffset() < targetOffset)
										instrOfBlock1.push_back(instr);
									else instrOfBlock2.push_back(instr);
								}
								block1->getInstructions() = instrOfBlock1;
								block2->getInstructions() = instrOfBlock2;
								block1->setMaxOffset(targetOffset);
								block2->setMaxOffset(targetBlock->getMaxOffset());
								block1->setNextNearBlock(block2);
								nextFarBlock = block2;
							}
							prevBlock->setNextFarBlock(targetBlock);
						}
						else {
							nextFarBlock = m_imageGraph->createBlock(curFuncGraph, targetOffset);
							prevBlock->setNextFarBlock(nextFarBlock);
						}
						if (instr->m_id == PCode::InstructionId::CBRANCH) {
							if (m_imageGraph->getBlockAtOffset(nextInstrOffset) == nullptr) {
								auto nextNearBlock = m_imageGraph->createBlock(curFuncGraph, nextInstrOffset);
								prevBlock->setNextNearBlock(nextNearBlock);
								curBlock = nextNearBlock;
								nextBlocksToVisitLater.push_back(nextFarBlock);
							}
							else {
								curBlock = nextFarBlock;
							}
						}
						else {
							curBlock = nextFarBlock;
						}
					}
					else if (instr->m_id == PCode::InstructionId::RETURN) {
						curBlock = nullptr;
						break;
					}
				}
				offset += m_decoder.getInstructionLength();
			}
		}
	};
};