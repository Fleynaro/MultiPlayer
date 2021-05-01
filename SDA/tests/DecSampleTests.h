#pragma once
#include "AbstractTest.h"
#include <Decompiler/Decompiler.h>
#include <Decompiler/LinearView/DecLinearView.h>
#include <Decompiler/LinearView/DecLinearViewOptimization.h>
#include <Decompiler/LinearView/DecLinearViewSimpleOutput.h>
#include <Decompiler/Optimization/DecGraphOptimization.h>
#include <Decompiler/SDA/Symbolization/DecGraphSymbolization.h>
#include <Decompiler/SDA/Optimizaton/SdaGraphFinalOptimization.h>
#include <Decompiler/PCode/Decoders/DecPCodeDecoderX86.h>
#include <Decompiler/PCode/DecPCodeConstValueCalc.h>
#include <Decompiler/PCode/ImageAnalyzer/DecImageAnalyzer.h>
#include <Decompiler/Graph/Analyzer/ImagePCodeGraphAnalyzer.h>
#include <Decompiler/DecMisc.h>
#include <Module/Image/SimpleBufferImage.h>
#include <Module/Image/VectorBufferImage.h>
#include <Manager/Managers.h>
#include <TestCodeToDecompile.h>

using namespace CE::Decompiler;
using namespace CE::Symbol;
using namespace CE::DataType;

class ProgramModuleFixtureDecBase : public ProgramModuleFixture {
public:
	RegisterFactoryX86 m_registerFactoryX86;
	Signature* m_defSignature;
	bool m_isOutput = true;

	ProgramModuleFixtureDecBase() {
		m_defSignature = createDefSig("defSignature");
		createTestDataTypes();
	}

	CE::DataType::Structure* m_vec3D = nullptr;
	CE::DataType::Structure* m_vecExt3D = nullptr;
	CE::DataType::Structure* m_vec4D = nullptr;
	CE::DataType::Structure* m_matrix4x4 = nullptr;
	void createTestDataTypes() {
		m_vec3D = typeManager()->createStructure("testVector3D", "");
		m_vec3D->addField(0x4 * 0, "x", findType("float", ""));
		m_vec3D->addField(0x4 * 1, "y", findType("float", ""));
		m_vec3D->addField(0x4 * 2, "z", findType("float", ""));

		m_vecExt3D = typeManager()->createStructure("testVectorExt3D", "");
		m_vecExt3D->addField(0x8 * 0, "x", findType("float", ""));
		m_vecExt3D->addField(0x8 * 1, "y", findType("float", ""));
		m_vecExt3D->addField(0x8 * 2, "z", findType("float", ""));

		m_vec4D = typeManager()->createStructure("testVector4D", "");
		m_vec4D->addField(0x4 * 0, "x", findType("float", ""));
		m_vec4D->addField(0x4 * 1, "y", findType("float", ""));
		m_vec4D->addField(0x4 * 2, "z", findType("float", ""));
		m_vec4D->addField(0x4 * 3, "w", findType("float", ""));

		m_matrix4x4 = typeManager()->createStructure("testMatrix4x4", "");
		m_matrix4x4->addField(m_vec4D->getSize() * 0, "vec1", GetUnit(m_vec4D));
		m_matrix4x4->addField(m_vec4D->getSize() * 1, "vec2", GetUnit(m_vec4D));
		m_matrix4x4->addField(m_vec4D->getSize() * 2, "vec3", GetUnit(m_vec4D));
		m_matrix4x4->addField(m_vec4D->getSize() * 3, "vec4", GetUnit(m_vec4D));
	}

	CE::TypeManager* typeManager() {
		return m_programModule->getTypeManager();
	}

	CE::SymbolManager* symbolManager() {
		return m_programModule->getSymbolManager();
	}

	CE::DataTypePtr findType(std::string typeName, std::string typeLevel = "") {
		return DataType::GetUnit(typeManager()->getTypeByName(typeName), typeLevel);
	}

	Signature* createDefSig(std::string name) {
		auto defSignature = typeManager()->createSignature(name);
		defSignature->addParameter("param1", findType("uint32_t"));
		defSignature->addParameter("param2", findType("uint32_t"));
		defSignature->addParameter("param3", findType("uint32_t"));
		defSignature->addParameter("param4", findType("uint32_t"));
		defSignature->addParameter("param5", findType("uint32_t"));
		defSignature->setReturnType(findType("uint32_t"));
		return defSignature;
	}

	void showDecGraph(DecompiledCodeGraph* decGraph, bool minInfo = false) {
		LinearViewSimpleOutput output(Misc::BuildBlockList(decGraph), decGraph);
		if (m_isOutput) {
			if(minInfo)
				output.setMinInfoToShow();
			output.show();
			out("******************\n\n\n");
		}
	}

	// print message
	void out(const char* fmt, ...) {
		if (!m_isOutput)
			return;
		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}

	// returns array of bytes on specified address of some function (seeing RET instruction)
	static std::vector<byte> GetFuncBytes(void* addr) {
		auto size = CalculateFuncSize((byte*)addr, 0);
		return std::vector<byte>((byte*)addr, (byte*)addr + size);
	}

	// calculates the function size, seeing RET instruction
	static int CalculateFuncSize(byte* addr, bool endByRet = false) {
		int size = 0;
		while (!(addr[size] == 0xC3 && addr[size + 1] == 0xCC))
			size++;
		return size + 1;
	}
};

class ProgramModuleFixtureDecComponent : public ProgramModuleFixtureDecBase {
public:
	PCode::VirtualMachineContext m_vmCtx;

	ProgramModuleFixtureDecComponent() {

	}

	// decode {bytes} into pcode instructions
	std::list<Instruction*> decode(std::vector<byte> bytes) {
		std::list<Instruction*> decodedInstructions;
		WarningContainer warningContainer;
		PCode::DecoderX86 decoder(&m_registerFactoryX86, &warningContainer);
		int offset = 0;
		while (offset < bytes.size()) {
			decoder.decode(bytes.data() + offset, offset, (int)bytes.size());
			if (decoder.getInstructionLength() == 0)
				break;
			decodedInstructions.insert(decodedInstructions.end(), decoder.getDecodedPCodeInstructions().begin(), decoder.getDecodedPCodeInstructions().end());
			offset += decoder.getInstructionLength();
		}
		return decodedInstructions;
	}

	// show all pcode instructions with original asm instructions
	void showInstructions(const std::list<Instruction*>& instructions) {
		PCodeBlock pcodeBlock(0, 0);
		pcodeBlock.getInstructions() = instructions;
		out(pcodeBlock.printDebug(nullptr, "", false, true).c_str());
	}

	// execute pcode on the virtual machine
	std::map<PCode::Instruction*, DataValue> executeAndCalcConstValue(std::list<Instruction*> decodedInstructions) {
		std::map<PCode::Instruction*, DataValue> constValues;
		PCode::ConstValueCalculating constValueCalculating(decodedInstructions, &m_vmCtx, &m_registerFactoryX86);
		constValueCalculating.start(constValues);
		return constValues;
	}

	// show const values calculated by the virtual machine
	void showConstValues(std::map<PCode::Instruction*, DataValue> constValues) {
		for (auto pair : constValues) {
			printf("%s -> %i", pair.first->printDebug().c_str(), pair.second);
		}
	}

	// need to optimize some expr. to one constant value
	void replaceSymbolWithExpr(INode* node, CE::Decompiler::Symbol::Symbol* symbol, INode* newNode) {
		node->iterateChildNodes([&](INode* childNode) {
			replaceSymbolWithExpr(childNode, symbol, newNode);
			});
		if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
			if (symbolLeaf->m_symbol == symbol) {
				node->replaceWith(newNode);
				delete node;
			}
		}
	}

	// optimize expr.
	void optimize(TopNode* topNode) {
		Optimization::ExprOptimization exprOptimization(topNode);
		exprOptimization.start();
	}
};

class ProgramModuleFixtureDecSamples : public ProgramModuleFixtureDecBase {
public:
	// test unit for some instruction list (asm code) presented as array of bytes
	struct SampleTest
	{
		int m_testId;
		IImage* m_image;
		int m_imageOffset = 0;
		Symbolization::UserSymbolDef m_userSymbolDef;
		std::map<int64_t, Signature*> m_functions;
		bool m_enabled = true;
		bool m_symbolization = true;
		bool m_showAllCode = false;
		bool m_showSymbCode = false;
		bool m_showAsmBefore = false;
		bool m_showFinalResult = false;

		void enableAllAndShowAll() {
			m_enabled = true;
			m_symbolization = true;
			m_showAllCode = true;
			m_showSymbCode = true;
			m_showAsmBefore = true;
			m_showFinalResult = true;
		}
	};

	std::list<SampleTest*> m_sampleTests;
	std::map<int, HS::Value> m_sampleTestHashes;

	//ignore all tests except
	int m_doTestIdOnly = 0;

	ProgramModuleFixtureDecSamples()
	{
		initSampleTestHashes();
		initSampleTest();
	}

	void initSampleTestHashes();

	void initSampleTest();

	bool checkHash(int type, std::list<std::pair<int, HS::Value>>& sampleTestHashes, HS::Value hash, SampleTest* sampleTest);

	SampleTest* createSampleTest(int testId, std::vector<byte> content) {
		return createSampleTest(testId, new VectorBufferImage(content));
	}

	SampleTest* createSampleTest(int testId, IImage* image, int offset = 0) {
		auto test = new SampleTest;
		test->m_testId = testId;
		test->m_image = image;
		test->m_imageOffset = offset;
		test->m_userSymbolDef = Misc::CreateUserSymbolDef(m_programModule);
		test->m_userSymbolDef.m_signature = m_defSignature;
		m_sampleTests.push_back(test);
		return test;
	}
};