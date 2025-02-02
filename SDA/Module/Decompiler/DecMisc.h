#pragma once
#include <Decompiler/Decompiler.h>
#include <Decompiler/LinearView/DecLinearView.h>
#include <Decompiler/LinearView/DecLinearViewOptimization.h>
#include <Decompiler/LinearView/DecLinearViewSimpleOutput.h>
#include <Decompiler/SDA/Symbolization/DecGraphSymbolization.h>
#include <Decompiler/SDA/Optimizaton/SdaGraphFinalOptimization.h>
#include <Decompiler/PCode/Decoders/DecPCodeDecoderX86.h>
#include <Decompiler/PCode/DecPCodeConstValueCalc.h>
#include <Decompiler/PCode/ImageAnalyzer/DecImageAnalyzer.h>

using namespace CE::Decompiler;
using namespace CE::Symbol;
using namespace CE::DataType;

namespace CE::Decompiler::Misc
{
    // show all symbols
    static std::string ShowAllSymbols(SdaCodeGraph* sdaCodeGraph) {
        std::string result;
        sdaCodeGraph->getSdaSymbols().sort([](CE::Symbol::ISymbol* a, CE::Symbol::ISymbol* b) {
            return a->getName() < b->getName();
            });

        for (auto var : sdaCodeGraph->getSdaSymbols()) {
            std::string comment = "//priority: " + std::to_string(var->getDataType()->getPriority());
            //size
            if (var->getDataType()->isArray())
                comment += ", size: " + std::to_string(var->getDataType()->getSize());
            //offsets
            if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(var)) {
                if (!autoSdaSymbol->getInstrOffsets().empty()) {
                    comment += ", offsets: ";
                    for (auto off : autoSdaSymbol->getInstrOffsets()) {
                        comment += std::to_string(off) + ", ";
                    }
                    comment.pop_back();
                    comment.pop_back();
                }
            }
            result += var->getDataType()->getDisplayName() + " " + var->getName() + "; " + comment + "\n";
        }
        result += "\n";
        return result;
    }

    static LinearView::BlockList* BuildBlockList(DecompiledCodeGraph* graph) {
        auto converter = LinearView::Converter(graph);
        converter.start();
        auto blockList = converter.getBlockList();
        OptimizeBlockList(blockList);
        return blockList;
    }

    static Symbolization::UserSymbolDef CreateUserSymbolDef(ProgramModule* programModule) {
        auto userSymbolDef = Symbolization::UserSymbolDef(programModule);
        userSymbolDef.m_globalSymbolTable = programModule->getGlobalMemoryArea();
        userSymbolDef.m_stackSymbolTable = new CE::Symbol::SymbolTable(programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::STACK_SPACE, 100000);
        userSymbolDef.m_funcBodySymbolTable = new CE::Symbol::SymbolTable(programModule->getMemoryAreaManager(), CE::Symbol::SymbolTable::GLOBAL_SPACE, 100000);
        return userSymbolDef;
    }
};