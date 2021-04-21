#include <Program.h>
#include "DecompilerDemoWindow.h"
#include <asmtk/asmtk.h>

using namespace CE;
using namespace asmjit;
using namespace asmtk;

std::string dumpCode(const uint8_t* buf, size_t size) {
    enum { kCharsPerLine = 39 };
    char hex[kCharsPerLine * 2 + 1];

    size_t i = 0;
    std::string result;
    while (i < size) {
        size_t j = 0;
        size_t end = size - i < kCharsPerLine ? size - i : size_t(kCharsPerLine);

        end += i;
        while (i < end) {
            uint8_t b0 = buf[i] >> 4;
            uint8_t b1 = buf[i] & 15;

            hex[j++] = b0 < 10 ? '0' + b0 : 'A' + b0 - 10;
            hex[j++] = b1 < 10 ? '0' + b1 : 'A' + b1 - 10;
            hex[j++] = ' ';
            i++;
        }

        hex[j] = '\0';
        result += hex;
    }

    result.pop_back();
    return result;
}

FS::Directory getCurrentDir() {
    char filename[MAX_PATH];
    GetModuleFileName(NULL, filename, MAX_PATH);
    return FS::File(filename).getDirectory().next("test");
}

void GUI::DecompilerDemoWindow::initProgram() {
    getCurrentDir().createIfNotExists();
    m_programModule = new ProgramModule(getCurrentDir());

    m_programModule->initDataBase("database.db");
    m_programModule->initManagers();
    m_programModule->load();
}

void GUI::DecompilerDemoWindow::deassembly(const std::string& textCode) {
    CodeHolder code;
    code.init(Environment(Environment::kArchX64));

    // Attach x86::Assembler `code`.
    x86::Assembler a(&code);

    // Create AsmParser that will emit to x86::Assembler.
    AsmParser p(&a);

    // Parse some assembly.
    Error err = p.parse(textCode.c_str());

    // Error handling (use asmjit::ErrorHandler for more robust error handling).
    if (err) {
        m_asmParsingErrorText.setDisplay(true);
        m_asmParsingErrorText.setText(std::string("Errors:\n") + DebugUtils::errorAsString(err));
        return;
    }
    m_asmParsingErrorText.setDisplay(false);

    // Now you can print the code, which is stored in the first section (.text).
    CodeBuffer& buffer = code.sectionById(0)->buffer();
    auto hexBytesStr = dumpCode(buffer.data(), buffer.size());
    m_bytes_input.setInputText(hexBytesStr);
}


// decompiler
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
#include <Module/Image/VectorBufferImage.h>
#include <Manager/Managers.h>

void GUI::DecompilerDemoWindow::decompile(const std::string& hexBytesStr)
{
    auto image = VectorBufferImage(content);

}
