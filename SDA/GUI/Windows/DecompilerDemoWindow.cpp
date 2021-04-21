#include "DecompilerDemoWindow.h"
#include <asmtk/asmtk.h>

using namespace asmjit;
using namespace asmtk;

static std::string dumpCode(const uint8_t* buf, size_t size) {
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

void GUI::DecompilerDemoWindow::deassembly() {
    CodeHolder code;
    code.init(Environment(Environment::kArchX64));

    auto textCode = m_asmCodeEditor->getEditor().GetText();

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
