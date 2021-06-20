#include "ImageDecorator.h"
#include <Manager/AddressSpaceManager.h>
#include <Image/PEImage.h>

CE::ImageDecorator::ImageDecorator(ImageManager* imageManager, AddressSpace* addressSpace, IMAGE_TYPE type, Symbol::SymbolTable* globalSymbolTable, Symbol::SymbolTable* funcBodySymbolTable, const std::string& name, const std::string& comment)
	:
	m_imageManager(imageManager),
	m_addressSpace(addressSpace),
	m_type(type),
	m_globalSymbolTable(globalSymbolTable),
	m_funcBodySymbolTable(funcBodySymbolTable),
	Description(name, comment)
{
	m_instrPool = new Decompiler::InstructionPool();
	m_imagePCodeGraph = new Decompiler::ImagePCodeGraph();
	m_vfunc_calls = new std::map<int64_t, CE::DataType::IFunctionSignature*>();
}

CE::ImageDecorator::ImageDecorator(ImageManager* imageManager, AddressSpace* addressSpace, ImageDecorator* parentImageDec, const std::string& name, const std::string& comment)
	: ImageDecorator(
		imageManager,
		addressSpace,
		parentImageDec->m_type,
		parentImageDec->m_globalSymbolTable,
		parentImageDec->m_funcBodySymbolTable,
		name,
		comment
	)
{
	m_instrPool = parentImageDec->m_instrPool;
	m_imagePCodeGraph = parentImageDec->m_imagePCodeGraph;
	m_vfunc_calls = parentImageDec->m_vfunc_calls;
	m_parentImageDec = parentImageDec;
}

void CE::ImageDecorator::load() {
	char* buffer = nullptr;
	int size;
	Helper::File::LoadFileIntoBuffer(getFile(), &buffer, &size);

	if (m_type == IMAGE_PE) {
		m_image = new PEImage((byte*)buffer, size);
	}
}

const fs::path& CE::ImageDecorator::getFile() {
	return m_addressSpace->getImagesDirectory() / fs::path(getName() + ".bin");
}
