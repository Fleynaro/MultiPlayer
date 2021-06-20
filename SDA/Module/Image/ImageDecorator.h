#pragma once
#include <Image/IImage.h>
#include <DB/DomainObject.h>
#include <Utils/Description.h>
#include <Decompiler/PCode/DecPCodeInstructionPool.h>
#include <Decompiler/Graph/DecPCodeGraph.h>
#include <Code/Type/FunctionSignature.h>

namespace CE
{
	class AddressSpace;
	class ImageManager;

	// it is a symbolized image that decorates a raw image and can manipulate with high-level things (symbols)
	class ImageDecorator : public DB::DomainObject, public Description, public IImage
	{
	public:
		enum IMAGE_TYPE {
			IMAGE_PE
		};

	private:
		ImageManager* m_imageManager;
		AddressSpace* m_addressSpace;
		IImage* m_image = nullptr;
		IMAGE_TYPE m_type;
		Symbol::SymbolTable* m_globalSymbolTable;
		Symbol::SymbolTable* m_funcBodySymbolTable;
		Decompiler::InstructionPool* m_instrPool;
		Decompiler::ImagePCodeGraph* m_imagePCodeGraph;
		std::map<int64_t, CE::DataType::IFunctionSignature*>* m_vfunc_calls;
		// need for making a clone that based on its parent image but haved own raw-image
		ImageDecorator* m_parentImageDec = nullptr;
		
	public:
		ImageDecorator(
			ImageManager* imageManager,
			AddressSpace* addressSpace,
			IMAGE_TYPE type,
			Symbol::SymbolTable* globalSymbolTable,
			Symbol::SymbolTable* funcBodySymbolTable,
			const std::string& name,
			const std::string& comment = "");

		ImageDecorator(ImageManager* imageManager, AddressSpace* addressSpace, ImageDecorator* parentImageDec, const std::string& name, const std::string& comment = "");

		~ImageDecorator() {
			if (m_image) {
				delete m_image->getData();
				delete m_image;
			}

			if (!m_parentImageDec) {
				delete m_instrPool;
				delete m_imagePCodeGraph;
				delete m_vfunc_calls;
			}
		}

		void load();

		void save() {
			Helper::File::SaveBufferIntoFile((char*)m_image->getData(), m_image->getSize(), getFile());
		}

		ImageManager* getImageManager() {
			return m_imageManager;
		}

		AddressSpace* getAddressSpace() {
			return m_addressSpace;
		}

		IMAGE_TYPE getType() {
			return m_type;
		}

		Symbol::SymbolTable* getGlobalSymbolTable() {
			return m_globalSymbolTable;
		}

		Symbol::SymbolTable* getFuncBodySymbolTable() {
			return m_funcBodySymbolTable;
		}

		Decompiler::InstructionPool* getInstrPool() {
			return m_instrPool;
		}

		Decompiler::ImagePCodeGraph* getPCodeGraph() {
			return m_imagePCodeGraph;
		}

		auto& getVirtFuncCalls() {
			return *m_vfunc_calls;
		}

		ImageDecorator* getParentImage() {
			return m_parentImageDec;
		}

		const fs::path& getFile();

		byte* getData() override {
			return m_image->getData();
		}

		int getSize() override {
			return m_image->getSize();
		}

		int getOffsetOfEntryPoint() override {
			return m_image->getOffsetOfEntryPoint();
		}

		SegmentType defineSegment(int offset) override {
			return m_image->defineSegment(offset);
		}

		int toImageOffset(int offset) override {
			return m_image->toImageOffset(offset);
		}

		int addrToImageOffset(uint64_t addr) override {
			return m_image->addrToImageOffset(addr);
		}

		std::uintptr_t getAddress() override {
			return m_image->getAddress();
		}
	};
};