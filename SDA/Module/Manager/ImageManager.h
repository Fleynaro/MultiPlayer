#pragma once
#include "AbstractManager.h"
#include <Image/ImageDecorator.h>

namespace DB {
	class ImageMapper;
};

namespace CE
{
	class ImageManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<ImageDecorator>;

		ImageManager(Project* project);

		ImageDecorator* createImage(AddressSpace* addressSpace, ImageDecorator::IMAGE_TYPE type, Symbol::SymbolTable* globalSymbolTable, Symbol::SymbolTable* vfuncCallSymbolTable, const std::string& name, const std::string& comment = "", bool generateId = true);

		void loadImages();

		ImageDecorator* findImageById(DB::Id id);

		ImageDecorator* findImageByName(const std::string& name);
	private:
		DB::ImageMapper* m_imageMapper;
	};
};