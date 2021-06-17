#pragma once
#include "AbstractManager.h"
#include <Decompiler/Graph/DecPCodeGraph.h>

namespace DB {
	class ImagePCodeGraphMapper;
};

namespace CE
{
	class ImagePCodeGraphManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Decompiler::ImagePCodeGraph>;

		ImagePCodeGraphManager(Project* project);

		Decompiler::ImagePCodeGraph* createImagePCodeGraph(bool generateId = true);

		void loadImagePCodeGraphs();

		Decompiler::ImagePCodeGraph* findImagePCodeGraphById(DB::Id id);
	private:
		DB::ImagePCodeGraphMapper* m_imagePCodeGraphMapper;
	};
};