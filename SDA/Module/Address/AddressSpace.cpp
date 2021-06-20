#include "AddressSpace.h"
#include <Manager/AddressSpaceManager.h>

const fs::path& CE::AddressSpace::getImagesDirectory() {
	return getAddrSpaceManager()->getProject()->getImagesDirectory() / fs::path(getName());
}
