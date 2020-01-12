#include <SdaInterface.h>
#include <Program.h>

SdaInterface* GetSdaInterface()
{
	return new SdaInterfaceImpl;
}

void SdaInterfaceImpl::start()
{
	g_program->start();
}

void SdaInterfaceImpl::render(IDXGISwapChain* pSwapChain)
{
	g_program->getUI()->render();
}
