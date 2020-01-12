#include <SdaInterface.h>
#include <Program.h>

SdaInterface* GetSdaInterface()
{
	return new SdaInterfaceImpl;
}

void SdaInterfaceImpl::start()
{

}

void SdaInterfaceImpl::execute_d3d_present(IDXGISwapChain* pSwapChain)
{

}
