#pragma once

class IDXGISwapChain;

class SdaInterface
{
public:
	virtual void start() = 0;
	virtual void execute_d3d_present(IDXGISwapChain* pSwapChain) = 0;
};

#ifdef SDA_DLL_EXPORTS 
class SdaInterfaceImpl : public SdaInterface
{
public:
	void start() override;
	void execute_d3d_present(IDXGISwapChain* pSwapChain) override;
};

extern "C"
{
	__declspec(dllexport) SdaInterface* GetSdaInterface();
};
#else
typedef SdaInterface* (*GET_SDA_INTERFACE) ();

static SdaInterface* getSdaInterface(HINSTANCE hModule) {
	GET_SDA_INTERFACE pGetSdaInterface = (GET_SDA_INTERFACE)GetProcAddress(hModule, "GetSdaInterface");
	return pGetSdaInterface();
}
#endif