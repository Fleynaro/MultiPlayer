#pragma once

class IDXGISwapChain;

class SdaInterface
{
public:
	virtual void start() = 0;
	virtual void render() = 0;
	virtual void setWindow(void* hwnd) = 0;
	virtual void setSwapChain(IDXGISwapChain* swapChain) = 0;
};

#ifdef SDA_DLL_EXPORTS 
class SdaInterfaceImpl : public SdaInterface
{
public:
	void start() override;
	void render() override;
	void setWindow(void* hwnd) override;
	void setSwapChain(IDXGISwapChain* pSwapChain) override;
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