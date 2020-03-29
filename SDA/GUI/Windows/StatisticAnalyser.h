#pragma once
#include "GUI/Windows/ItemLists/FunctionList.h"

namespace GUI::Window::Statistic
{
	class SignatureAnalyser
		: public PrjWindow
	{
	public:
		SignatureAnalyser(API::Function::Function* function)
			: PrjWindow("Siganture analyser"), m_function(function)
		{
			//select buffers

			getMainContainer()
				.addItem(
					new Elements::Button::ButtonStd(
						"Analyse",
						Events::Listener(
							std::function([&](Events::ISender* sender) {

							})
						)
					)
				);
		}

	protected:
		API::Function::Function* m_function;
	};

};