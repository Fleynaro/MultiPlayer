#pragma once
#include "Function.h"

namespace CE
{
	namespace Type {
		class Class;
	};

	namespace Function
	{
		class Method : public Function
		{
		public:
			Method(void* addr, RangeList size, int id, std::string name, std::string desc = "")
				: Function(addr, size, id, name, desc)
			{}

			bool isMethod() override {
				return true;
			}

			virtual void call(ArgList args) {}

			std::string getSigName() override {
				return (isVirtual() ? "virtual " : "") + Function::getSigName();
			}

			std::string getName() override;

			void setClass(Type::Class* Class);

			Type::Class* getClass() {
				return (Type::Class*)(
					static_cast<Type::Pointer*>(getSignature().getArgList()[0])->getType()
				);
			}

			bool isConstructor() {
				return m_virtual;
			}

			bool isVirtual() {
				return m_virtual;
			}

			Function* getFunctionBasedOn() {
				auto func = new Function(m_addr, m_ranges, getId(), getName(), getDesc());
				func->getArgNameList().swap(getArgNameList());
				func->getSignature().getArgList().swap(getSignature().getArgList());
				func->getSignature().setReturnType(getSignature().getReturnType());
				return func;
			}
		private:
			bool m_constructor = false;
			bool m_virtual = false;
		};
	};
};