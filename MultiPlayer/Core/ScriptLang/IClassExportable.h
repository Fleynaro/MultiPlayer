#pragma once


#include "main.h"


#define IS_CLASS_EXPORTABLE(Class) std::is_base_of<IExportable<##Class>, ##Class>::value
#define CLASS_EXPORTABLE_ASSERT(Class) static_assert(IS_CLASS_EXPORTABLE(##Class), "Need to use IExportable!")


namespace Class
{
	class Builder;

	//interface to export API class on c++ to an external script runtime(V8, Lua, Pawn, ...)
	template<typename T>
	class IExportable
	{
	public:
		IExportable() = default;
		virtual ~IExportable() {};
		virtual T* getPersistent() = 0;

		bool isDynamic() {
			return m_dynamic;
		}

		void toDynamic() {
			m_dynamic = true;
		}

		void toNotDynamic() {
			m_dynamic = false;
		}

		void incRefCounter() {
			m_refCount++;
		}

		bool decRefCounter() {
			return --m_refCount == 0;
		}

		static void setClassBuilder(Builder* builder) {
			m_builder = builder;
		}

		static Builder* getClassBuilder() {
			return m_builder;
		}
	private:
		inline static Builder* m_builder = nullptr;
		bool m_dynamic = false;
		unsigned short m_refCount = 0;
	};
};