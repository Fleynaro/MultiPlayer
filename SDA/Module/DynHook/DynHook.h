#pragma once

#include <main.h>
#include <Assembler/Assembler.h>
#include <Vendor/minhook/include/MinHook.h>


void module_dynhook();

//MYTODO: проблема. хук функций, у которых в начале вызов другой функции => нельзя прыгнуть из сегмента данных в сегмент кода
//MYTODO: юзать minhook, одна интструкция jmp с прыжком в пределах code segment(для многопоточности). Если есть условный переход, то заменять jmp на ориг. байты и перекидывать на ориг функцию
//MYTODO: pushad, popad

namespace CE
{
	namespace Hook
	{
		static bool init() {
			return MH_Initialize() != MH_OK;
		}

		static bool uninit() {
			return MH_Uninitialize() != MH_OK;
		}

		class DynHook;

		namespace Method
		{
			class IMethod
			{
			public:
				IMethod(DynHook* dynHook)
					: m_dynHook(dynHook)
				{}

				virtual void generateDynFuncBody() = 0;
				virtual uint64_t getUID() = 0;
				virtual uint64_t& getArgumentValue(int argId) = 0;
				virtual uint64_t& getXmmArgumentValue(int argId) = 0;
				virtual uint64_t& getReturnValue() = 0;
				virtual uint64_t& getXmmReturnValue() = 0;
				virtual void* getReturnAddress() = 0;
				virtual void* getUserData() = 0;
			protected:
				DynHook* m_dynHook;
			};

			template<typename T>
			class Method2;
		};

		class DynHook
		{
		public:
			
			typedef bool(*t_callback_before)(DynHook*);
			typedef void(*t_callback_after)(DynHook*);

			DynHook(void* func_ptr = nullptr, t_callback_before callback_before = nullptr, t_callback_after callback_after = nullptr)
				:
				m_func_ptr(func_ptr),
				m_callback_before(callback_before),
				m_callback_after(callback_after)
			{}

			~DynHook() {
				unhook();

				if (m_method != nullptr)
					delete m_method;
			}

			void setXmmSaved(bool value) {
				m_xmmSaved = value;
			}

			bool hook() {
				if (!createDynEmptyFunction()) {
					return false;
				}

				m_method->generateDynFuncBody();
				return true;
			}

			bool unhook()
			{
				destroyDynFunction();
				return true;
			}

			bool enable()
			{
				if (!hasDynFunction()) {
					if (!hook()) {
						return false;
					}
				}
				return MH_EnableHook(m_func_ptr) == MH_OK;
			}

			bool disable()
			{
				if (!hasDynFunction())
					return false;
				return MH_DisableHook(m_func_ptr) == MH_OK;
			}

			bool hasDynFunction() {
				return m_dynFuncBuffer != nullptr;
			}

			void destroyDynFunction() {
				if (!hasDynFunction())
					return;
				delete[] m_dynFuncBuffer;
				m_dynFuncBuffer = nullptr;

				if (m_trampline != nullptr) {
					MH_RemoveHook(m_func_ptr);
				}
			}

			bool createDynEmptyFunction(int size = 500)
			{
				m_dynFuncBuffer = new BYTE[size];
				DWORD old;
				VirtualProtect(m_dynFuncBuffer, size, PAGE_EXECUTE_READWRITE, &old);

				if (MH_CreateHook(m_func_ptr, m_dynFuncBuffer,
					reinterpret_cast<LPVOID*>(&m_trampline)) != MH_OK)
				{
					destroyDynFunction();
					return false;
				}

				return true;
			}

			void fillDynFunction(Assembly::Block& code) {
				using namespace Assembly;

				ByteStream bs(m_dynFuncBuffer);
				bs.setWriteFlag(false);
				code.compile(bs);
				bs.setWriteFlag(true);
				code.compile(bs);
				bs.debugShow();
			}
		
			void setUserPtr(void* ptr) {
				m_userPtr = ptr;
			}

			void* getUserPtr() {
				return m_userPtr;
			}

			inline int getArgCount() {
				return m_func_argsCount;
			}

			void setArgCount(int amount) {
				m_func_argsCount = amount;
			}

			inline uint64_t getUID() {
				return getMethod()->getUID();
			}

			template<typename T>
			inline T& getUserData()
			{
				return *(T*)getMethod()->getUserData();
			}

			template<typename T = uint64_t>
			inline T& getArgumentValue(int argId)
			{
				return (T&)getMethod()->getArgumentValue(argId);
			}

			template<typename T = uint64_t>
			inline T& getXmmArgumentValue(int argId)
			{
				return (T&)getMethod()->getXmmArgumentValue(argId);
			}

			template<typename T>
			inline void setArgumentValue(int argId, T value)
			{
				getArgumentValue<T>(argId) = value;
			}

			template<typename T>
			inline void setXmmArgumentValue(int argId, T value)
			{
				getXmmArgumentValue<T>(argId) = value;
			}

			template<typename T = uint64_t>
			inline T& getReturnValue()
			{
				return (T&)getMethod()->getReturnValue();
			}

			template<typename T = uint64_t>
			inline T& getXmmReturnValue()
			{
				return (T&)getMethod()->getXmmReturnValue();
			}

			template<typename T>
			inline void setReturnValue(T value)
			{
				getReturnValue<T>() = value;
			}

			template<typename T>
			inline void setXmmReturnValue(T value)
			{
				getXmmReturnValue<T>() = value;
			}

			inline void* getReturnAddress()
			{
				return getMethod()->getReturnAddress();
			}

			void setMethod(Method::IMethod* method)
			{
				if (m_method != nullptr)
					delete m_method;
				m_method = method;
			}

			inline Method::IMethod* getMethod() {
				return m_method;
			}

			inline bool isXmmSaved() {
				return m_xmmSaved;
			}

			t_callback_before m_callback_before;
			t_callback_after m_callback_after;
			void* m_func_ptr;
			byte* m_trampline = nullptr;
		private:
			Method::IMethod* m_method = nullptr;
			byte* m_dynFuncBuffer = nullptr;
			int m_func_size = 30;
			int m_func_argsCount = 5;
			bool m_xmmSaved = true;
			void* m_userPtr = nullptr;
		};

		namespace Method
		{
			template<typename UserType>
			class Method2 : public IMethod
			{
			public:
				Method2(DynHook* dynHook)
					: IMethod(dynHook)
				{}

				struct CallState
				{
					uint64_t m_ret_addr = 0;
					std::uintptr_t m_rsp = 0;
					uint32_t m_id;
					UserType m_userData;

					CallState(uint32_t id)
						: m_id(id)
					{}

					inline std::uintptr_t& getRsp() {
						return m_rsp;
					}

					inline uint32_t getId() {
						return m_id;
					}
				};

				struct CallStack
				{
					std::vector<CallState> m_buffer;

					uint32_t m_callStateId = 0;
					uint32_t m_callStackId;
					CallStack() {
						generateId();
					}

					inline uint32_t getId() {
						return m_callStackId;
					}

					uint32_t getNewId() {
						return m_callStateId ++;
					}
				private:
					void generateId() {
						std::random_device rd;
						std::default_random_engine generator(rd());
						std::uniform_int_distribution<uint32_t> distribution(0, 0xFFFFFFFF);
						m_callStackId = distribution(generator);
					}
				};

				__declspec(thread) static inline CallStack* m_callStack = nullptr;
				std::list<CallStack*> m_stacks;

				static CallStack* getCurCallStack() {
					return m_callStack;
				}

				static CallState* getCurCallState() {
					return (CallState*)&getCurCallStack()->m_buffer[getCurCallStack()->m_buffer.size() - 1];
				}

				static void newCallStack() {
					m_callStack = new CallStack;
				}

				static CallState* newCallState() {
					if (getCurCallStack() == nullptr) {
						newCallStack();
					}
					getCurCallStack()->m_buffer.push_back(CallState(getCurCallStack()->getNewId()));
					return getCurCallState();
				}

				static uint64_t popCallState() {
					auto retAddr = getCurCallState()->m_ret_addr;
					getCurCallStack()->m_buffer.pop_back();
					return retAddr;
				}

				void generateDynFuncBody() override
				{
					using namespace Assembly;

					Register::Register64 regs_gen[4] = { Register::rcx, Register::rdx, Register::r8, Register::r9 };
					Register::Register64 regs_xmm[4] = { Register::xmm0, Register::xmm1, Register::xmm2, Register::xmm3 };

					Block NewCallState;
					NewCallState
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x108)
						.mov(Register::rax, (uint64_t)& newCallState)
						.call(Register::rax)
						.add(Register::rsp, 0x108)
						.pop(Register::rbp);
					Block PopCallState;
					PopCallState
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x100)
						.mov(Register::rax, (uint64_t)& popCallState)
						.call(Register::rax)
						.add(Register::rsp, 0x100)
						.pop(Register::rbp);
					Block callback_before;
					callback_before
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x100)
						.mov(Register::rax, (uint64_t)m_dynHook->m_callback_before)
						.call(Register::rax)
						.add(Register::rsp, 0x100)
						.pop(Register::rbp);
					Block callback_after;
					callback_after
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x100)
						.mov(Register::rax, (uint64_t)m_dynHook->m_callback_after)
						.call(Register::rax)
						.add(Register::rsp, 0x100)
						.pop(Register::rbp);


					int argCount = min(m_dynHook->getArgCount(), 4);
					int64_t stackFrameSize = 0x100;

					//allocate the main stack frame and write arguments there for callback_before
					int mainStackFrameSize = (2 * argCount * 0x8 + 0x10) & ~0xF; //aligning on 16-byte boundary
					mainStackFrameSize += 8;
					Assembly::Block body;

					//stack frame
					body
						.mov(Register::rax, Register::rsp, 0x0) //get origin ret addr
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, (uint64_t)mainStackFrameSize)
						.push(Register::rax);

					//store 4 first args
					for (int i = 0; i < argCount; i++)
						body
						.mov(Register::rbp, -0x08 * i - 0x08, regs_gen[i]);
					if (m_dynHook->isXmmSaved()) {
						//store 4 first xmm args
						for (int i = 0; i < argCount; i++)
							body
							.movsd(Register::rbp, -0x08 * (argCount + i) - 0x08, regs_xmm[i]);
					}

					//create a new call state
					body
						.addUnit(&NewCallState)
						//store the origin return address
						.pop(Register::rcx) //get origin ret addr
						.mov(Register::rax, 0x0, Register::rcx)
						.mov(Register::rax, 0x8, Register::rbp);

					//*** call the callback_before ***
					body
						.mov(Register::rcx, (uint64_t)m_dynHook)
						.addUnit(&callback_before);

					Label label;
					Label label2;
					//prepare all to call the original function
					body
						//deallocate the main stack frame
						.add(Register::rsp, (uint64_t)mainStackFrameSize)
						.pop(Register::rbp);

					//check if callback_before returns true or false
					auto retValuesSize = (uint64_t)m_dynHook->isXmmSaved() * 0x8 + 0x8;
					body
						//for return values(xmm, not xmm)
						.sub(Register::rsp, retValuesSize)
						.test(Register::al, Register::al)
						.jz(&label2)
						.add(Register::rsp, retValuesSize)
						//replace the return address with another
						.mov(Register::rcx, &label)
						.mov(Register::rsp, 0x0, Register::rcx);
					
					//restore 4 first args
					for (int i = 0; i < argCount; i++)
						body
						.mov(regs_gen[i], Register::rsp, -0x08 * i - 0x10);
					if (m_dynHook->isXmmSaved()) {
						//restore 4 first xmm args
						for (int i = 0; i < argCount; i++)
							body
							.movsd(regs_xmm[i], Register::rsp, -0x08 * (argCount + i) - 0x10);
					}


					//*** call the original function ***
					body
						.mov(Register::rax, (uint64_t)m_dynHook->m_trampline)
						.jmp(Register::rax); //problem with it
					

					//after the original function executed
					body
						.label(label)
						.sub(Register::rsp, 0x8)
						//return value
						.push(Register::rax);
					if (m_dynHook->isXmmSaved()) {
						//return xmm value
						body
							.sub(Register::rsp, 0x8)
							.movsd(Register::rsp, 0, Register::xmm0);
					}

					//*** call the callback_after ***
					if (m_dynHook->m_callback_after != nullptr) {
						body
							.mov(Register::rcx, (uint64_t)m_dynHook)
							//.lea(Register::rdx, Register::rsp, -(m_dynHook->isXmmSaved() * 0x8 + 0x8))
							.addUnit(&callback_after);
					}


					//we go here anyway
					body
						.label(label2)
						.addUnit(&PopCallState)
						.mov(Register::rcx, Register::rax);
					if (m_dynHook->isXmmSaved()) {
						//return xmm value
						body
							.movsd(Register::xmm0, Register::rsp, 0)
							.add(Register::rsp, 0x8);
					}
					body
						//return value
						.pop(Register::rax)
						//return back
						.add(Register::rsp, 0x8)
						.jmp(Register::rcx);

					m_dynHook->fillDynFunction(body);
				}

				uint64_t getUID() override {
					return ((uint64_t)getCurCallStack()->getId() << 32) | (uint64_t)getCurCallState()->getId();
				}

				uint64_t& getArgumentValue(int argId) override
				{
					if (argId <= 4) {
						return *(uint64_t*)(getCurCallState()->getRsp() - (std::uintptr_t)argId * 0x8);
					}
					else {
						return *(uint64_t*)(getCurCallState()->getRsp() + (std::uintptr_t)argId * 0x8 + 0x8);
					}
				}

				uint64_t& getXmmArgumentValue(int argId) override
				{
					if (argId <= 4) {
						return *(uint64_t*)(getCurCallState()->getRsp() - (std::uintptr_t)min(4, m_dynHook->getArgCount()) * 0x8 - (std::uintptr_t)argId * 0x8);
					}
					else {
						return getArgumentValue(argId);
					}
				}

				uint64_t& getReturnValue() override
				{
					return *(uint64_t*)(getCurCallState()->getRsp());
				}

				uint64_t& getXmmReturnValue() override
				{
					return *(uint64_t*)(getCurCallState()->getRsp() - 0x8);
				}

				void* getReturnAddress() override
				{
					if (getCurCallState()->m_ret_addr != 0) {
						return (void*)getCurCallState()->m_ret_addr;
					}
					return (void*)*(uint64_t*)(getCurCallState()->getRsp() - 0x8);
				}

				void* getUserData() override
				{
					return &getCurCallState()->m_userData;
				}
			};
		};
	};
};