#pragma once

#include <main.h>
#include <Assembler/Assembler.h>


void module_dynhook();


namespace CE
{
	namespace Hook
	{
		class DynHook;

		namespace Method
		{
			class IMethod
			{
			public:
				IMethod(DynHook* dynHook)
					: m_dynHook(dynHook)
				{}

				virtual bool hook() = 0;
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

			class Method1;
			template<typename T>
			class Method2;
			class MethodOld;
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

			void setXmmSaved(bool value) {
				m_xmmSaved = value;
			}

			bool hook() {
				return m_method->hook();
			}

			void disassemble()
			{
				const int jmpSize = 10 + 3; //mov + jmp
				ZyanUSize offset = 0;

				ZydisDecoder decoder;
				ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

				ZydisDecodedInstruction instruction;
				while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)((ZyanU64)m_func_ptr + offset), m_func_size - offset,
					&instruction)))
				{
					offset += instruction.length;
					if (offset >= jmpSize) {
						break;
					}
				}

				memcpy_s(m_oldBytes, sizeof(m_oldBytes), m_func_ptr, offset);
				m_oldBytesSize = static_cast<int>(offset);
			}
			

			bool createTrampline(Assembly::Block& code)
			{
				using namespace Assembly;

				m_tramplineBuffer = VirtualAlloc(NULL, 500, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (m_tramplineBuffer == NULL) {
					return false;
				}
				ByteStream bs((byte*)m_tramplineBuffer);
				bs.setWriteFlag(false);
				code.compile(bs);
				bs.setWriteFlag(true);
				code.compile(bs);
				bs.debugShow();
				return true;
			}

		public:
			void enable()
			{
				using namespace Assembly;

				//make jump to the trampline
				Block jmpToTrampline;
				jmpToTrampline
					.mov(Register::rax, (uint64_t)m_tramplineBuffer)
					.jmp(Register::rax);

				ByteStream bs((byte*)m_func_ptr);

				DWORD old;
				VirtualProtect(m_func_ptr, m_oldBytesSize, PAGE_EXECUTE_READWRITE, &old);
				memset(m_func_ptr, 0x90, m_oldBytesSize);
				bs.setWriteFlag(true);
				jmpToTrampline.compile(bs);
				bs.debugShow();
				VirtualProtect(m_func_ptr, m_oldBytesSize, old, &old);
			}

			void disable()
			{
				DWORD old;
				VirtualProtect(m_func_ptr, m_oldBytesSize, PAGE_EXECUTE_READWRITE, &old);
				memcpy_s(m_func_ptr, m_oldBytesSize, m_oldBytes, m_oldBytesSize);
				VirtualProtect(m_func_ptr, m_oldBytesSize, old, &old);
			}

			bool unhook()
			{
				if (m_tramplineBuffer == NULL) {
					return false;
				}
				VirtualFree(m_tramplineBuffer, 0, MEM_RELEASE);
				m_tramplineBuffer = NULL;

				disable();
				m_oldBytesSize = 0;
				return true;
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
			BYTE m_oldBytes[32] = { 0x0 };
			int m_oldBytesSize = 0;
		private:
			Method::IMethod* m_method = nullptr;
			LPVOID m_tramplineBuffer = NULL;
			int m_func_size = 30;
			int m_func_argsCount = 5;
			bool m_xmmSaved = true;
			void* m_userPtr = nullptr;
		};

		namespace Method
		{
			class Method1 : public IMethod
			{
			public:
				Method1(DynHook* dynHook)
					: IMethod(dynHook)
				{}

				struct CallState
				{
					uint64_t m_args[4] = { 0,0,0,0 };
					uint64_t m_xmm_args[4] = { 0,0,0,0 };
					uint64_t m_ret_addr = 0;
				};

				struct CallStack
				{
					CallState* m_curCallState = nullptr;
					std::vector<CallState> m_buffer;
				};

				__declspec(thread) static inline CallStack* m_callStack = nullptr;
				std::list<CallStack*> m_stacks;

				static void newCallState() {
					if (m_callStack == nullptr) {
						m_callStack = new CallStack;
					}
					m_callStack->m_buffer.push_back(CallState());
					m_callStack->m_curCallState = (CallState*)& m_callStack->m_buffer[m_callStack->m_buffer.size() - 1];
				}

				static void popCallState() {
					m_callStack->m_buffer.pop_back();
				}

				bool hook() override
				{
					using namespace Assembly;
					m_dynHook->disassemble();


					Register::Register64 regs_gen[4] = { Register::rcx, Register::rdx, Register::r8, Register::r9 };
					Register::Register64 regs_xmm[4] = { Register::xmm0, Register::xmm1, Register::xmm2, Register::xmm3 };

					Block getCurCallState;
					getCurCallState
						.mov_ptr(Register::rax, (uint64_t)& m_callStack)
						.mov(Register::rax, Register::rax, 0);
					Block NewCallStack;
					NewCallStack
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x100)
						.mov(Register::rax, (uint64_t)& newCallState)
						.call(Register::rax)
						.add(Register::rsp, 0x100)
						.pop(Register::rbp);
					Block popCallStack;
					popCallStack
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


					Block trampline;
					int argCount = min(m_dynHook->getArgCount(), 4);
					int64_t stackFrameSize = 0x100;

					//store 4 first args
					for (int i = 1; i <= argCount; i++)
						trampline
						.mov(Register::rsp, -0x08 * i, regs_gen[i - 1]);
					if (m_dynHook->isXmmSaved()) {
						//store 4 first xmm args
						for (int i = 1; i <= argCount; i++)
							trampline
							.movsd(Register::rsp, -0x08 * (argCount + i), regs_xmm[i - 1]);
					}

					trampline
						.addUnit(&NewCallStack);

					trampline
						.addUnit(&getCurCallState);
					//restore 4 first args
					for (int i = 1; i <= argCount; i++)
						trampline
						.mov(regs_gen[i - 1], Register::rsp, -0x08 * i);
					if (m_dynHook->isXmmSaved()) {
						//restore 4 first xmm args
						for (int i = 1; i <= argCount; i++)
							trampline
							.movsd(regs_xmm[i - 1], Register::rsp, -0x08 * (argCount + i));
					}

					//store 4 first args again
					for (int i = 0; i < argCount; i++)
						trampline
						.mov(Register::rax, 0x08 * i, regs_gen[i]);
					if (m_dynHook->isXmmSaved()) {
						//store 4 first xmm args again
						for (int i = 0; i < argCount; i++)
							trampline
							.movsd(Register::rax, 0x08 * (4 + i), regs_xmm[i]);
					}

					trampline
						.mov(Register::rcx, (uint64_t)m_dynHook)
						.lea(Register::rdx, Register::rsp, 0)
						.addUnit(&callback_before);



					Label label;
					Label label2;
					RawBlock* rawBlock;
					//prepare all to call original function
					trampline
						//store the return address
						.pop(Register::rcx)
						.mov(Register::dl, Register::al)
						.addUnit(&getCurCallState)
						.mov(Register::rax, 0x8 * 8, Register::rcx)
						//check if callback_before returns true or false
						.test(Register::dl, Register::dl)
						.jz(&label2)
						//replace the return address with another
						.mov(Register::rcx, &label)
						.push(Register::rcx);


					//restore 4 first args again
					for (int i = 0; i < argCount; i++)
						trampline
						.mov(regs_gen[i], Register::rax, 0x08 * i);
					if (m_dynHook->isXmmSaved()) {
						//restore 4 first xmm args again
						for (int i = 0; i < argCount; i++)
							trampline
							.movsd(regs_xmm[i], Register::rax, 0x08 * (4 + i));
					}

					//call the original function
					trampline
						.rawBlock(&rawBlock)
						.mov(Register::rax, (uint64_t)m_dynHook->m_func_ptr + m_dynHook->m_oldBytesSize)
						.jmp(Register::rax);
					rawBlock->setData(m_dynHook->m_oldBytes, m_dynHook->m_oldBytesSize);

					trampline
						.label(label)
						.mov(Register::rcx, Register::rax)
						.addUnit(&getCurCallState)
						.mov(Register::rax, 0x0, Register::rcx);
					if (m_dynHook->isXmmSaved()) {
						trampline
							.movsd(Register::rax, 0x8 * 4, Register::xmm0);
					}

					if (m_dynHook->m_callback_after != nullptr) {
						trampline
							.mov(Register::rcx, (uint64_t)m_dynHook)
							.lea(Register::rdx, Register::rsp, 0)
							.addUnit(&callback_after);
					}

					trampline
						.label(label2)
						.addUnit(&getCurCallState)

						//return addr
						.mov(Register::rcx, Register::rax, 0x8 * 8)
						.push(Register::rcx)

						//return value
						.mov(Register::rcx, Register::rax, 0x0)
						.push(Register::rcx)

						//return xmm value
						.mov(Register::rcx, Register::rax, 0x8 * 4)
						.push(Register::rcx)

						.addUnit(&popCallStack)

						//return xmm value
						.movsd(Register::xmm0, Register::rsp, 0)
						.pop(Register::rcx)
						//return value
						.pop(Register::rax)
						//return addr
						.pop(Register::rcx)
						.jmp(Register::rcx);


					//make the trampline
					if (!m_dynHook->createTrampline(trampline))
						return false;
					m_dynHook->enable();
					return true;
				}

				uint64_t getUID() override {
					return 0;
				}

				uint64_t& getArgumentValue(int argId) override
				{
					uint64_t result = 0;
					return result;
				}

				uint64_t& getXmmArgumentValue(int argId) override
				{
					uint64_t result = 0;
					return result;
				}

				uint64_t& getReturnValue() override
				{
					uint64_t result = 0;
					return result;
				}

				uint64_t& getXmmReturnValue() override
				{
					uint64_t result = 0;
					return result;
				}

				void* getReturnAddress() override
				{
					return nullptr;
				}

				void* getUserData() override
				{
					return nullptr;
				}
			};


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
					CallState* m_curCallState = nullptr;
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
					return getCurCallStack()->m_curCallState;
				}

				static void newCallStack() {
					m_callStack = new CallStack;
				}

				static void newCallState() {
					if (getCurCallStack() == nullptr) {
						newCallStack();
					}
					getCurCallStack()->m_buffer.push_back(CallState(getCurCallStack()->getNewId()));
					getCurCallStack()->m_curCallState = (CallState*)&getCurCallStack()->m_buffer[getCurCallStack()->m_buffer.size() - 1];
				}

				static void popCallState() {
					getCurCallStack()->m_buffer.pop_back();
				}

				bool hook() override
				{
					using namespace Assembly;
					m_dynHook->disassemble();


					Register::Register64 regs_gen[4] = { Register::rcx, Register::rdx, Register::r8, Register::r9 };
					Register::Register64 regs_xmm[4] = { Register::xmm0, Register::xmm1, Register::xmm2, Register::xmm3 };

					Block GetCurCallState;
					GetCurCallState
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x50)
						.mov(Register::rax, (uint64_t)& getCurCallState)
						.call(Register::rax)
						.add(Register::rsp, 0x50)
						.pop(Register::rbp);
						//.mov_ptr(Register::rax, (uint64_t)& m_callStack)
						//.mov(Register::rax, Register::rax, 0);
					Block NewCallState;
					NewCallState
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, 0x100)
						.mov(Register::rax, (uint64_t)& newCallState)
						.call(Register::rax)
						.add(Register::rsp, 0x100)
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


					Block trampline;
					int argCount = min(m_dynHook->getArgCount(), 4);
					int64_t stackFrameSize = 0x100;

					//allocate the main stack frame and write arguments
					int mainStackFrameSize = (2 * argCount * 0x8 + 0x10) & ~0xF; //aligning on 16-byte boundary
					mainStackFrameSize += 8;
					trampline
						.push(Register::rbp)
						.mov(Register::rbp, Register::rsp)
						.sub(Register::rsp, (uint64_t)mainStackFrameSize);

					//store 4 first args
					for (int i = 0; i < argCount; i++)
						trampline
						.mov(Register::rbp, -0x08 * i - 0x08, regs_gen[i]);
					if (m_dynHook->isXmmSaved()) {
						//store 4 first xmm args
						for (int i = 0; i < argCount; i++)
							trampline
							.movsd(Register::rbp, -0x08 * (argCount + i) - 0x08, regs_xmm[i]);
					}

					//create a new call state
					trampline
						.addUnit(&NewCallState);

					//call the callback_before
					trampline
						.addUnit(&GetCurCallState)
						.mov(Register::rax, 0x8, Register::rbp)
						.mov(Register::rcx, (uint64_t)m_dynHook)
						.addUnit(&callback_before);

					Label label;
					Label label2;
					RawBlock* rawBlock;
					//prepare all to call the original function
					trampline
						//deallocate the main stack frame
						.add(Register::rsp, (uint64_t)mainStackFrameSize)
						.pop(Register::rbp)
						.mov(Register::dl, Register::al)
						//store the return address
						.addUnit(&GetCurCallState)
						.pop(Register::rcx)
						.mov(Register::rax, 0x0, Register::rcx)
						//check if callback_before returns true or false
						.sub(Register::rsp, (uint64_t)m_dynHook->isXmmSaved() * 0x8 + 0x8 + 0x8)
						.test(Register::dl, Register::dl)
						.jz(&label2)
						.add(Register::rsp, (uint64_t)m_dynHook->isXmmSaved() * 0x8 + 0x8 + 0x8)
						//replace the return address with another
						.mov(Register::rcx, &label)
						.push(Register::rcx);

					//restore 4 first args
					for (int i = 0; i < argCount; i++)
						trampline
						.mov(regs_gen[i], Register::rsp, -0x08 * i - 0x10);
					if (m_dynHook->isXmmSaved()) {
						//restore 4 first xmm args
						for (int i = 0; i < argCount; i++)
							trampline
							.movsd(regs_xmm[i], Register::rsp, -0x08 * (argCount + i) - 0x10);
					}
					//call the original function
					trampline
						.rawBlock(&rawBlock)
						.mov(Register::rax, (uint64_t)m_dynHook->m_func_ptr + m_dynHook->m_oldBytesSize)
						.jmp(Register::rax); //problem with it
					rawBlock->setData(m_dynHook->m_oldBytes, m_dynHook->m_oldBytesSize);

					trampline
						.label(label)
						.sub(Register::rsp, 0x8)
						//return value
						.push(Register::rax);
					if (m_dynHook->isXmmSaved()) {
						//return xmm value
						trampline
							.sub(Register::rsp, 0x8)
							.movsd(Register::rsp, 0, Register::xmm0);
					}

					if (m_dynHook->m_callback_after != nullptr) {
						trampline
							.mov(Register::rcx, (uint64_t)m_dynHook)
							//.lea(Register::rdx, Register::rsp, -(m_dynHook->isXmmSaved() * 0x8 + 0x8))
							.addUnit(&callback_after);
					}

					trampline
						.label(label2)
						.addUnit(&PopCallState);
					if (m_dynHook->isXmmSaved()) {
						//return xmm value
						trampline
							.movsd(Register::xmm0, Register::rsp, 0)
							.add(Register::rsp, 0x8);
					}
					trampline
						//return addr
						.addUnit(&GetCurCallState)
						.mov(Register::rcx, Register::rax, 0x0)
						//return value
						.pop(Register::rax)
						//return back
						.add(Register::rsp, 0x8)
						.jmp(Register::rcx);


					//make the trampline
					if (!m_dynHook->createTrampline(trampline))
						return false;
					m_dynHook->enable();
					return true;
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





			class MethodOld : public IMethod
			{
			public:
				MethodOld(DynHook* dynHook)
					: IMethod(dynHook)
				{}

				__declspec(thread) static inline uint64_t m_retAddr = 0;
				bool hook() override
				{
					using namespace Assembly;

					m_dynHook->disassemble();
					Register::Register64 regs_up[4] = { Register::rcx, Register::rdx, Register::r8, Register::r9 };
					Register::Register64 regs_down[4] = { Register::xmm0, Register::xmm1, Register::xmm2, Register::xmm3 };
					uint64_t argCount = min(m_dynHook->getArgCount(), 4) * 0;
					uint64_t stackFrame = 0x40;

					Block trampline;

					//store 4 first args in stack
					for (int i = 1; i <= argCount; i++)
						trampline
						.mov(Register::rsp, 0x08 * i, regs_up[i - 1]);
					trampline
						.push(Register::rax);
					if (m_dynHook->isXmmSaved()) {
						//store 4 first xmm args in stack
						for (int i = 1; i <= argCount; i++)
							trampline
							.movsd(Register::rsp, -0x08 * i, regs_down[i - 1]);
					}

					//call the callback before calling the original function
					Label label;
					trampline
						.mov(Register::rcx, (uint64_t)m_dynHook)
						.mov(Register::rdx, Register::rsp)

						.sub(Register::rsp, stackFrame + argCount * 0x8)
						.mov(Register::rax, (uint64_t)m_dynHook->m_callback_before)
						.call(Register::rax)
						.add(Register::rsp, stackFrame + argCount * 0x8)

						.test(Register::al, Register::al);

					if (m_dynHook->isXmmSaved()) {
						//restore 4 first xmm args from stack
						for (int i = 1; i <= argCount; i++)
							trampline
							.movsd(regs_down[i - 1], Register::rsp, -0x08 * i);
					}
					trampline
						.pop(Register::rax);
					//restore 4 first args from stack
					for (int i = 1; i <= argCount; i++)
						trampline
						.mov(regs_up[i - 1], Register::rsp, 0x08 * i);

					trampline
						.jz(&label);

					Label label2;
					RawBlock* rawBlock;
					//prepare all to call original function
					trampline
						.pop(Register::rax)
						.mov(Register::rbx, (uint64_t)& m_retAddr)
						.mov(Register::rbx, 0, Register::rax)
						.mov(Register::rax, (uint64_t)m_dynHook->m_func_ptr + m_dynHook->m_oldBytesSize)
						.mov(Register::rbx, &label2)
						.push(Register::rbx)
						.rawBlock(&rawBlock)
						.jmp(Register::rax)
						.label(label2);
					//restore original first bytes of original function
					rawBlock->setData(m_dynHook->m_oldBytes, m_dynHook->m_oldBytesSize);

					if (m_dynHook->m_callback_after != nullptr) {
						trampline
							.push(Register::rsi);
						trampline
							.mov(Register::rcx, (uint64_t)m_dynHook)
							.mov(Register::rdx, Register::rsp);

						if (m_dynHook->isXmmSaved()) {
							trampline
								.push(Register::r15)
								.movsd(Register::rsp, 0x0, Register::xmm0);
						}

						trampline
							.push(Register::rax)
							.sub(Register::rsp, 0x10)
							.mov(Register::rax, (uint64_t)m_dynHook->m_callback_after)
							.call(Register::rax)
							.add(Register::rsp, 0x10)
							.pop(Register::rax);

						if (m_dynHook->isXmmSaved()) {
							trampline
								.pop(Register::r15);
						}
						trampline
							.pop(Register::rsi);
					}
					//jump back
					trampline
						.mov(Register::rcx, (uint64_t)& m_retAddr)
						.mov(Register::rbx, Register::rcx, 0)
						.jmp(Register::rbx)
						.label(label)
						.ret();

					//make the trampline
					if (!m_dynHook->createTrampline(trampline))
						return false;
					m_dynHook->enable();
					return true;
				}

				uint64_t getUID() override {
					return 0;
				}

				uint64_t& getArgumentValue(int argId) override
				{
					uint64_t result = 0;
					return result;
				}

				uint64_t& getXmmArgumentValue(int argId) override
				{
					uint64_t result = 0;
					return result;
				}

				uint64_t& getReturnValue() override
				{
					uint64_t result = 0;
					return result;
				}

				uint64_t& getXmmReturnValue() override
				{
					uint64_t result = 0;
					return result;
				}

				void* getReturnAddress() override
				{
					return nullptr;
				}

				void* getUserData() override
				{
					return nullptr;
				}
			};
		};
	};
};