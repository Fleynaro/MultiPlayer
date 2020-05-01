//#pragma once
//#include "AbstractManager.h"
//#include "GVarManager.h"
//#include <Code/Function/MethodDeclaration.h>
//#include <Utils/BitStream.h>
//
//#include "FunctionDeclManager.h"
//#include "FunctionDefManager.h"
//
//namespace CE
//{
//	namespace Ghidra
//	{
//		class FunctionManager;
//	};
//
//	namespace CallGraph::Unit
//	{
//		class FunctionBody;
//		class NodeGroup;
//	};
//
//	namespace Function::Tag
//	{
//		class Manager;
//	};
//
//	namespace API::Function
//	{
//		class Function : public ItemDB
//		{
//		public:
//			Function(FunctionManager* funcManager, CE::Function::Function* function, API::Function::FunctionDecl* decl)
//				: m_funcManager(funcManager), m_function(function), m_decl(decl)
//			{}
//
//			FunctionManager* getFunctionManager() {
//				return m_funcManager;
//			}
//
//			void save() override {
//				lock();
//
//				getFunctionManager()->saveFunction(*getFunction());
//				if (getFunctionManager()->isGhidraManagerWorking()) {
//					getFunctionManager()->getGhidraManager()->push({
//						getFunctionManager()->getGhidraManager()->buildDesc(getFunction())
//						});
//				}
//
//				unlock();
//			}
//
//			bool hasBody() {
//				return m_funcBody != nullptr;
//			}
//
//			CallGraph::Unit::FunctionBody* getBody() {
//				if (m_funcBody == nullptr) {
//					m_funcBody = new CallGraph::Unit::FunctionBody(this);
//				}
//				return m_funcBody;
//			}
//
//			void setBody(CallGraph::Unit::FunctionBody* body) {
//				if (m_funcBody != nullptr) {
//					delete m_funcBody;
//				}
//				m_funcBody = body;
//			}
//
//			API::Function::FunctionDecl* getDeclaration() {
//				return m_decl;
//			}
//
//			CE::Function::FunctionDefinition& getDefinition() {
//				return getFunction()->getDefinition();
//			}
//
//			bool isFunction() {
//				return getFunction()->isFunction();
//			}
//
//			CE::Function::Function* getFunction() {
//				return m_function;
//			}
//
//			CE::Function::Method* getMethod() {
//				return static_cast<CE::Function::Method*>(getFunction());
//			}
//		private:
//			API::Function::FunctionDecl* m_decl;
//			CallGraph::Unit::FunctionBody* m_funcBody = nullptr;
//			FunctionManager* m_funcManager;
//		protected:
//			CE::Function::Function* m_function;
//		};
//	};
//};