
#include <iostream>
#include <Windows.h>

#pragma comment(lib, "LinearMath282.lib")
#pragma comment(lib, "BulletCollision282.lib")
#pragma comment(lib, "BulletDynamics282.lib")

#include <bullet3-2.82\src\btBulletDynamicsCommon.h>
#include <DirectXMath.h>


void d3d()
{
	using namespace DirectX;
	static XMMATRIX mat;

	static XMVECTOR Eye = XMVectorSet(float(rand() % 10), 0.0f, 1.0f, 0.0f);
	mat = XMMatrixIdentity(); //0F 11 44 04 20

	mat *= XMMatrixTranspose(mat);

	mat *= XMMatrixLookAtLH(Eye, Eye, XMVectorSet(50.0f, float(rand() % 10), 1.0f, 0.0f));

	printf("%i", mat.r[0], Eye.m128_i32);
}

void bullet()
{
	///collision configuration contains default setup for memory, collision setup. Advanced users can create their own configuration.
	btDefaultCollisionConfiguration* collisionConfiguration = new btDefaultCollisionConfiguration();
	///use the default collision dispatcher. For parallel processing you can use a diffent dispatcher (see Extras/BulletMultiThreaded)
	btCollisionDispatcher* dispatcher = new btCollisionDispatcher(collisionConfiguration);
	///btDbvtBroadphase is a good general purpose broadphase. You can also try out btAxis3Sweep.
	btBroadphaseInterface* overlappingPairCache = new btDbvtBroadphase();
	///the default constraint solver. For parallel processing you can use a different solver (see Extras/BulletMultiThreaded)
	btSequentialImpulseConstraintSolver* solver = new btSequentialImpulseConstraintSolver;

	//create a world
	auto m_dynamicsWorld = new btDiscreteDynamicsWorld(dispatcher, overlappingPairCache, solver, collisionConfiguration);
	m_dynamicsWorld->setGravity(btVector3(0, -15, 0));

	auto colShape = new btSphereShape(5);

	btTransform trans;
	trans.getRotation();

	btVector3 localInertia(0, 0, 0);
	colShape->calculateLocalInertia(3, localInertia);

	btDefaultMotionState* MotionState = new btDefaultMotionState(trans);
	btRigidBody::btRigidBodyConstructionInfo rbInfo(1, MotionState, colShape, localInertia);
	auto rigidBody = new btRigidBody(rbInfo);
	auto vel = rigidBody->getAngularVelocity();
	m_dynamicsWorld->addRigidBody(rigidBody);
	printf("vel = %f", vel.getX());
}


bool isFoo(float pos[3]) {
    return pos[0] == 0.3 && pos[2] == 1.2;
}

float gArr[300];

btMatrix3x3 getRandMat() {
	return btMatrix3x3(float(rand() % 10), float(rand() % 10), float(rand() % 10), 0.0, 0.0, 0.0, float(rand() % 10), 0.0, 0.0);
}

int main()
{
	bullet();
	//d3d();
	//auto lol = SIMD_EPSILON;
	//printf("%f = %x\n\n", lol, (int&)lol);



    float arr[3] = { float(rand() % 10), 2.0, 3.0 };
    bool rrr = isFoo(arr);
    memset(gArr, arr[0], rand());
   // printf("result = %i, %i", rrr, mat.getColumn(0).getX());
	Sleep(1000000);
    system("pause");
}
