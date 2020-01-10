#pragma once

#include "main.h"
#include "Game/ScriptEngine/Natives/types.h"
#include "Core/ScriptLang/IClassExportable.h"

namespace SDK {
	#include <glm/vec2.hpp>
	#include <glm/vec3.hpp>
	
	class Vector3D : public Class::IExportable<Vector3D>
	{
	public:
		float x;
		float y;
		float z;

	public:
		//for export
		Vector3D* getPersistent() override {
			return constructor(getX(), getY(), getZ());
		}
		//for export
		static Vector3D* constructor(float x, float y, float z) {
			return new Vector3D(x, y, z);
		}

		Vector3D(float x, float y, float z)
			: x(x)
			, y(y)
			, z(z)
		{ }

		Vector3D()
			: Vector3D(0,0,0)
		{ }

		Vector3D(const SE::Vector3& vec)
			: Vector3D(vec.x, vec.y, vec.z)
		{ }

		Vector3D(float arr[3])
			: Vector3D(arr[0], arr[1], arr[2])
		{ }

		Vector3D(glm::vec3 vec)
			: Vector3D(vec.x, vec.y, vec.z)
		{ }

		float getX() {
			return x;
		}

		float getY() {
			return y;
		}

		float getZ() {
			return z;
		}

		void setX(float value) {
			x = value;
		}

		void setY(float value) {
			y = value;
		}

		void setZ(float value) {
			z = value;
		}

		operator glm::vec3() {
			return glm::vec3(getX(), getY(), getZ());
		}

		void set(const Vector3D& vec) {
			setX(vec.x);
			setY(vec.y);
			setY(vec.z);
		}

		Vector3D& operator+=(Vector3D vec) {
			set(*this + vec);
			return *this;
		}

		Vector3D& operator-=(Vector3D vec) {
			set(*this - vec);
			return *this;
		}

		Vector3D& operator*=(float scalar) {
			set(*this * scalar);
			return *this;
		}

		Vector3D operator+(Vector3D vec) {
			return Add(*this, vec);
		}

		Vector3D operator-(Vector3D vec) {
			return Sub(*this, vec);
		}

		Vector3D operator*(float scalar) {
			return Mul(*this, scalar);
		}

		static Vector3D Add(Vector3D vec1, Vector3D vec2) {
			Vector3D result;
			result.set((glm::vec3)vec1 + (glm::vec3)vec2);
			return result;
		}

		static Vector3D Sub(Vector3D vec1, Vector3D vec2) {
			Vector3D result;
			result.set((glm::vec3)vec1 - (glm::vec3)vec2);
			return result;
		}

		static Vector3D Mul(Vector3D vec, float scalar) {
			Vector3D result;
			result.set((glm::vec3)vec * scalar);
			return result;
		}
	};

	class Vector2D
		: public Vector3D, public Class::IExportable<Vector2D>
	{
	public:
		//for export
		Vector2D* getPersistent() override {
			return constructor(getX(), getY());
		}
		//for export
		static Vector2D* constructor(float x, float y) {
			return new Vector2D(x, y);
		}

		Vector2D()
			: Vector3D()
		{ }

		Vector2D(const SE::Vector2& vec)
			: Vector2D(vec.x, vec.y)
		{ }

		Vector2D(float x, float y)
			: Vector3D(x, y, 0)
		{ }

		Vector2D(float arr[2])
			: Vector2D(arr[0], arr[1])
		{ }

		Vector2D(glm::vec2 vec)
			: Vector2D(vec.x, vec.y)
		{ }
	};

	using Pos = Vector3D;
	using Rot = Vector3D;
	using Speed = Vector3D;
	using Point2 = Vector2D;
	using Point3 = Vector3D;
	using Size2 = Vector2D;
	using Size3 = Vector3D;
};