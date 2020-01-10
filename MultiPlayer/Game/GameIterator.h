#pragma once



//Game iterator class
template<typename T>
class IGameIterator
{
protected:
	inline virtual T* ref() {
		return m_elem;
	}

	//increase by
	inline virtual T* add(int n, bool change = true) {
		return m_elem + n;
	}

	//increase by 1
	inline virtual T* increment() {
		return add(1);
	}

	//decrease by 1
	inline virtual T* decrement() {
		return add(-1);
	}
public:
	IGameIterator(T * elem = nullptr)
		: m_elem(elem)
	{}
	
	T& operator*() {
		return *ref();
	}

	T* operator&() {
		return ref();
	}

	IGameIterator operator+(int n) {
		return add(n, false);
	}
	IGameIterator operator-(int n) {
		return add(-n, false);
	}

	IGameIterator& operator+=(int n) {
		m_elem = add(n);
		return *this;
	}
	IGameIterator& operator-=(int n) {
		m_elem = add(-n);
		return *this;
	}

	IGameIterator& operator++() {
		m_elem = increment();
		return *this;
	}
	IGameIterator& operator--() {
		m_elem = decrement();
		return *this;
	}
	IGameIterator operator++(int) {
		++* this;
		return *this - 1;
	}
	IGameIterator operator--(int) {
		--* this;
		return *this + 1;
	}

	bool operator==(const IGameIterator & it) {
		return m_elem == it.m_elem;
	}
	bool operator!=(const IGameIterator & it) {
		return m_elem != it.m_elem;
	}

	using difference_type = T;
	using value_type = T;
	using pointer = const T*;
	using reference = const T &;
	using iterator_category = std::forward_iterator_tag;
protected:
	T* m_elem;
};
