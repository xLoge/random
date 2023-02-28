#pragma once
#include <immintrin.h>
#include <random>

// Fast is also cryptographically secure.
// * non fast function are just generated using a heatmap. So they take longer.
class random
{
private:
#ifdef _M_X64
	using engine = std::mt19937_64;
#else 
	using engine = std::mt19937;
#endif

#ifdef _M_X64
	static size_t rdrand64() noexcept {
		size_t ret = 0;
		while (!_rdrand64_step(&ret));
		return ret;
	}

	static size_t rdseed64() noexcept {
		size_t ret = 0;
		while (!_rdseed64_step(&ret));
		return ret;
	}
#endif

	static uint32_t rdrand32() noexcept {
		uint32_t ret = 0;
		while (!_rdrand32_step(&ret));
		return ret;
	}

	static uint32_t rdseed32() noexcept {
		uint32_t ret = 0;
		while (!_rdseed32_step(&ret));
		return ret;
	}

public:
	static size_t rand() noexcept {
#ifdef _M_X64
		return rdseed64();
#else 
		return rdseed32();
#endif
	}

	static uint32_t rand32() noexcept {
		return rdseed32();
	}

#ifdef _M_X64
	static size_t rand64() noexcept {
		return rdseed64();
	}
#endif

	static size_t fast_rand() noexcept {
#ifdef _M_X64
		return rdrand64();
#else 
		return rdrand32();
#endif
	}

	static uint32_t fast_rand32() noexcept {
		return rdrand32();
	}

#ifdef _M_X64
	static size_t fast_rand64() noexcept {
		return rdrand32();
	}
#endif

	static size_t rand_in_range(size_t _MIN, size_t _MAX) noexcept {
		engine mt(rdseed32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}

	static uint32_t rand_in_range32(uint32_t _MIN, uint32_t _MAX) noexcept {
		engine mt(rdseed32());
		std::uniform_int<uint32_t> dist(_MIN, _MAX);
		return dist(mt);
	}

#ifdef _M_X64
	static size_t rand_in_range64(size_t _MIN, size_t _MAX) noexcept {
		engine mt(rdseed32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}
#endif

	static size_t fast_rand_in_range(size_t _MIN, size_t _MAX) noexcept {
		engine mt(rdrand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}

	static size_t fast_rand_in_range32(size_t _MIN, size_t _MAX) noexcept {
		engine mt(rdrand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}

#ifdef _M_X64
	static size_t fast_rand_in_range64(size_t _MIN, size_t _MAX) noexcept {
		engine mt(rdrand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}
#endif
};
