#pragma once
#include <random>
#include <vector>
#include <array>
#include <string>
#include <bitset>
#include <mutex>
#include <immintrin.h>
#include <intrin.h>

// https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170
class InstructionSet
{
public:
	InstructionSet() {
		std::array<int, 4> cpui;

		__cpuid(cpui.data(), 0);
		nIds_ = cpui[0];

		for (int i = 0; i <= nIds_; ++i)
		{
			__cpuidex(cpui.data(), i, 0);
			data_.push_back(cpui);
		}

		char vendor[32];
		memset(vendor, 0, sizeof(vendor));
		*reinterpret_cast<int*>(vendor) = data_[0][1];
		*reinterpret_cast<int*>(vendor + 4) = data_[0][3];
		*reinterpret_cast<int*>(vendor + 8) = data_[0][2];
		vendor_ = vendor;

		if (vendor_ == "GenuineIntel") {
			isIntel_ = true;
		}
		else if (vendor_ == "AuthenticAMD") {
			isAMD_ = true;
		}

		if (nIds_ >= 1) {
			f_1_ECX_ = data_[1][2];
			f_1_EDX_ = data_[1][3];
		}

		if (nIds_ >= 7) {
			f_7_EBX_ = data_[7][1];
			f_7_ECX_ = data_[7][2];
		}

		__cpuid(cpui.data(), 0x80000000);
		nExIds_ = cpui[0];

		char brand[0x40];
		memset(brand, 0, sizeof(brand));

		for (int i = 0x80000000; i <= nExIds_; ++i)
		{
			__cpuidex(cpui.data(), i, 0);
			extdata_.push_back(cpui);
		}

		// load bitset with flags for function 0x80000001
		if (nExIds_ >= 0x80000001)
		{
			f_81_ECX_ = extdata_[1][2];
			f_81_EDX_ = extdata_[1][3];
		}

		// Interpret CPU brand string if reported
		if (nExIds_ >= 0x80000004)
		{
			memcpy(brand, extdata_[2].data(), sizeof(cpui));
			memcpy(brand + 16, extdata_[3].data(), sizeof(cpui));
			memcpy(brand + 32, extdata_[4].data(), sizeof(cpui));
			brand_ = brand;
		}
	};

	int nIds_ = 0;
	int nExIds_ = 0;
	std::string vendor_;
	std::string brand_;
	bool isIntel_ = 0;
	bool isAMD_ = 0;
	std::bitset<32> f_1_ECX_;
	std::bitset<32> f_1_EDX_;
	std::bitset<32> f_7_EBX_;
	std::bitset<32> f_7_ECX_;
	std::bitset<32> f_81_ECX_;
	std::bitset<32> f_81_EDX_;
	std::vector<std::array<int, 4>> data_;
	std::vector<std::array<int, 4>> extdata_;
};

// Fast is also cryptographically secure.
// * non fast function are just generated using a heatmap. So they take longer. ( up to 4x )
class random
{
private:
	static InstructionSet _cpu_instructions;
	static bool _has_RDRAND;
	static bool _has_RDSEED;

#ifdef _M_X64
	static size_t _rand64() {
		if (_has_RDSEED) {
			size_t _out;
			while (!_rdseed64_step(&_out));
			return _out;
		}
		else {
			return _fast_rand64();
		}
	}
#endif

	static uint32_t _rand32() {
		if (_has_RDSEED) {
			uint32_t _out;
			while (!_rdseed32_step(&_out));
			return _out;
		}
		else {
			return _fast_rand32();
		}
	}

#ifdef _M_X64
	static size_t _fast_rand64() {
		if (_has_RDRAND) {
			size_t _out;
			while (!_rdrand64_step(&_out));
			return _out;
		}
		else {
			std::mt19937_64 mt(std::random_device{}());
			std::uniform_int<size_t> dist(0, -1);
			return dist(mt);
		}
	}
#endif

	static uint32_t _fast_rand32() {
		if (_has_RDRAND) {
			uint32_t _out;
			while (!_rdrand32_step(&_out));
			return _out;
		}
		else {
			std::mt19937 mt(std::random_device{}());
			std::uniform_int<uint32_t> dist(0, -1);
			return dist(mt);
		}
	}

#ifdef _M_X64
	using engine = std::mt19937_64;
#else 
	using engine = std::mt19937;
#endif

public:
	static size_t rand() noexcept {
#ifdef _M_X64
		return _rand64();
#else 
		return _rand32();
#endif
	}

	static uint32_t rand32() noexcept {
		return _rand32();
	}

#ifdef _M_X64
	static size_t rand64() noexcept {
		return _rand64();
	}
#endif

	static size_t fast_rand() noexcept {
#ifdef _M_X64
		return _fast_rand64();
#else 
		return _fast_rand32();
#endif
	}

	static uint32_t fast_rand32() noexcept {
		return _fast_rand32();
	}

#ifdef _M_X64
	static size_t fast_rand64() noexcept {
		return _fast_rand64();
	}
#endif

	static size_t rand_in_range(size_t _MIN, size_t _MAX) noexcept {
		engine mt(_rand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}

	static uint32_t rand_in_range32(uint32_t _MIN, uint32_t _MAX) noexcept {
		engine mt(_rand32());
		std::uniform_int<uint32_t> dist(_MIN, _MAX);
		return dist(mt);
	}

#ifdef _M_X64
	static size_t rand_in_range64(size_t _MIN, size_t _MAX) noexcept {
		engine mt(_rand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}
#endif

	static size_t fast_rand_in_range(size_t _MIN, size_t _MAX) noexcept {
		engine mt(_fast_rand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}

	static size_t fast_rand_in_range32(uint32_t _MIN, uint32_t _MAX) noexcept {
		engine mt(_fast_rand32());
		std::uniform_int<uint32_t> dist(_MIN, _MAX);
		return dist(mt);
	}

#ifdef _M_X64
	static size_t fast_rand_in_range64(size_t _MIN, size_t _MAX) noexcept {
		engine mt(_fast_rand32());
		std::uniform_int<size_t> dist(_MIN, _MAX);
		return dist(mt);
	}
#endif

	static double rand_double(double _MIN = 0., double _MAX = std::numeric_limits<double>::max())
	{
		return (static_cast<double>(rand_in_range(0, std::numeric_limits<uint32_t>::max())) / static_cast<double>(std::numeric_limits<uint32_t>::max())) * (_MAX - _MIN);
	}

	static double fast_rand_double(double _MIN = 0., double _MAX = std::numeric_limits<double>::max())
	{
		return (static_cast<double>(fast_rand_in_range(0, std::numeric_limits<uint32_t>::max())) / static_cast<double>(std::numeric_limits<uint32_t>::max())) * (_MAX - _MIN);
	}

	static float rand_float(float _MIN = 0.F, float _MAX = std::numeric_limits<float>::max())
	{
		return (static_cast<float>(rand_double(_MIN, _MAX)));
	}

	static float fast_rand_float(float _MIN = 0.F, float _MAX = std::numeric_limits<float>::max())
	{
		return (static_cast<float>(fast_rand_double(_MIN, _MAX)));
	}
};

InstructionSet random::_cpu_instructions = InstructionSet{ };
bool random::_has_RDRAND = random::_cpu_instructions.f_1_ECX_[30];
bool random::_has_RDSEED = random::_cpu_instructions.f_7_EBX_[18];
