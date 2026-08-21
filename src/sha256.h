#pragma once

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cstddef>

using namespace std;

class SHA256
{
public:
	// Block && DIGEST SIZE
	static const size_t DIGEST_SIZE = 32; // 256 Bit
	static const size_t BLOCK_SIZE = 64; // 512 Bit

	//Constructor
	SHA256();

	void reset(); // reset to initial Values
	void finish(uint8_t out[DIGEST_SIZE]);
	string finish_hex();
	static string to_hex(const uint8_t* data, size_t len);
	static void hash(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE]);
	static string hash_hex(const string& text);

	// Deluxe Layer
	void update(const char* text);
	void update(const string& text);

	void update(const uint8_t* data, size_t len);


	//====DOUBLE SHA256====================================================================
	static void hash_double(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE]);
	static string hash_double_hex(const string& text);
	static string hash_double_hex_reversed(const uint8_t* data, size_t len);

	void saveState(uint32_t state[8]);
	void restoreState(uint32_t state[8], uint64_t bitlen);


private:

	void transform(const uint8_t block[BLOCK_SIZE]);
	//==== HELPER ===============================================//
	uint32_t rotr(uint32_t x, uint32_t n);
	uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
	uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
	uint32_t sigma0(uint32_t x);
	uint32_t sigma1(uint32_t x);
	uint32_t gamma0(uint32_t x);
	uint32_t gamma1(uint32_t x);


	// =============================//
	uint32_t _state[8];
	uint64_t _bitlen; // length from buffer
	uint8_t _buffer[BLOCK_SIZE];	// buffer -> incomplete blocks
	uint32_t _buffer_len;
};

