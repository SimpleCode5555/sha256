#include "SHA256.h"

using namespace std;

// Intialize Hash Values
SHA256::SHA256()
{
	reset();
}

// Reset the State after Hashing to initial values [ FIPS 180-4 Standard ]
void SHA256::reset()
{
	_state[0] = 0x6a09e667u;
	_state[1] = 0xbb67ae85u;
	_state[2] = 0x3c6ef372u;
	_state[3] = 0xa54ff53au;
	_state[4] = 0x510e527fu;
	_state[5] = 0x9b05688cu;
	_state[6] = 0x1f83d9abu;
	_state[7] = 0x5be0cd19u;

	_bitlen = 0;
	_buffer_len = 0;
}

// dynamic change data in block without get all chunk
void SHA256::update(const uint8_t* data, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		_buffer[_buffer_len] = data[i];
		_buffer_len++;

		if (_buffer_len == BLOCK_SIZE)
		{
			transform(_buffer);
			_bitlen += 512;
			_buffer_len = 0;
		}
	}
}

// 2 additional update Layer
void SHA256::update(const char* text)
{
	update(reinterpret_cast<const uint8_t*>(text), strlen(text));
}

void SHA256::update(const string& text)
{
	update(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

// Padding 
void SHA256::finish(uint8_t out[DIGEST_SIZE])
{
	uint32_t i = _buffer_len;

	_bitlen += (uint64_t)_buffer_len * 8;

	// append a single Bit
	_buffer[i] = 0x80;
	i++;

	// fill with 0 -> ( Blocksize - 8 )
	if (i > BLOCK_SIZE - 8)
	{
		while (i < BLOCK_SIZE)
		{
			_buffer[i] = 0x00;
			i++;
		}

		transform(_buffer);
		i = 0;
	}

	while (i < BLOCK_SIZE - 8)
	{
		_buffer[i] = 0x00;
		i++;
	}

	// write the lowest bit to buffer 
	// Convert Bit to Big Endian
	_buffer[56] = (uint8_t)(_bitlen >> 56);
	_buffer[57] = (uint8_t)(_bitlen >> 48);
	_buffer[58] = (uint8_t)(_bitlen >> 40);
	_buffer[59] = (uint8_t)(_bitlen >> 32);
	_buffer[60] = (uint8_t)(_bitlen >> 24);
	_buffer[61] = (uint8_t)(_bitlen >> 16);
	_buffer[62] = (uint8_t)(_bitlen >> 8);
	_buffer[63] = (uint8_t)(_bitlen);

	transform(_buffer);

	// Swap the Bit Order from the Most important Bit
	for (uint32_t j = 0; j < 8; j++)
	{
		out[j * 4 + 0] = (uint8_t)(_state[j] >> 24);
		out[j * 4 + 1] = (uint8_t)(_state[j] >> 16);
		out[j * 4 + 2] = (uint8_t)(_state[j] >> 8);
		out[j * 4 + 3] = (uint8_t)(_state[j]);
	}
}

// Convertion to HexString
string SHA256::finish_hex()
{
	uint8_t digest[DIGEST_SIZE];
	finish(digest);

	return to_hex(digest, DIGEST_SIZE);
}

// Process Hashing
void SHA256::hash(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE])
{
	SHA256 ctx;
	ctx.update(data, len);
	ctx.finish(out);
}

// Process Hashing and convert to Hex
string SHA256::hash_hex(const string& text)
{
	SHA256 ctx;
	ctx.update(text);
	return ctx.finish_hex();
}

//====BEGIN DOUBLE SHA256 =====================================================================//
// Second Hashing Round within the Output Hash from first Round as Input
void SHA256::hash_double(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE])
{
	uint8_t first[DIGEST_SIZE];
	hash(data, len, first);
	hash(first, DIGEST_SIZE, out);
}

string SHA256::hash_double_hex(const string& text)
{
	uint8_t digest[DIGEST_SIZE];
	hash_double(reinterpret_cast<const uint8_t*>(text.data()), text.size(), digest);

	return to_hex(digest, DIGEST_SIZE);
}

string SHA256::hash_double_hex_reversed(const uint8_t* data, size_t len)
{
	uint8_t digest[DIGEST_SIZE];
	hash_double(data, len, digest);

	// Flip the byte order to Big-Endian
	uint8_t reversed[DIGEST_SIZE];

	for (size_t i = 0; i < DIGEST_SIZE; i++)
	{
		reversed[i] = digest[DIGEST_SIZE - 1 - i];
	}

	return to_hex(reversed, DIGEST_SIZE);
}

// R Shift -> (n) positions && fill with zero
uint32_t SHA256::rotr(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32 - n));
}

// Bitwise Multiplexer
uint32_t SHA256::ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (~x & z);
}

// Majority Value ( 2/3 ) 1 | 0
uint32_t SHA256::maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

// 3 Rotations with variable numbers of right Shifts from Startvalue (x)
uint32_t SHA256::sigma0(uint32_t x)
{
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint32_t SHA256::sigma1(uint32_t x)
{
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

// 2 Rotations right same as sigma && 3 bits rightshift with (x)
uint32_t SHA256::gamma0(uint32_t x)
{
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

// 2 Rotations right same as sigma && 10 bits rightshift with (x)
uint32_t SHA256::gamma1(uint32_t x)
{
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void SHA256::transform(const uint8_t block[BLOCK_SIZE])
{
	// Init the 64 Round constants
	// Square Root of first 64 Prime Numbers
	static const uint32_t K[64] = {
			0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
			0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
			0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
			0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
			0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
			0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
			0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
			0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
			0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
			0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
			0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
			0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
			0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
			0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
			0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
			0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
	};

	uint32_t w[64];

	// Message Scheduele first Data from Block Split
	for (uint32_t t = 0; t < 16; t++)
	{
		w[t] = ((uint32_t)block[t * 4 + 0] << 24)
			| ((uint32_t)block[t * 4 + 1] << 16)
			| ((uint32_t)block[t * 4 + 2] << 8)
			| ((uint32_t)block[t * 4 + 3]);
	}

	// Fill Data from 16 to 64
	for (uint32_t t = 16; t < 64; t++)
	{
		w[t] = gamma1(w[t - 2]) + w[t - 7]
			+ gamma0(w[t - 15]) + w[t - 16];
	}

	// Init the 8 Parts from the 512 Bit Input
	uint32_t a = _state[0];
	uint32_t b = _state[1];
	uint32_t c = _state[2];
	uint32_t d = _state[3];
	uint32_t e = _state[4];
	uint32_t f = _state[5];
	uint32_t g = _state[6];
	uint32_t h = _state[7];

	for (uint32_t t = 0; t < 64; t++)
	{
		// Choose e,f,g (&h) bitwise
		// Choose a,b,c (&a) bitwise
		uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[t] + w[t];
		uint32_t t2 = sigma0(a) + maj(a, b, c);

		// Shift each position once && add t1 + t2
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	// Add intermediate values
	_state[0] += a;
	_state[1] += b;
	_state[2] += c;
	_state[3] += d;
	_state[4] += e;
	_state[5] += f;
	_state[6] += g;
	_state[7] += h;
}

// Conversion from uint8 to String ( HEX )
string SHA256::to_hex(const uint8_t* data, size_t len)
{
	static const char hex_chars[] = "0123456789abcdef";
	string result;
	result.reserve(len * 2);

	for (size_t i = 0; i < len; i++)
	{
		result += hex_chars[(data[i] >> 4) & 0x0F];
		result += hex_chars[data[i] & 0x0F];
	}
	return result;
}

// Save s the actually State between Hashing Rounds
void SHA256::saveState(uint32_t state[8])
{
	memcpy(state, _state, sizeof(_state));
}

// Restore the saved State
void SHA256::restoreState(uint32_t state[8], uint64_t bitlen)
{
	memcpy(_state, state, sizeof(_state));
	_bitlen = bitlen;
	_buffer_len = 0;
	memset(_buffer, 0, sizeof(_buffer));

}

