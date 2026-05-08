#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include <ctime>

using namespace std;

const int kSBox[] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67,
	0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
	0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7,
	0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1,
	0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
	0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83,
	0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
	0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA,
	0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
	0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
	0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
	0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
	0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
	0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
	0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4,
	0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
	0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70,
	0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
	0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
	0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1,
	0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0,
	0x54, 0xBB, 0x16};

const uint8_t kRcon[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10,
	0x20, 0x40, 0x80, 0x1B, 0x36};

int key[16] = {
	0x2b, 0x7e, 0x15, 0x16,
	0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88,
	0x09, 0xcf, 0x4f, 0x3c};

array<uint8_t, 16> addRoundKey(const array<uint8_t, 16> &text, const array<uint8_t, 16> &roundKey)
{
	array<uint8_t, 16> output{};
	for (size_t i = 0; i < 16; ++i)
	{
		// ^ is xor operation
		// The mask passes through XOR unchanged:
		// (state ^ mask) ^ roundKey = (state ^ roundKey) ^ mask
		output[i] = text[i] ^ roundKey[i];
	}

	return output;
}


array<uint8_t, 16> subBytes(const array<uint8_t, 16> &text, uint8_t &mask)
{
	uint8_t m_in  = mask;
	uint8_t m_out = static_cast<uint8_t>(rand() % 256);

	uint8_t maskedSBox[256];
	for (int x = 0; x < 256; ++x)
		maskedSBox[x ^ m_in] = static_cast<uint8_t>(kSBox[x]) ^ m_out;

	array<uint8_t, 16> output{};
	for (size_t i = 0; i < 16; ++i)
	{
		output[i] = maskedSBox[text[i]];
	}

	mask = m_out;
	return output;
}

array<uint8_t, 16> mixcolumn(const array<uint8_t, 16> &text)
{
	auto xtime = [](uint8_t x) -> uint8_t
	{
		return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
	};

	auto mul2 = [&](uint8_t x) -> uint8_t
	{
		return xtime(x);
	};

	auto mul3 = [&](uint8_t x) -> uint8_t
	{
		// 3x = 2x ^ x
		return static_cast<uint8_t>(xtime(x) ^ x);
	};


	array<uint8_t, 16> output{};
	for (size_t col = 0; col < 4; ++col)
	{
		uint8_t s0 = text[0 * 4 + col];
		uint8_t s1 = text[1 * 4 + col];
		uint8_t s2 = text[2 * 4 + col];
		uint8_t s3 = text[3 * 4 + col];

		// b0 = (02*a0) ^ (03*a1) ^ (01*a2) ^ (01*a3)
		// b1 = (01*a0) ^ (02*a1) ^ (03*a2) ^ (01*a3)
		// b2 = (01*a0) ^ (01*a1) ^ (02*a2) ^ (03*a3)
		// b3 = (03*a0) ^ (01*a1) ^ (01*a2) ^ (02*a3)

		output[0 * 4 + col] = static_cast<uint8_t>(mul2(s0) ^ mul3(s1) ^ s2 ^ s3);
		output[1 * 4 + col] = static_cast<uint8_t>(s0 ^ mul2(s1) ^ mul3(s2) ^ s3);
		output[2 * 4 + col] = static_cast<uint8_t>(s0 ^ s1 ^ mul2(s2) ^ mul3(s3));
		output[3 * 4 + col] = static_cast<uint8_t>(mul3(s0) ^ s1 ^ s2 ^ mul2(s3));
	}

	return output;
}


array<uint8_t, 16> shiftRows(const array<uint8_t, 16> &text)
{
	array<uint8_t, 16> output{};
	output[0] = text[0];
	output[1] = text[1];
	output[2] = text[2];
	output[3] = text[3];
	output[4] = text[5];
	output[5] = text[6];
	output[6] = text[7];
	output[7] = text[4];
	output[8] = text[10];
	output[9] = text[11];
	output[10] = text[8];
	output[11] = text[9];
	output[12] = text[15];
	output[13] = text[12];
	output[14] = text[13];
	output[15] = text[14];

	return output;
}

array<uint8_t, 16> textToBytes(const string &text)
{
	if (text.size() != 16)
	{
		throw invalid_argument("textToBytes expects exactly 16 characters for one AES block");
	}

	array<uint8_t, 16> bytes{};
	for (size_t i = 0; i < 16; ++i)
	{
		bytes[i] = static_cast<uint8_t>(text[i]);
	}

	return bytes;
}

array<uint8_t, 4> getColumn(const array<uint8_t, 16> &state, size_t col)
{
	return {
		state[0 * 4 + col],
		state[1 * 4 + col],
		state[2 * 4 + col],
		state[3 * 4 + col]};
}

void setColumn(array<uint8_t, 16> &state, size_t col, const array<uint8_t, 4> &word)
{
	state[0 * 4 + col] = word[0];
	state[1 * 4 + col] = word[1];
	state[2 * 4 + col] = word[2];
	state[3 * 4 + col] = word[3];
}

array<uint8_t, 4> rotWord(const array<uint8_t, 4> &word)
{
	return {word[1], word[2], word[3], word[0]};
}

array<uint8_t, 4> subWord(const array<uint8_t, 4> &word)
{
	return {
		static_cast<uint8_t>(kSBox[word[0]]),
		static_cast<uint8_t>(kSBox[word[1]]),
		static_cast<uint8_t>(kSBox[word[2]]),
		static_cast<uint8_t>(kSBox[word[3]])};
}

array<array<uint8_t, 16>, 11> expandKey128(const array<uint8_t, 16> &initialKey)
{
	array<array<uint8_t, 16>, 11> roundKeys{};
	roundKeys[0] = initialKey;

	for (size_t round = 1; round <= 10; ++round)
	{
		array<uint8_t, 16> nextKey{};

		array<uint8_t, 4> temp = rotWord(getColumn(roundKeys[round - 1], 3));
		temp = subWord(temp);
		temp[0] ^= kRcon[round - 1];

		array<uint8_t, 4> w0 = getColumn(roundKeys[round - 1], 0);
		array<uint8_t, 4> w1 = getColumn(roundKeys[round - 1], 1);
		array<uint8_t, 4> w2 = getColumn(roundKeys[round - 1], 2);
		array<uint8_t, 4> w3 = getColumn(roundKeys[round - 1], 3);

		array<uint8_t, 4> nw0{};
		array<uint8_t, 4> nw1{};
		array<uint8_t, 4> nw2{};
		array<uint8_t, 4> nw3{};

		for (size_t i = 0; i < 4; ++i)
		{
			nw0[i] = static_cast<uint8_t>(w0[i] ^ temp[i]);
			nw1[i] = static_cast<uint8_t>(w1[i] ^ nw0[i]);
			nw2[i] = static_cast<uint8_t>(w2[i] ^ nw1[i]);
			nw3[i] = static_cast<uint8_t>(w3[i] ^ nw2[i]);
		}

		setColumn(nextKey, 0, nw0);
		setColumn(nextKey, 1, nw1);
		setColumn(nextKey, 2, nw2);
		setColumn(nextKey, 3, nw3);

		roundKeys[round] = nextKey;
	}

	return roundKeys;
}

array<uint8_t, 16> AES128(const array<uint8_t, 16> &plainText, const array<uint8_t, 16> &initialKey)
{
	auto roundKeys = expandKey128(initialKey);

	uint8_t mask = static_cast<uint8_t>(rand() % 256);


	array<uint8_t, 16> state{};
	for (size_t i = 0; i < 16; ++i)
		state[i] = plainText[i] ^ mask;

	state = addRoundKey(state, roundKeys[0]);

	for (size_t round = 1; round <= 9; ++round)
	{
		
		state = subBytes(state, mask);

		state = shiftRows(state);

		state = mixcolumn(state);

		state = addRoundKey(state, roundKeys[round]);
	}

	state = subBytes(state, mask);  
	state = shiftRows(state);        
	state = addRoundKey(state, roundKeys[10]);

	
	array<uint8_t, 16> ciphertext{};
	for (size_t i = 0; i < 16; ++i)
		ciphertext[i] = state[i] ^ mask;

	return ciphertext;
}

void printHexBlock(const array<uint8_t, 16> &block)
{
	ios oldState(nullptr);
	oldState.copyfmt(cout);

	for (auto byteValue : block)
	{
		cout << hex << setw(2) << setfill('0') << static_cast<int>(byteValue);
	}

	cout.copyfmt(oldState);
}

int main()
{
	srand(static_cast<unsigned>(time(nullptr)));

	const array<uint8_t, 16> testKey = {
		0x2b, 0x28, 0xab, 0x09,
		0x7e, 0xae, 0xf7, 0xcf,
		0x15, 0xd2, 0x15, 0x4f,
		0x16, 0xa6, 0x88, 0x3c};

	const array<uint8_t, 16> testPlaintext = {
		0x32, 0x88, 0x31, 0xe0,
		0x43, 0x5a, 0x31, 0x37,
		0xf6, 0x30, 0x98, 0x07,
		0xa8, 0x8d, 0xa2, 0x34};

	const array<uint8_t, 16> expectedCiphertext = {
		0x39, 0x02, 0xdc, 0x19,
		0x25, 0xdc, 0x11, 0x6a,
		0x84, 0x09, 0x85, 0x0b,
		0x1d, 0xfb, 0x97, 0x32};

	const array<uint8_t, 16> actualCiphertext = AES128(testPlaintext, testKey);

	cout << "Plaintext: ";
	printHexBlock(testPlaintext);
	cout << '\n';

	cout << "Key      : ";
	printHexBlock(testKey);
	cout << '\n';

	cout << "Expected : ";
	printHexBlock(expectedCiphertext);
	cout << '\n';

	cout << "Actual   : ";
	printHexBlock(actualCiphertext);
	cout << '\n';

	if (actualCiphertext == expectedCiphertext)
	{
		cout << "Test result: PASS" << '\n';
		return 0;
	}

	cout << "Test result: FAIL" << '\n';
	return 1;
}
