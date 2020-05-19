#include"ARIA.h"

#define Seed_Bit 32 // 시드길이를 바이트로 나타낸 것
#define len_seed 2

#define DRBG_seedlen 55
#define ON 66
#define OFF 67
#define EntropyInputLen 32
#define NonceLen 16
#define SEED_Len 55
#define Reseed_Interval 6
#define LeftBigger 99
#define RightBigger 100
#define Same 101
#define RESEED_INTERVAL 6


typedef struct {
	int Entropylen;
	int Noncelen;
	int perStringlen;
	int Additionaldatalen;
	int prediction_resistance_flag;
	int Randombitlen;
	BYTE C[ARIA_KEY_SIZE];
	BYTE V[ARIA_BLOCK_SIZE];
	BYTE reseed_counter[ARIA_BLOCK_SIZE];

} CTR_DRBG;

int padding(BYTE** state, int len);
void CBC_MAC(BYTE* in, BYTE* IV, BYTE* out);
void CTR_df(CTR_DRBG* state, BYTE* seed_material, BYTE* seed);
void CTR_Instantiate_Function(CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString);
void update(CTR_DRBG* state, BYTE* seed);
int Compare2(BYTE* a, BYTE* b, int len);
void CTR_DRBG_Function(CTR_DRBG* state, BYTE* Randombit, int Randombitlen, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* AdditionalData, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* AdditionalData2);
void CTR_Set_CTR_DRBG(CTR_DRBG* state);
void CTR_Set_Init(CTR_DRBG* state, BYTE** perString, BYTE** AdditionalInput, BYTE** AdditionalEntropy, BYTE** AdditionalDataReseed, BYTE** AdditionalInput2);
void File_Read_init_CTR(FILE* fp, CTR_DRBG* state);
void File_Read_CTR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2);
void File_Write_init_CTR(FILE* fp, CTR_DRBG* state);
void File_Write_CTR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2, BYTE* Randombit);
void File_Write_CTR_PR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2, BYTE* Randombit);
void File_Read_CTR_PR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2);
void CTR_ADD_2(BYTE* CTR, int len);
void CTR_df_3(CTR_DRBG* state, BYTE* seed_material, BYTE* seed);


void CTR_df_2(CTR_DRBG* state, BYTE* seed_material, BYTE* seed);
#pragma once
