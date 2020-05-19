#include "SHA2.h"
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
#define MODE 1 // 0 : SHA256-DRBG  1: CTR-DRBG

typedef struct {
	BYTE V[DRBG_seedlen];
	BYTE C[DRBG_seedlen];
	int Entropylen;
	int Noncelen;
	int perStringlen;
	int Additionaldatalen;
	int prediction_resistance_flag;
	int security_strength;
	BYTE reseed_counter[RESEED_INTERVAL];


} HASH_DRBG;


void Hash_df(BYTE* seed, BYTE* seed_material, int seedlen, int len);
void Reseed_Function(HASH_DRBG* state, BYTE* Entropy, BYTE* additionalinput, int seedlen);
void Generate_Function(HASH_DRBG* state, BYTE* Randombit, BYTE* Entropy, BYTE* additionaldata, int seedlen, int Randombitlen);
void Addition(BYTE* c, BYTE* a, BYTE* b, int len);
void CTR_ADD(BYTE* CTR, int len);
void Instantiate(HASH_DRBG* state, BYTE* EntropyInput, BYTE* Nonce, BYTE* PersonalizationString, int seedlen);
void Set_HASH_DRBG(HASH_DRBG* state);
void Rotate2(BYTE* a);
void reverse(BYTE* a, int len);
int Compare(BYTE* a, BYTE* b, int len);

void File_Write(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2, BYTE* Randombit, int Randombitlen);
void File_Read_init(FILE* fp, HASH_DRBG* state);

void HASH_DRBG_Function(HASH_DRBG* state, BYTE* Randombit, int Randombitlen, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* AdditionalData, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* AdditionalData2);
void File_Read(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2);
void Set_Init(HASH_DRBG* state, BYTE** perString, BYTE** AdditionalInput, BYTE** AdditionalEntropy, BYTE** AdditionalDataReseed, BYTE** AdditionalInput2);
void File_Write_init(FILE* fp, HASH_DRBG* state);
void File_Read_PR(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2);
void File_Write_PR(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2, BYTE* Randombit, int Randombitlen);