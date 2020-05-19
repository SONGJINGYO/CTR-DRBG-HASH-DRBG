#include "HASH_DRBG.h"
#include "CTR_DRBG.h"

//HASH-DRBG
#if MODE==0
int main() {

	BYTE Entropy[32] = { 0x00, };
	BYTE Nonce[16] = { 0x00, };
	BYTE* perString = NULL;
	BYTE* AdditionalEntropy = NULL;
	BYTE* AdditionalData = NULL;
	BYTE* AdditionalDataReseed = NULL;
	BYTE* EntropyReseed = NULL;
	BYTE* EntropyReseed2 = NULL;
	BYTE* AdditionalData2 = NULL;

	BYTE* AdditionalData3 = NULL;
	BYTE* perString2 = NULL;
	BYTE AdditionalEntropy2[32] = { 0xF1,0x48,0xFD,0x64,0x8C,0x2B,0x7B,0xB0,0x93,0x95,0xFF,0x21,0x8C,0x07,0xD3,0x67,0xB8,0xCC,0xE9,0x3A,0x3B,0x88,0x1F,0x93,0x7E,0x14,0xC1,0x1D,0xD2,0x89,0x4F,0xE6 };
	FILE* rfp = NULL;
	FILE* wfp = NULL;
	HASH_DRBG ash = { {0x00},0x00, };
	BYTE RandomBit[32] = { 0x00, };
	int cnt_i = 0;
	Set_HASH_DRBG(&ash);
	perString = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalData = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalEntropy = (BYTE*)calloc(32, sizeof(BYTE));
	EntropyReseed2 = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalDataReseed = (BYTE*)calloc(32, sizeof(BYTE));
	EntropyReseed = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalData2 = (BYTE*)calloc(32, sizeof(BYTE));

	//예측내성 OFF
	//fopen_s(&rfp, "HASH_DRBG(SHA256(-)(no PR))_KAT.req", "rb");
	//fopen_s(&wfp, "HASH_DRBG(SHA256(-)(no PR))_KAT.rsp", "wb");
	//예측내성 ON
	fopen_s(&rfp, "HASH_DRBG(SHA256(-)(PR))_KAT.req", "rb");
	fopen_s(&wfp, "HASH_DRBG(SHA256(-)(PR))_KAT.rsp", "wb");


	int cnt_j = 0;
	//예측내성을 OFF 하였을때
	/* All True 확인
	for (cnt_i = 0; cnt_i < 4; cnt_i++) {
		printf("cnt_i=%d\n", cnt_i);
		//엔트로피, 난스, 개별화문자열, 추가데이터등의 길이를 파일로부터 읽어오기 위한 함수입니다.
		File_Read_init(rfp, &ash);
		//읽어온 길이 정보를 HASH_DRBG 구조체에 저장하는 함수입니다.
		Set_Init(&ash, &perString, &AdditionalData, &AdditionalEntropy, &AdditionalDataReseed, &AdditionalData2);

		//엔트로피, 난스, 개별화문자열, 추가데이터등의 초기화정보를 파일에 입력해주는 함수입니다.
		File_Write_init(wfp, &ash);
		for (cnt_j = 0; cnt_j < 15; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);

			//위에서 init함수로 길이정보를 초기화시켜 FILE_READ는 본격적으로 엔트로피와 난스 개별화문자열 추가입력데이터 등의 정보를 파일로부터 읽어오는 함수입니다.
			File_Read(rfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			//HASH_DRBG 난수열을 출력해주는 함수입니다.
			HASH_DRBG_Function(&ash, RandomBit, 256, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//출력된 난수열과 엔트로피 난스 개별화문자열 추가입력데이터의 정보를 파일에 쓰는 함수입니다.
			File_Write(wfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2, RandomBit, 256);

		}
	}
	*/

	//예측내성을 ON 하였을때

	for (cnt_i = 0; cnt_i < 4; cnt_i++) {
		printf("cnt_i=%d\n", cnt_i);
		//엔트로피, 난스, 개별화문자열, 추가데이터등의 길이를 파일로부터 읽어오기 위한 함수입니다.
		File_Read_init(rfp, &ash);
		//읽어온 길이 정보를 HASH_DRBG 구조체에 저장하는 함수입니다.
		Set_Init(&ash, &perString, &AdditionalData, &AdditionalEntropy, &AdditionalDataReseed, &AdditionalData2);
		//엔트로피, 난스, 개별화문자열, 추가데이터등의 초기화정보를 파일에 입력해주는 함수입니다.
		File_Write_init(wfp, &ash);
		for (cnt_j = 0; cnt_j < 15; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);
			//위에서 init함수로 길이정보를 초기화시켜 FILE_READ는 본격적으로 엔트로피와 난스 개별화문자열 추가입력데이터 등의 정보를 파일로부터 읽어오는 함수입니다.
			File_Read_PR(rfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2);
			//HASH_DRBG 난수열을 출력해주는 함수입니다.
			HASH_DRBG_Function(&ash, RandomBit, 256, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2);
			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//출력된 난수열과 엔트로피 난스 개별화문자열 추가입력데이터의 정보를 파일에 쓰는 함수입니다.
			File_Write_PR(wfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2, RandomBit, 256);

		}
	}






	return 0;
}
#else if MODE==1
int main() {

	BYTE Entropy[32] = { 0x00, };
	BYTE Nonce[16] = { 0x00, };
	BYTE* perString = NULL;
	BYTE* AdditionalEntropy = NULL;
	BYTE* AdditionalData = NULL;
	BYTE* AdditionalDataReseed = NULL;

	BYTE* EntropyReseed = NULL;
	BYTE* EntropyReseed2 = NULL;
	BYTE* AdditionalData2 = NULL;
	FILE* rfp = NULL;
	FILE* wfp = NULL;
	BYTE Randombit[ARIA_BLOCK_SIZE] = { 0x00, };
	int cnt_i = 0;
	perString = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalData = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalEntropy = (BYTE*)calloc(32, sizeof(BYTE));
	EntropyReseed2 = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalDataReseed = (BYTE*)calloc(32, sizeof(BYTE));
	EntropyReseed = (BYTE*)calloc(32, sizeof(BYTE));
	AdditionalData2 = (BYTE*)calloc(32, sizeof(BYTE));
	int cnt_j = 0;
	CTR_DRBG ctr = { {0x00},0x00, };
	//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!예측내성을 켰을시와 껐으시 아래의 파일이름을 바꿔야합니다.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	fopen_s(&rfp, "CTR_DRBG(ARIA-128(use df)(no PR))_KAT.req", "rb");
	fopen_s(&wfp, "CTR_DRBG(ARIA-128(use df)(no PR))_KAT.rsp", "wb");

	CTR_Set_CTR_DRBG(&ctr);
	//예측내성을 설정하지 않았을 때


	for (cnt_i = 0; cnt_i < 1; cnt_i++) {
		printf("================cnt_i=%d============\n", cnt_i);
		//파일에서 초기 길이정보를 읽어와 CTR_DRBG 구조체를 초기화시키는 함수입니다.
		File_Read_init_CTR(rfp, &ctr);

		//길이정보를 읽어와서 메모리를 할당하거나 길이정보가 0인 경우 함수를 NULL로 셋팅하는 함수입니다.
		CTR_Set_Init(&ctr, &perString, &AdditionalData, &EntropyReseed, &AdditionalDataReseed, &AdditionalData2);

		//읽어온 초기정보를 파일에 쓰는 함수입니다.
		File_Write_init_CTR(wfp, &ctr);
		for (cnt_j = 0; cnt_j < 1; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);
			//엔트로피, 난스, 추가입력데이터 등의 정보를 파일에서 읽어오는 함수입니다. (예측내성 OFF)
			File_Read_CTR(rfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			//CTR_DRBG 함수입니다.
			CTR_DRBG_Function(&ctr, Randombit, ctr.Randombitlen, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//엔트로피, 난스, 추가입력데이터, 난수열 등의 정보를 파일에 쓰는 함수입니다. (예측내성 OFF)
			File_Write_CTR(wfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2, Randombit);
		}

	}



	//예측내성 설정시
	//All True 확인
	/*
	for (cnt_i = 0; cnt_i < 14; cnt_i++) {
		printf("cnt_i=%d\n", cnt_i);
		//파일에서 초기 길이정보를 읽어와 CTR_DRBG 구조체를 초기화시키는 함수입니다.
		File_Read_init_CTR(rfp, &ctr);
		//길이정보를 읽어와서 메모리를 할당하거나 길이정보가 0인 경우 함수를 NULL로 셋팅하는 함수입니다.
		CTR_Set_Init(&ctr, &perString, &AdditionalData, &EntropyReseed, &AdditionalDataReseed, &AdditionalData2);

		//읽어온 초기정보를 파일에 쓰는 함수입니다.
		File_Write_init_CTR(wfp, &ctr);

		for (cnt_j = 0; cnt_j < 15; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);
			//엔트로피, 난스, 추가입력데이터 등의 정보를 파일에서 읽어오는 함수입니다. (예측내성 ON)
			File_Read_CTR_PR(rfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2,EntropyReseed2);
			//CTR_DRBG 함수입니다.
			CTR_DRBG_Function(&ctr, Randombit, ctr.Randombitlen, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2);

			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//엔트로피, 난스, 추가입력데이터, 난수열 등의 정보를 파일에 쓰는 함수입니다. (예측내성 OFF)
			File_Write_CTR_PR(wfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2, Randombit);

		}
	}
	*/
	/*
	printf("Entropy=");
	for (cnt_i = 0; cnt_i < ctr.Entropylen; cnt_i++) {
		printf("%X ", Entropy[cnt_i]);
	}printf("\n");
	printf("Nonce=");
	for (cnt_i = 0; cnt_i < ctr.Noncelen; cnt_i++) {
		printf("%X ", Nonce[cnt_i]);
	}printf("\n");
	printf("Perstring=");
	for (cnt_i = 0; cnt_i < ctr.perStringlen; cnt_i++) {
		printf("%X ", perString[cnt_i]);
	}printf("\n");
	printf("Additional Input=");
	for (cnt_i = 0; cnt_i < ctr.Additionaldatalen; cnt_i++) {
		printf("%X ", AdditionalData[cnt_i]);
	}printf("\n");
	printf("Reseed Entropy Input=");
	for (cnt_i = 0; cnt_i < ctr.Entropylen; cnt_i++) {
		printf("%X ", EntropyReseed[cnt_i]);
	}printf("\n");
	printf("Reseed Addtionaldata Input=");
	for (cnt_i = 0; cnt_i < ctr.Additionaldatalen; cnt_i++) {
		printf("%X ", AdditionalDataReseed[cnt_i]);
	}printf("\n");
	printf("Additional Input=");
	for (cnt_i = 0; cnt_i < ctr.Additionaldatalen; cnt_i++) {
		printf("%X ", AdditionalData2[cnt_i]);
	}printf("\n");
	*/

	return 0;
}
#endif
