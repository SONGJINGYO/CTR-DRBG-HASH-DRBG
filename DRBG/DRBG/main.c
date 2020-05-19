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

	//�������� OFF
	//fopen_s(&rfp, "HASH_DRBG(SHA256(-)(no PR))_KAT.req", "rb");
	//fopen_s(&wfp, "HASH_DRBG(SHA256(-)(no PR))_KAT.rsp", "wb");
	//�������� ON
	fopen_s(&rfp, "HASH_DRBG(SHA256(-)(PR))_KAT.req", "rb");
	fopen_s(&wfp, "HASH_DRBG(SHA256(-)(PR))_KAT.rsp", "wb");


	int cnt_j = 0;
	//���������� OFF �Ͽ�����
	/* All True Ȯ��
	for (cnt_i = 0; cnt_i < 4; cnt_i++) {
		printf("cnt_i=%d\n", cnt_i);
		//��Ʈ����, ����, ����ȭ���ڿ�, �߰������͵��� ���̸� ���Ϸκ��� �о���� ���� �Լ��Դϴ�.
		File_Read_init(rfp, &ash);
		//�о�� ���� ������ HASH_DRBG ����ü�� �����ϴ� �Լ��Դϴ�.
		Set_Init(&ash, &perString, &AdditionalData, &AdditionalEntropy, &AdditionalDataReseed, &AdditionalData2);

		//��Ʈ����, ����, ����ȭ���ڿ�, �߰������͵��� �ʱ�ȭ������ ���Ͽ� �Է����ִ� �Լ��Դϴ�.
		File_Write_init(wfp, &ash);
		for (cnt_j = 0; cnt_j < 15; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);

			//������ init�Լ��� ���������� �ʱ�ȭ���� FILE_READ�� ���������� ��Ʈ���ǿ� ���� ����ȭ���ڿ� �߰��Էµ����� ���� ������ ���Ϸκ��� �о���� �Լ��Դϴ�.
			File_Read(rfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			//HASH_DRBG �������� ������ִ� �Լ��Դϴ�.
			HASH_DRBG_Function(&ash, RandomBit, 256, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//��µ� �������� ��Ʈ���� ���� ����ȭ���ڿ� �߰��Էµ������� ������ ���Ͽ� ���� �Լ��Դϴ�.
			File_Write(wfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2, RandomBit, 256);

		}
	}
	*/

	//���������� ON �Ͽ�����

	for (cnt_i = 0; cnt_i < 4; cnt_i++) {
		printf("cnt_i=%d\n", cnt_i);
		//��Ʈ����, ����, ����ȭ���ڿ�, �߰������͵��� ���̸� ���Ϸκ��� �о���� ���� �Լ��Դϴ�.
		File_Read_init(rfp, &ash);
		//�о�� ���� ������ HASH_DRBG ����ü�� �����ϴ� �Լ��Դϴ�.
		Set_Init(&ash, &perString, &AdditionalData, &AdditionalEntropy, &AdditionalDataReseed, &AdditionalData2);
		//��Ʈ����, ����, ����ȭ���ڿ�, �߰������͵��� �ʱ�ȭ������ ���Ͽ� �Է����ִ� �Լ��Դϴ�.
		File_Write_init(wfp, &ash);
		for (cnt_j = 0; cnt_j < 15; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);
			//������ init�Լ��� ���������� �ʱ�ȭ���� FILE_READ�� ���������� ��Ʈ���ǿ� ���� ����ȭ���ڿ� �߰��Էµ����� ���� ������ ���Ϸκ��� �о���� �Լ��Դϴ�.
			File_Read_PR(rfp, &ash, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2);
			//HASH_DRBG �������� ������ִ� �Լ��Դϴ�.
			HASH_DRBG_Function(&ash, RandomBit, 256, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2);
			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//��µ� �������� ��Ʈ���� ���� ����ȭ���ڿ� �߰��Էµ������� ������ ���Ͽ� ���� �Լ��Դϴ�.
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
	//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!���������� �����ÿ� ������ �Ʒ��� �����̸��� �ٲ���մϴ�.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	fopen_s(&rfp, "CTR_DRBG(ARIA-128(use df)(no PR))_KAT.req", "rb");
	fopen_s(&wfp, "CTR_DRBG(ARIA-128(use df)(no PR))_KAT.rsp", "wb");

	CTR_Set_CTR_DRBG(&ctr);
	//���������� �������� �ʾ��� ��


	for (cnt_i = 0; cnt_i < 1; cnt_i++) {
		printf("================cnt_i=%d============\n", cnt_i);
		//���Ͽ��� �ʱ� ���������� �о�� CTR_DRBG ����ü�� �ʱ�ȭ��Ű�� �Լ��Դϴ�.
		File_Read_init_CTR(rfp, &ctr);

		//���������� �о�ͼ� �޸𸮸� �Ҵ��ϰų� ���������� 0�� ��� �Լ��� NULL�� �����ϴ� �Լ��Դϴ�.
		CTR_Set_Init(&ctr, &perString, &AdditionalData, &EntropyReseed, &AdditionalDataReseed, &AdditionalData2);

		//�о�� �ʱ������� ���Ͽ� ���� �Լ��Դϴ�.
		File_Write_init_CTR(wfp, &ctr);
		for (cnt_j = 0; cnt_j < 1; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);
			//��Ʈ����, ����, �߰��Էµ����� ���� ������ ���Ͽ��� �о���� �Լ��Դϴ�. (�������� OFF)
			File_Read_CTR(rfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			//CTR_DRBG �Լ��Դϴ�.
			CTR_DRBG_Function(&ctr, Randombit, ctr.Randombitlen, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2);
			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//��Ʈ����, ����, �߰��Էµ�����, ������ ���� ������ ���Ͽ� ���� �Լ��Դϴ�. (�������� OFF)
			File_Write_CTR(wfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalDataReseed, AdditionalData2, Randombit);
		}

	}



	//�������� ������
	//All True Ȯ��
	/*
	for (cnt_i = 0; cnt_i < 14; cnt_i++) {
		printf("cnt_i=%d\n", cnt_i);
		//���Ͽ��� �ʱ� ���������� �о�� CTR_DRBG ����ü�� �ʱ�ȭ��Ű�� �Լ��Դϴ�.
		File_Read_init_CTR(rfp, &ctr);
		//���������� �о�ͼ� �޸𸮸� �Ҵ��ϰų� ���������� 0�� ��� �Լ��� NULL�� �����ϴ� �Լ��Դϴ�.
		CTR_Set_Init(&ctr, &perString, &AdditionalData, &EntropyReseed, &AdditionalDataReseed, &AdditionalData2);

		//�о�� �ʱ������� ���Ͽ� ���� �Լ��Դϴ�.
		File_Write_init_CTR(wfp, &ctr);

		for (cnt_j = 0; cnt_j < 15; cnt_j++) {
			printf("cnt_j=%d\n", cnt_j);
			//��Ʈ����, ����, �߰��Էµ����� ���� ������ ���Ͽ��� �о���� �Լ��Դϴ�. (�������� ON)
			File_Read_CTR_PR(rfp, &ctr, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2,EntropyReseed2);
			//CTR_DRBG �Լ��Դϴ�.
			CTR_DRBG_Function(&ctr, Randombit, ctr.Randombitlen, Entropy, Nonce, perString, AdditionalData, EntropyReseed, AdditionalData2, EntropyReseed2);

			fprintf(wfp, "COUNT = %d\n", cnt_j);
			//��Ʈ����, ����, �߰��Էµ�����, ������ ���� ������ ���Ͽ� ���� �Լ��Դϴ�. (�������� OFF)
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
