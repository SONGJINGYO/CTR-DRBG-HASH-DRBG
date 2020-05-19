#include"HASH_DRBG.h"
//���Ͽ��� HASH_DRBG�� �ʿ��� ������ �о���� �Լ��Դϴ�.
void File_Read(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2) {
	int temp = 0x00;
	int temp2 = 0x00;
	int cnt_i = 0;
	BYTE test[10000] = { 0x00, };
	//Count
	fscanf(fp, "%s = ", test);
	fscanf(fp, "%d", &temp);

	fscanf(fp, "%s = ", test);

	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		Entropy[cnt_i] = (BYTE)temp;
	}
	//Nonce
	fscanf(fp, "%s = ", test);
	for (cnt_i = 0; cnt_i < state->Noncelen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		Nonce[cnt_i] = (BYTE)temp;
	}
	//perString
	fscanf(fp, "%s = ", test);
	if (perString != NULL) {
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			perString[cnt_i] = (BYTE)temp;
		}
	}
	//�߰�������

	fscanf(fp, "%s = ", test);
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			additionaldata[cnt_i] = (BYTE)temp;
		}
	}
	//���õ� ��Ʈ����
	fscanf(fp, "%s = ", test);
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		EntropyReseed[cnt_i] = (BYTE)temp;
	}
	//���õ� �߰�������
	fscanf(fp, "%s = ", test);
	if (AdditionalInputReseed != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			AdditionalInputReseed[cnt_i] = (BYTE)temp;
		}
	}
	fscanf(fp, "%s = ", test);
	if (Additionaldata2 != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			Additionaldata2[cnt_i] = (BYTE)temp;
		}
	}
	return;
}
//���Ͽ��� HASH_DRBG�� ������ �о���� �Լ��ε� ���� �Լ��� �ٸ� ������ ���������� �������� ������ �о���� ������ �ٸ��� �����Դϴ�.
void File_Read_PR(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2) {
	int temp = 0x00;
	int temp2 = 0x00;
	int cnt_i = 0;
	BYTE test[10000] = { 0x00, };
	//Count
	fscanf(fp, "%s = ", test);
	fscanf(fp, "%d", &temp);

	fscanf(fp, "%s = ", test);

	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		Entropy[cnt_i] = (BYTE)temp;
	}
	//Nonce
	fscanf(fp, "%s = ", test);
	for (cnt_i = 0; cnt_i < state->Noncelen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		Nonce[cnt_i] = (BYTE)temp;
	}
	//perString
	fscanf(fp, "%s = ", test);
	if (perString != NULL) {
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			perString[cnt_i] = (BYTE)temp;
		}
	}
	//�߰�������

	fscanf(fp, "%s = ", test);
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			additionaldata[cnt_i] = (BYTE)temp;
		}
	}
	//���õ� ��Ʈ����
	fscanf(fp, "%s = ", test);
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		EntropyReseed[cnt_i] = (BYTE)temp;
	}
	//���õ� �߰�������2
	fscanf(fp, "%s = ", test);
	if (additionaldata2 != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			additionaldata2[cnt_i] = (BYTE)temp;
		}
	}
	fscanf(fp, "%s = ", test);

	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		EntropyReseed2[cnt_i] = (BYTE)temp;
	}

	return;
}
//HASH_DRBG�� �ʱ�ȭ ���� ���Ͽ� ���� �Լ��Դϴ�.
void File_Write_init(FILE* fp, HASH_DRBG* state) {
	int cnt_i = 0;
	fprintf(fp, "[SHA-256]\n");
	if (state->prediction_resistance_flag == ON) {
		fprintf(fp, "[PredictionResistance = True]\n");
	}
	else {
		fprintf(fp, "[PredictionResistance = False]\n");
	}
	fprintf(fp, "[EntropyInputLen = %d]\n", state->Entropylen * 8);
	fprintf(fp, "[NonceLen = %d]\n", state->Noncelen * 8);
	fprintf(fp, "[PersonalizationStringLen = %d]\n", state->perStringlen * 8);
	fprintf(fp, "[AdditionalInputLen = %d]\n\n", state->Additionaldatalen * 8);

	return;
}
//HASH_DRBG�� ���� ���Ͽ� ���� �Լ��Դϴ�. (�������� OFF)
void File_Write(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2, BYTE* Randombit, int Randombitlen) {
	int cnt_i = 0;

	fprintf(fp, "EntropyInput = ");
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fprintf(fp, "%02X", Entropy[cnt_i]);
	}	fprintf(fp, "\n");
	fprintf(fp, "Nonce = ");
	for (cnt_i = 0; cnt_i < state->Noncelen; cnt_i++) {
		fprintf(fp, "%02X", Nonce[cnt_i]);
	}	fprintf(fp, "\n");
	fprintf(fp, "PersonalizationString = ");
	if (perString != NULL) {
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			fprintf(fp, "%02X", perString[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}
	fprintf(fp, "AdditionalInput = ");
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fprintf(fp, "%02X", additionaldata[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}
	fprintf(fp, "EntropyInputReseed = ");

	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fprintf(fp, "%02X", EntropyReseed[cnt_i]);
	}	fprintf(fp, "\n");

	fprintf(fp, "AdditionalInputReseed = ");
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fprintf(fp, "%02X", AdditionalInputReseed[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}

	fprintf(fp, "AdditionalInput = ");
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fprintf(fp, "%02X", Additionaldata2[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}


	fprintf(fp, "ReturnedBits = ");
	for (cnt_i = 0; cnt_i < Randombitlen / 8; cnt_i++) {
		fprintf(fp, "%02X", Randombit[cnt_i]);
	}	fprintf(fp, "\n\n");


	return;
}






//���Ͽ��� �� ���������� �о�� HASH_DRBG����ü�� ���������� �ʱ�ȭ��Ű������ �Լ��Դϴ�.
void File_Read_init(FILE* fp, HASH_DRBG* state) {

	int temp = 0x00;
	int cnt_i = 0;
	BYTE test3[100] = { 0x00, };
	BYTE test2[100] = { 0x00, };
	BYTE False[5] = { 'F','a','l','s','e' };
	fscanf(fp, "%s\n", test3);

	fscanf(fp, "%s = %s", test3, test2);
	if (Compare(test2, False, 5) == Same) {
		state->prediction_resistance_flag = OFF;
	}
	else {
		state->prediction_resistance_flag = ON;
	}
	fscanf(fp, "%s =", test3);
	fscanf(fp, "%d", &temp);
	fscanf(fp, "%s", test3);
	//����Ʈ ����
	state->Entropylen = temp / 8;

	fscanf(fp, "%s =", test3);
	fscanf(fp, "%d", &temp);
	fscanf(fp, "%s", test3);
	state->Noncelen = temp / 8;

	fscanf(fp, "%s =", test3);
	fscanf(fp, "%d", &temp);
	fscanf(fp, "%s", test3);
	state->perStringlen = temp / 8;

	fscanf(fp, "%s =", test3);
	fscanf(fp, "%d", &temp);
	fscanf(fp, "%s", test3);
	state->Additionaldatalen = temp / 8;

	return;
}

//HASH_DRBG�� ������ ��Ʈ���� ���� ����ȭ���ڿ� �߰��Էµ����� ���� ������ ���Ͽ� ���� ���� �Լ��Դϴ�. (FILE_WRITE�� �ٸ� ���� FILE_WRITE_PR�Լ��� ��� ���������� ON�� �Ǿ��� �� ����Ǵ� �Լ��Դϴ�.)
void File_Write_PR(FILE* fp, HASH_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2, BYTE* Randombit, int Randombitlen) {
	int cnt_i = 0;

	fprintf(fp, "EntropyInput = ");
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fprintf(fp, "%02X", Entropy[cnt_i]);
	}	fprintf(fp, "\n");
	fprintf(fp, "Nonce = ");
	for (cnt_i = 0; cnt_i < state->Noncelen; cnt_i++) {
		fprintf(fp, "%02X", Nonce[cnt_i]);
	}	fprintf(fp, "\n");
	fprintf(fp, "PersonalizationString = ");
	if (perString != NULL) {
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			fprintf(fp, "%02X", perString[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}
	fprintf(fp, "AdditionalInput = ");
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fprintf(fp, "%02X", additionaldata[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}
	fprintf(fp, "EntropyInputPR = ");

	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fprintf(fp, "%02X", EntropyReseed[cnt_i]);
	}	fprintf(fp, "\n");

	fprintf(fp, "AdditionalInput = ");
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fprintf(fp, "%02X", additionaldata2[cnt_i]);
		}	fprintf(fp, "\n");
	}
	else {
		fprintf(fp, "\n");
	}

	fprintf(fp, "EntropyInputPR = ");

	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fprintf(fp, "%02X", EntropyReseed2[cnt_i]);
	}	fprintf(fp, "\n");



	fprintf(fp, "ReturnedBits = ");
	for (cnt_i = 0; cnt_i < Randombitlen / 8; cnt_i++) {
		fprintf(fp, "%02X", Randombit[cnt_i]);
	}	fprintf(fp, "\n\n");


	return;
}
