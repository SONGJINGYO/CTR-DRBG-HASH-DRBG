#include"CTR_DRBG.h"

//���� len��ŭ �� �迭�� ���ϴ� �Լ��Դϴ�.
int Compare2(BYTE* a, BYTE* b, int len) {
	int cnt_i = 0;

	for (cnt_i = len - 1; cnt_i >= 0; cnt_i--) {
		if (a[cnt_i] > b[cnt_i]) {

			return LeftBigger;
		}
		else if (a[cnt_i] < b[cnt_i]) {

			return RightBigger;
		}

	}

	return Same;
}
//�����Լ����� ���Ǵ� �Էµ����͸� 128��Ʈ�� ����� �����ֱ����� �е��Լ��Դϴ�.
int padding(BYTE** state, int len) {
	int paddinglen = 0;
	int cnt_i = 0;

	if (len % 16 == 0) {
		return len;
	}

	else {
		paddinglen = 16 - (len % 16);

		(*state) = (BYTE*)realloc(*state, len + paddinglen);

		for (cnt_i = len; cnt_i < len + paddinglen; cnt_i++) {
			(*state)[cnt_i] = 0;
		}

	}
	return len + paddinglen;
}
//�����Լ����� ���Ǵ� CBC_MAC �Լ��Դϴ�.
void CBC_MAC(BYTE* in, BYTE* IV, BYTE* out) {
	int cnt_i = 0;
	Byte rk[16 * 17];
	BYTE KEY[ARIA_KEY_SIZE] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
	BYTE TEMP[ARIA_BLOCK_SIZE] = { 0x00, };
	memcpy(TEMP, in, sizeof(BYTE) * ARIA_BLOCK_SIZE);

	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		TEMP[cnt_i] ^= IV[cnt_i];
	}
	Crypt(TEMP, EncKeySetup(KEY, rk, 128), rk, out);



	return;
}
//CTR_DRBG���� ���Ǵ� �����Լ��Դϴ�.
void CTR_df(CTR_DRBG* state, BYTE* seed_material, BYTE* seed) {
	int len = state->Entropylen + state->Noncelen + state->perStringlen + 16 + 8 + 1;
	//�� �Էµ������� ���̸� �ǹ��մϴ�.
	int len2 = state->Entropylen + state->Noncelen + state->perStringlen;
	//��Ʈ���� ���� �߰��Էµ������� ������ ���� �ǹ��մϴ�.
	BYTE* TEMP = NULL;
	BYTE TEMP2[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE IV[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE result[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE* TEMP3 = NULL;
	Byte rk[16 * 17];
	BYTE KEY[ARIA_KEY_SIZE] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	int cnt_v = 0;
	TEMP = (BYTE*)calloc(len, sizeof(BYTE));
	TEMP3 = (BYTE*)calloc(len, sizeof(BYTE));

	//0~15 ���� ó�� 0,0,0,0 �� ī���� , �������� 0 �е�


	//TEMP �ε��� 16 17 18 19 -> �Էµ������� ����Ʈ ����  20,21,22,23 -> ��µ������� ����Ʈ ���� : 32
	TEMP[19] = len2;
	TEMP[23] = 32;

	//�� �� �ڿ��� seed_material�� �����˴ϴ�.
	for (cnt_i = 0; cnt_i < len2; cnt_i++) {

		TEMP[cnt_i + 24] = seed_material[cnt_i];

	}
	//�������� 0x80�� �߰��մϴ�.
	TEMP[cnt_i + 24] = 0x80;
	//128bit�� ����� �����ֱ����� �е��� �մϴ�.
	len = padding(&TEMP, len); // len�� ����Ʈ ���̷ν� 16���� ������ �Ǹ� CBC-MAC�� Ƚ���� ������ �˴ϴ�.



	len = len / 16;

	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}
	//ARIA Encrpyt �ʱ� ��ȣȭ ������ ��� CBC_MAC�������� XOR�� ���� �����Ƿ� ���� ó���Ͽ����ϴ�.
	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);

	//CBC MAC �����Դϴ�.
	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	//C update
	memcpy(state->C, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);

	//CBC_MAC�� �� 2�� �����մϴ�.
	TEMP[3] = 1; // counter ����

	cnt_k = 0;
	//�ʱ� ��ȣȭ
	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}

	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);
	//CBC_MAC �����Դϴ�.
	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	memcpy(state->V, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);




	//��ȣȭ
	Crypt(state->V, EncKeySetup(state->C, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_v] = TEMP2[cnt_i];
		cnt_v++;
	}
	Crypt(TEMP2, EncKeySetup(state->C, rk, 128), rk, result);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_v] = result[cnt_i];
		cnt_v++;
	}
	free(TEMP);

	return;
}
//Generate�Լ����� Additional �����͸� �Է����� �޾� �����Լ��� �����ϴµ� �׶� ����ϴ� �Լ��Դϴ�.
void CTR_df_3(CTR_DRBG* state, BYTE* seed_material, BYTE* seed) {
	int len = state->Additionaldatalen + 16 + 8 + 1;
	//Additionallen + 25
	int len2 = state->Additionaldatalen;
	BYTE* TEMP = NULL;
	BYTE TEMP2[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP4[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP5[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE IV[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE result[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE* TEMP3 = NULL;
	Byte rk[16 * 17];
	BYTE KEY[ARIA_KEY_SIZE] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	int cnt_v = 0;
	TEMP = (BYTE*)calloc(len, sizeof(BYTE));
	TEMP3 = (BYTE*)calloc(len, sizeof(BYTE));

	//0~15 ���� ó�� 0,0,0,0 �� ī���� , �������� 0 �е�


	//16 17 18 19 -> �Էµ������� ����Ʈ ����  20,21,22,23 -> ��µ������� ����Ʈ ���� : 32
	TEMP[19] = len2;
	TEMP[23] = 32;

	for (cnt_i = 0; cnt_i < len2; cnt_i++) {

		TEMP[cnt_i + 24] = seed_material[cnt_i];

	}

	TEMP[cnt_i + 24] = 0x80;

	len = padding(&TEMP, len); // len�� ����Ʈ ���̷ν� 16���� ������ �Ǹ� CBC-MAC�� Ƚ���� ������ �˴ϴ�.


	len = len / 16;

	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}

	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);

	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	memcpy(TEMP4, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);


	TEMP[3] = 1; // counter

	cnt_k = 0;

	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}

	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);

	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	memcpy(TEMP5, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);




	//��ȣȭ
	Crypt(TEMP5, EncKeySetup(TEMP4, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_v] = TEMP2[cnt_i];
		cnt_v++;
	}
	Crypt(TEMP2, EncKeySetup(TEMP4, rk, 128), rk, result);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_v] = result[cnt_i];
		cnt_v++;
	}
	free(TEMP);

	return;
}
//Reseed�Լ����� ��Ʈ�����Է°� �߰��Է��� ���� �޾� �����Լ��� ����ϴµ� �׶� ����ϴ� �Լ��Դϴ�.
void CTR_df_2(CTR_DRBG* state, BYTE* seed_material, BYTE* seed) {
	int len = state->Entropylen + state->Additionaldatalen + 16 + 8 + 1;
	int len2 = state->Entropylen + state->Additionaldatalen;
	BYTE* TEMP = NULL;
	BYTE TEMP2[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP4[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP5[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE IV[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE result[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE* TEMP3 = NULL;
	Byte rk[16 * 17];
	BYTE KEY[ARIA_KEY_SIZE] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	int cnt_v = 0;
	TEMP = (BYTE*)calloc(len, sizeof(BYTE));
	TEMP3 = (BYTE*)calloc(len, sizeof(BYTE));

	//0~15 ���� ó�� 0,0,0,0 �� ī���� , �������� 0 �е�


	//16 17 18 19 -> �Էµ������� ����Ʈ ����  20,21,22,23 -> ��µ������� ����Ʈ ���� : 32
	TEMP[19] = len2;
	TEMP[23] = 32;

	for (cnt_i = 0; cnt_i < len2; cnt_i++) {

		TEMP[cnt_i + 24] = seed_material[cnt_i];

	}

	TEMP[cnt_i + 24] = 0x80;

	len = padding(&TEMP, len); // len�� ����Ʈ ���̷ν� 16���� ������ �Ǹ� CBC-MAC�� Ƚ���� ������ �˴ϴ�.


	len = len / 16;

	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}

	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);

	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	memcpy(TEMP4, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);


	TEMP[3] = 1; // counter

	cnt_k = 0;

	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}

	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);

	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	memcpy(TEMP5, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);




	//��ȣȭ
	Crypt(TEMP5, EncKeySetup(TEMP4, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_v] = TEMP2[cnt_i];
		cnt_v++;
	}
	Crypt(TEMP2, EncKeySetup(TEMP4, rk, 128), rk, result);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_v] = result[cnt_i];
		cnt_v++;
	}
	free(TEMP);

	return;
}
//Reseed �Լ� �Դϴ�.
void CTR_Reseed_Function(CTR_DRBG* state, BYTE* Entropy, BYTE* AdditionalData) {
	int len = state->Entropylen + state->Additionaldatalen;
	BYTE* TEMP = NULL;
	TEMP = (BYTE*)calloc(len, sizeof(BYTE));
	BYTE seed[32] = { 0x00, };
	BYTE result[32] = { 0x00, };
	BYTE TEMP2[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP3[ARIA_BLOCK_SIZE] = { 0x00, };
	Byte rk[16 * 17];
	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	//���� ���� ��Ʈ���ǿ� �߰��Էµ����͸� ��Ĩ�ϴ�.
	if (Entropy != NULL) {
		for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
			TEMP[cnt_j] = Entropy[cnt_i];
			cnt_j++;
		}
	}
	if (AdditionalData != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			TEMP[cnt_j] = AdditionalData[cnt_i];
			cnt_j++;
		}
	}
	//�����Լ�
	CTR_df_2(state, TEMP, seed);

	//���ΰ����Լ�
	update(state, result);

	//���� �� ��� �� XOR
	for (cnt_i = 0; cnt_i < 32; cnt_i++) {
		seed[cnt_i] ^= result[cnt_i];
	}
	//���� V,C update
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		state->C[cnt_i] = seed[cnt_i];
	}
	for (cnt_i = 16; cnt_i < 32; cnt_i++) {
		state->V[cnt_i - 16] = seed[cnt_i];
	}


	return;

}
//�迭���� ĳ���� ����ϴ� ���� �Լ��Դϴ�.
void CTR_ADD_2(BYTE* CTR, int len) { //; 
	int cnt_i = 0;
	BYTE* CTR2 = NULL;
	BYTE* out = NULL;

	CTR2 = (BYTE*)calloc(len, sizeof(BYTE));
	out = (BYTE*)calloc(len, sizeof(BYTE));

	CTR2[len - 1] = 0x01;
	int carry = 0;
	memcpy(out, CTR, len * sizeof(BYTE));
	for (cnt_i = len - 1; cnt_i >= 0; cnt_i--) {

		out[cnt_i] = CTR2[cnt_i] + CTR[cnt_i] + carry;
		if (CTR[cnt_i] > out[cnt_i]) {
			carry = 1;
		}
		else {
			carry = 0;
		}
	}


	memcpy(CTR, out, len * sizeof(BYTE));
	free(out);
	free(CTR2);
	return;
}
//���ΰ����Լ��Դϴ�.
void update(CTR_DRBG* state, BYTE* seed) {
	Byte TEMP[16] = { 0x00, };
	Byte TEMP2[16] = { 0x00, };
	//V�� �����մϴ�.
	memcpy(TEMP, state->V, ARIA_BLOCK_SIZE * sizeof(BYTE));
	Byte rk[16 * 17];
	int cnt_i = 0;
	int cnt_j = 0;
	//V�� 1�� ���մϴ�.
	CTR_ADD_2(TEMP, 16);
	//ARIA ��ȣȭ�� �����մϴ�.
	Crypt(TEMP, EncKeySetup(state->C, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_j] = TEMP2[cnt_i];
		cnt_j++;
	}
	//V�� 1�� ���մϴ�.
	CTR_ADD_2(TEMP, 16);
	//ARIA ��ȣȭ�� �����մϴ�.
	Crypt(TEMP, EncKeySetup(state->C, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_j] = TEMP2[cnt_i];
		cnt_j++;
	}


	return;

}
//Generate�Լ��Դϴ�.
void CTR_Generate_Function(CTR_DRBG* state, BYTE* Randombit, BYTE* Entropy, BYTE* additionaldata, int Randombitlen) {
	BYTE reseed_interval[ARIA_BLOCK_SIZE] = { 0xff,0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	BYTE seed[32] = { 0x00, };
	BYTE seed2[32] = { 0x00, };
	BYTE TEMP[16] = { 0x00, };
	BYTE TEMP2[16] = { 0x00, };
	BYTE TEMP3[16] = { 0x00, };
	BYTE TEMP4[16] = { 0x00, };
	Byte rk[16 * 17];
	int cnt_i = 0;
	int cnt_j = 0;
	//���õ� ī���Ͱ� ���õ� ���͹����� Ŭ ��쳪 ���������� �����ִ� ��� ���õ� �Լ��� �����մϴ�.
	if ((Compare2(reseed_interval, state->reseed_counter, ARIA_BLOCK_SIZE) == RightBigger) || (state->prediction_resistance_flag == ON)) {

		CTR_Reseed_Function(state, Entropy, additionaldata);
	}
	else if (additionaldata != NULL) {
		//�߰��Էµ����Ͱ� NULL�� �ƴ� ���
		//�����Լ�
		CTR_df_3(state, additionaldata, seed);
		//���ΰ����Լ�
		update(state, seed2);
		//���� �� ����� XOR�� ���� v,c ������Ʈ�� �����մϴ�.
		for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
			state->C[cnt_i] = seed[cnt_i] ^ seed2[cnt_i];
		}
		for (cnt_i = ARIA_BLOCK_SIZE; cnt_i < ARIA_BLOCK_SIZE + ARIA_BLOCK_SIZE; cnt_i++) {
			state->V[cnt_i - 16] = seed[cnt_i] ^ seed2[cnt_i];
		}

	}
	//�߰��Էµ����Ͱ� NULL�� ���� ���ΰ����� ���� �ʰ� �������� ����մϴ�.
	CTR_ADD_2(state->V, 16);

	Crypt(state->V, EncKeySetup(state->C, rk, 128), rk, Randombit);
	printf("Randombit = ");
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		printf("%X ", Randombit[cnt_i]);
	}printf("\n\n");

	//������ ��� �� ���ΰ����Լ��� ���� ���� ���� �����Լ����� ���� ���� XOR�Ͽ�  V��C�� �����մϴ�.
	update(state, seed2);

	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		state->C[cnt_i] = seed[cnt_i] ^ seed2[cnt_i];
	}
	for (cnt_i = ARIA_BLOCK_SIZE; cnt_i < ARIA_BLOCK_SIZE + ARIA_BLOCK_SIZE; cnt_i++) {
		state->V[cnt_i - 16] = seed[cnt_i] ^ seed2[cnt_i];
	}



	return;
}
//�ν��Ͻ� �����Լ��Դϴ�.
void CTR_Instantiate_Function(CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString) {
	int len = state->Entropylen + state->Noncelen + state->perStringlen;
	//��������=��Ʈ���Ǳ���+��������+����ȭ���ڿ�����

	BYTE* seed_material = NULL;
	BYTE seed[Seed_Bit] = { 0x00, };
	BYTE KEY[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE V_state[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP[ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE result[ARIA_BLOCK_SIZE + ARIA_BLOCK_SIZE] = { 0x00, };
	BYTE TEMP2[ARIA_BLOCK_SIZE] = { 0x00, };
	Byte rk[16 * 17];
	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	seed_material = (BYTE*)calloc(len, sizeof(BYTE));

	// seed_material ����
	if (Entropy != NULL) {
		for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
			seed_material[cnt_j] = Entropy[cnt_i];
			cnt_j++;
		}
	}
	if (Nonce != NULL) {
		for (cnt_i = 0; cnt_i < state->Noncelen; cnt_i++) {
			seed_material[cnt_j] = Nonce[cnt_i];
			cnt_j++;
		}
	}
	if (perString != NULL) {
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			seed_material[cnt_j] = perString[cnt_i];
			cnt_j++;
		}
	}
	//�����Լ�
	CTR_df(state, seed_material, seed);


	//�ʱ� KEY=0, V=0���� V��C�� �����մϴ�.
	//V+1
	CTR_ADD_2(TEMP, 16);
	//V+1 ��ȣȭ
	Crypt(TEMP, EncKeySetup(KEY, rk, 128), rk, TEMP2);

	//��ȣȭ�� ���� result�� �����մϴ�.
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		result[cnt_i] = TEMP2[cnt_i];
	}
	//V+2
	CTR_ADD_2(TEMP, 16);

	//V+2��ȣȭ
	Crypt(TEMP, EncKeySetup(KEY, rk, 128), rk, TEMP2);

	//��ȣȭ�� ���� result�� �����մϴ�.
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		result[cnt_i + 16] = TEMP2[cnt_i];
	}


	//�����Լ��� ���� ���� ���� XOR, ���������� V�� C�� ������Ʈ �մϴ�.
	for (cnt_i = 0; cnt_i < 32; cnt_i++) {
		result[cnt_i] ^= seed[cnt_i];
	}

	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		state->C[cnt_i] = result[cnt_i];
	}
	for (cnt_i = 16; cnt_i < 32; cnt_i++) {
		state->V[cnt_i - 16] = result[cnt_i];
	}


	free(seed_material);

	return;
}



//�ʱ� CTR_DRBG ����ü�� ���� �ʱ�ȭ�ϱ� ���� �Լ��Դϴ�.
void CTR_Set_CTR_DRBG(CTR_DRBG* state) {
	memset((state)->V, 0, 16 * sizeof(BYTE));
	memset((state)->C, 0, 16 * sizeof(BYTE));
	memset((state)->reseed_counter, 0, 16 * sizeof(BYTE));
	state->prediction_resistance_flag = OFF;
	state->Additionaldatalen = 0;
	state->Entropylen = 0;
	state->Noncelen = 0;
	state->perStringlen = 0;

	(state)->reseed_counter[ARIA_BLOCK_SIZE - 1] = 1;

	return;


}
//FILE_READ_INIT �Լ��� ���� ���������� �������� �Ʒ��� �Լ��� ���� ���� �޸𸮸� �Ҵ����ְų� NULL�� ������ִ� �Լ��Դϴ�.
void CTR_Set_Init(CTR_DRBG* state, BYTE** perString, BYTE** AdditionalInput, BYTE** AdditionalEntropy, BYTE** AdditionalDataReseed, BYTE** AdditionalInput2) {
	if (state->perStringlen == 0) {
		(*perString) = NULL;
	}
	else if (state->perStringlen != 0) {
		(*perString) = (BYTE*)calloc(state->perStringlen, sizeof(BYTE));
	}

	if (state->Additionaldatalen == 0) {

		(*AdditionalInput) = NULL;
		(*AdditionalDataReseed) = NULL;
		(*AdditionalInput2) = NULL;
	}
	else if (state->Additionaldatalen != 0) {
		(*AdditionalInput) = (BYTE*)calloc(state->Additionaldatalen, sizeof(BYTE));
		(*AdditionalDataReseed) = (BYTE*)calloc(state->Additionaldatalen, sizeof(BYTE));
		(*AdditionalInput2) = (BYTE*)calloc(state->Additionaldatalen, sizeof(BYTE));
	}


	if (state->Entropylen == 0) {
		(*AdditionalEntropy) = NULL;
	}
	else if (state->Entropylen != 0) {
		(*AdditionalEntropy) = (BYTE*)calloc(state->Entropylen, sizeof(BYTE));
	}


	return;
}
//CTR_DRBG �Լ��Դϴ�.
void CTR_DRBG_Function(CTR_DRBG* state, BYTE* Randombit, int Randombitlen, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* AdditionalData, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* AdditionalData2) {

	int cnt_i = 0;

	if (state->prediction_resistance_flag == OFF) {
		CTR_Instantiate_Function(state, Entropy, Nonce, perString);



		CTR_Generate_Function(state, Randombit, EntropyReseed, AdditionalData, 128);
		if (state->prediction_resistance_flag == OFF) {

			CTR_Reseed_Function(state, EntropyReseed, AdditionalInputReseed);
		}

		CTR_Generate_Function(state, Randombit, AdditionalInputReseed, AdditionalData2, 128);
	}
	else {
		CTR_Instantiate_Function(state, Entropy, Nonce, perString);




		CTR_Generate_Function(state, Randombit, EntropyReseed, AdditionalData, 128);
		if (state->prediction_resistance_flag == OFF) {

			CTR_Reseed_Function(state, EntropyReseed, AdditionalInputReseed);
		}

		CTR_Generate_Function(state, Randombit, AdditionalData2, AdditionalInputReseed, 128);
	}

	return;
}

//CTR_DRBG�� �ʱ� ���������� �о�������� �Լ��Դϴ�.
void File_Read_init_CTR(FILE* fp, CTR_DRBG* state) {

	int temp = 0x00;
	int cnt_i = 0;
	BYTE test3[100] = { 0x00, };
	BYTE test2[100] = { 0x00, };
	BYTE False[5] = { 'F','A','L','S','E' };
	fscanf(fp, "%s %s %s\n", test3, test3, test3);

	fscanf(fp, "%s = %s", test3, test2);

	if (Compare2(test2, False, 5) == Same) {

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

	fscanf(fp, "%s =", test3);
	fscanf(fp, "%d", &temp);
	fscanf(fp, "%s", test3);
	state->Randombitlen = temp / 8;
	return;
}
//���������� OFF�Ǿ����� ��Ʈ���� ���� ����ȭ���ڿ� ���� ������ �о�������� �Լ��Դϴ�.
void File_Read_CTR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2) {
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
};

//�ʱ� ���������� �������� ������ ���Ͽ� ���� �Լ��Դϴ�.
void File_Write_init_CTR(FILE* fp, CTR_DRBG* state) {
	int cnt_i = 0;
	fprintf(fp, "[ARIA-128 use df]\n");
	if (state->prediction_resistance_flag == ON) {
		fprintf(fp, "[PredictionResistance = TRUE]\n");
	}
	else {
		fprintf(fp, "[PredictionResistance = FALSE]\n");
	}
	fprintf(fp, "[EntropyInputLen = %d]\n", state->Entropylen * 8);
	fprintf(fp, "[NonceLen = %d]\n", state->Noncelen * 8);
	fprintf(fp, "[PersonalizationStringLen = %d]\n", state->perStringlen * 8);
	fprintf(fp, "[AdditionalInputLen = %d]\n", state->Additionaldatalen * 8);
	fprintf(fp, "[ReturnedBitsLen = %d]\n\n", state->Randombitlen * 8);
	return;
}
//���������� ������ �� ��Ʈ����, ����, ����ȭ���ڿ�, ������ ���� ������ ���Ͽ� ���� �Լ��Դϴ�.
void File_Write_CTR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* Additionaldata2, BYTE* Randombit) {
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
	for (cnt_i = 0; cnt_i < state->Randombitlen; cnt_i++) {
		fprintf(fp, "%02X", Randombit[cnt_i]);
	}	fprintf(fp, "\n\n");


	return;
}

//���������� ������ �� ��Ʈ���� ���� ����ȭ���ڿ� ������ ���� ������ ���Ͽ� ���� �Լ��Դϴ�.
void File_Write_CTR_PR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2, BYTE* Randombit) {
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
	for (cnt_i = 0; cnt_i < state->Randombitlen; cnt_i++) {
		fprintf(fp, "%02X", Randombit[cnt_i]);
	}	fprintf(fp, "\n\n");


	return;
}


//���������� ������ �� ��Ʈ����, ����, ����ȭ���ڿ� ���� ������ ���Ͽ��� �о�������� �Լ��Դϴ�.
void File_Read_CTR_PR(FILE* fp, CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* additionaldata, BYTE* EntropyReseed, BYTE* additionaldata2, BYTE* EntropyReseed2) {
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
