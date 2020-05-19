#include"CTR_DRBG.h"

//길이 len만큼 두 배열을 비교하는 함수입니다.
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
//유도함수에서 사용되는 입력데이터를 128비트의 배수로 맞춰주기위한 패딩함수입니다.
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
//유도함수에서 사용되는 CBC_MAC 함수입니다.
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
//CTR_DRBG에서 사용되는 유도함수입니다.
void CTR_df(CTR_DRBG* state, BYTE* seed_material, BYTE* seed) {
	int len = state->Entropylen + state->Noncelen + state->perStringlen + 16 + 8 + 1;
	//총 입력데이터의 길이를 의미합니다.
	int len2 = state->Entropylen + state->Noncelen + state->perStringlen;
	//엔트로피 난스 추가입력데이터의 길이의 합을 의미합니다.
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

	//0~15 까지 처음 0,0,0,0 은 카운터 , 나머지는 0 패딩


	//TEMP 인덱스 16 17 18 19 -> 입력데이터의 바이트 길이  20,21,22,23 -> 출력데이터의 바이트 길이 : 32
	TEMP[19] = len2;
	TEMP[23] = 32;

	//그 후 뒤에는 seed_material로 구성됩니다.
	for (cnt_i = 0; cnt_i < len2; cnt_i++) {

		TEMP[cnt_i + 24] = seed_material[cnt_i];

	}
	//마지막에 0x80을 추가합니다.
	TEMP[cnt_i + 24] = 0x80;
	//128bit의 배수로 맞춰주기위해 패딩을 합니다.
	len = padding(&TEMP, len); // len은 바이트 길이로써 16으로 나누게 되면 CBC-MAC의 횟수가 나오게 됩니다.



	len = len / 16;

	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}
	//ARIA Encrpyt 초기 암호화 과정의 경우 CBC_MAC과정에서 XOR가 들어가지 않으므로 따로 처리하였습니다.
	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);

	//CBC MAC 과정입니다.
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

	//CBC_MAC을 총 2번 적용합니다.
	TEMP[3] = 1; // counter 증가

	cnt_k = 0;
	//초기 암호화
	for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
		TEMP2[cnt_j] = TEMP[cnt_k];
		cnt_k++;
	}

	Crypt(TEMP2, EncKeySetup(KEY, rk, 128), rk, IV);
	//CBC_MAC 과정입니다.
	for (cnt_i = 1; cnt_i < len; cnt_i++) {
		for (cnt_j = 0; cnt_j < ARIA_BLOCK_SIZE; cnt_j++) {
			TEMP2[cnt_j] = TEMP[cnt_k];
			cnt_k++;
		}
		CBC_MAC(TEMP2, IV, result);
		memcpy(IV, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);
	}
	memcpy(state->V, result, sizeof(BYTE) * ARIA_BLOCK_SIZE);




	//암호화
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
//Generate함수에서 Additional 데이터만 입력으로 받아 유도함수를 진행하는데 그때 사용하는 함수입니다.
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

	//0~15 까지 처음 0,0,0,0 은 카운터 , 나머지는 0 패딩


	//16 17 18 19 -> 입력데이터의 바이트 길이  20,21,22,23 -> 출력데이터의 바이트 길이 : 32
	TEMP[19] = len2;
	TEMP[23] = 32;

	for (cnt_i = 0; cnt_i < len2; cnt_i++) {

		TEMP[cnt_i + 24] = seed_material[cnt_i];

	}

	TEMP[cnt_i + 24] = 0x80;

	len = padding(&TEMP, len); // len은 바이트 길이로써 16으로 나누게 되면 CBC-MAC의 횟수가 나오게 됩니다.


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




	//암호화
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
//Reseed함수에서 엔트로피입력과 추가입력의 값을 받아 유도함수를 사용하는데 그때 사용하는 함수입니다.
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

	//0~15 까지 처음 0,0,0,0 은 카운터 , 나머지는 0 패딩


	//16 17 18 19 -> 입력데이터의 바이트 길이  20,21,22,23 -> 출력데이터의 바이트 길이 : 32
	TEMP[19] = len2;
	TEMP[23] = 32;

	for (cnt_i = 0; cnt_i < len2; cnt_i++) {

		TEMP[cnt_i + 24] = seed_material[cnt_i];

	}

	TEMP[cnt_i + 24] = 0x80;

	len = padding(&TEMP, len); // len은 바이트 길이로써 16으로 나누게 되면 CBC-MAC의 횟수가 나오게 됩니다.


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




	//암호화
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
//Reseed 함수 입니다.
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
	//가장 먼저 엔트로피와 추가입력데이터를 합칩니다.
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
	//유도함수
	CTR_df_2(state, TEMP, seed);

	//내부갱신함수
	update(state, result);

	//위의 두 결과 값 XOR
	for (cnt_i = 0; cnt_i < 32; cnt_i++) {
		seed[cnt_i] ^= result[cnt_i];
	}
	//최종 V,C update
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		state->C[cnt_i] = seed[cnt_i];
	}
	for (cnt_i = 16; cnt_i < 32; cnt_i++) {
		state->V[cnt_i - 16] = seed[cnt_i];
	}


	return;

}
//배열에서 캐리를 고려하는 덧셈 함수입니다.
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
//내부갱신함수입니다.
void update(CTR_DRBG* state, BYTE* seed) {
	Byte TEMP[16] = { 0x00, };
	Byte TEMP2[16] = { 0x00, };
	//V를 복사합니다.
	memcpy(TEMP, state->V, ARIA_BLOCK_SIZE * sizeof(BYTE));
	Byte rk[16 * 17];
	int cnt_i = 0;
	int cnt_j = 0;
	//V에 1을 더합니다.
	CTR_ADD_2(TEMP, 16);
	//ARIA 암호화를 진행합니다.
	Crypt(TEMP, EncKeySetup(state->C, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_j] = TEMP2[cnt_i];
		cnt_j++;
	}
	//V에 1을 더합니다.
	CTR_ADD_2(TEMP, 16);
	//ARIA 암호화를 진행합니다.
	Crypt(TEMP, EncKeySetup(state->C, rk, 128), rk, TEMP2);
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		seed[cnt_j] = TEMP2[cnt_i];
		cnt_j++;
	}


	return;

}
//Generate함수입니다.
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
	//리시드 카운터가 리시드 인터벌보다 클 경우나 예측내성이 켜져있는 경우 리시드 함수를 진행합니다.
	if ((Compare2(reseed_interval, state->reseed_counter, ARIA_BLOCK_SIZE) == RightBigger) || (state->prediction_resistance_flag == ON)) {

		CTR_Reseed_Function(state, Entropy, additionaldata);
	}
	else if (additionaldata != NULL) {
		//추가입력데이터가 NULL이 아닐 경우
		//유도함수
		CTR_df_3(state, additionaldata, seed);
		//내부갱신함수
		update(state, seed2);
		//위의 두 결과값 XOR를 통해 v,c 업데이트를 진행합니다.
		for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
			state->C[cnt_i] = seed[cnt_i] ^ seed2[cnt_i];
		}
		for (cnt_i = ARIA_BLOCK_SIZE; cnt_i < ARIA_BLOCK_SIZE + ARIA_BLOCK_SIZE; cnt_i++) {
			state->V[cnt_i - 16] = seed[cnt_i] ^ seed2[cnt_i];
		}

	}
	//추가입력데이터가 NULL인 경우는 내부갱신을 하지 않고 난수열을 출력합니다.
	CTR_ADD_2(state->V, 16);

	Crypt(state->V, EncKeySetup(state->C, rk, 128), rk, Randombit);
	printf("Randombit = ");
	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		printf("%X ", Randombit[cnt_i]);
	}printf("\n\n");

	//난수열 출력 후 내부갱신함수를 통해 나온 값과 유도함수에서 나온 값을 XOR하여  V와C를 갱신합니다.
	update(state, seed2);

	for (cnt_i = 0; cnt_i < ARIA_BLOCK_SIZE; cnt_i++) {
		state->C[cnt_i] = seed[cnt_i] ^ seed2[cnt_i];
	}
	for (cnt_i = ARIA_BLOCK_SIZE; cnt_i < ARIA_BLOCK_SIZE + ARIA_BLOCK_SIZE; cnt_i++) {
		state->V[cnt_i - 16] = seed[cnt_i] ^ seed2[cnt_i];
	}



	return;
}
//인스턴스 생성함수입니다.
void CTR_Instantiate_Function(CTR_DRBG* state, BYTE* Entropy, BYTE* Nonce, BYTE* perString) {
	int len = state->Entropylen + state->Noncelen + state->perStringlen;
	//길이정보=엔트로피길이+난스길이+개별화문자열길이

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

	// seed_material 생성
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
	//유도함수
	CTR_df(state, seed_material, seed);


	//초기 KEY=0, V=0으로 V와C를 갱신합니다.
	//V+1
	CTR_ADD_2(TEMP, 16);
	//V+1 암호화
	Crypt(TEMP, EncKeySetup(KEY, rk, 128), rk, TEMP2);

	//암호화된 값을 result에 저장합니다.
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		result[cnt_i] = TEMP2[cnt_i];
	}
	//V+2
	CTR_ADD_2(TEMP, 16);

	//V+2암호화
	Crypt(TEMP, EncKeySetup(KEY, rk, 128), rk, TEMP2);

	//암호화된 값을 result에 저장합니다.
	for (cnt_i = 0; cnt_i < 16; cnt_i++) {
		result[cnt_i + 16] = TEMP2[cnt_i];
	}


	//유도함수를 통해 나온 값과 XOR, 최종적으로 V와 C를 업데이트 합니다.
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



//초기 CTR_DRBG 구조체의 값을 초기화하기 위한 함수입니다.
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
//FILE_READ_INIT 함수를 통해 길이정보를 가져오면 아래의 함수를 통해 실제 메모리를 할당해주거나 NULL로 만들어주는 함수입니다.
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
//CTR_DRBG 함수입니다.
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

//CTR_DRBG의 초기 길이정보를 읽어오기위한 함수입니다.
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

	//바이트 길이
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
//예측내성이 OFF되었을때 엔트로피 난스 개별화문자열 등의 정보를 읽어오기위한 함수입니다.
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
	//추가데이터

	fscanf(fp, "%s = ", test);
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			additionaldata[cnt_i] = (BYTE)temp;
		}
	}
	//리시드 엔트로피
	fscanf(fp, "%s = ", test);
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		EntropyReseed[cnt_i] = (BYTE)temp;
	}
	//리시드 추가데이터
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

//초기 길이정보와 예측내성 정보를 파일에 쓰는 함수입니다.
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
//예측내성이 꺼졌을 때 엔트로피, 난스, 개별화문자열, 난수열 등의 정보를 파일에 쓰는 함수입니다.
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

//예측내성이 켜졌을 때 엔트로피 난스 개별화문자열 난수열 등의 정보를 파일에 쓰는 함수입니다.
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


//예측내성이 켜졌을 때 엔트로피, 난스, 개별화문자열 등의 정보를 파일에서 읽어오기위한 함수입니다.
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
	//추가데이터

	fscanf(fp, "%s = ", test);
	if (additionaldata != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			fscanf(fp, "%02X", &temp);
			additionaldata[cnt_i] = (BYTE)temp;
		}
	}
	//리시드 엔트로피
	fscanf(fp, "%s = ", test);
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		fscanf(fp, "%02X", &temp);
		EntropyReseed[cnt_i] = (BYTE)temp;
	}
	//리시드 추가데이터2
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
