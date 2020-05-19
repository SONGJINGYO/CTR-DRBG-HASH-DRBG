#include"HASH_DRBG.h"
//길이 len만큼 두 배열을 비교하는 함수입니다.
int Compare(BYTE* a, BYTE* b, int len) {
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
//배열에 1씩 캐리를 고려하여 더하는 함수입니다.
void CTR_ADD(BYTE* CTR, int len) {
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
//realloc 함수 사용 시 추가로 얻어지는 메모리의 공간이 배열의 맨 뒷칸에 생기는게 그것을 맨 앞으로 0번째 인덱스로 가져오기 위한 함수입니다.
void Rotate2(BYTE* a) {
	int cnt_i = 0;
	BYTE Temp = 0;
	for (cnt_i = SEED_Len + 1; cnt_i >= 0; cnt_i--) {
		a[cnt_i] = a[cnt_i - 1];
	}
	a[0] = 0;
	return;
}
//HASH_DRBG의 유도함수입니다.
void Hash_df(BYTE* seed, BYTE* seed_material, int seedlen, int len) {

	BYTE temp[32] = { 0x00, };
	BYTE temp2[32] = { 0x00, };
	BYTE* state = NULL;
	state = (BYTE*)calloc(len + 5, sizeof(BYTE));

	int cnt_j = 0;
	int cnt_i = 1;
	int cnt_k = 0;


	state[3] = 0x01;
	state[4] = 0xb8;

	for (cnt_j = 0; cnt_j < len; cnt_j++) {
		state[5 + cnt_j] = seed_material[cnt_j];
	}


	state[0] = 1;

	SHA256_Encrpyt(state, _msize(state), temp);

	state[0] = 2;
	SHA256_Encrpyt(state, len + 5, temp2);

	for (cnt_i = 0; cnt_i < 32; cnt_i++) {
		seed[cnt_i] = temp[cnt_i];
	}
	for (cnt_i = 32; cnt_i < 55; cnt_i++) {
		seed[cnt_i] = temp2[cnt_i - 32];
	}

	free(state);
	return;
}
//HASH_DRBG의 인스턴스 생성함수입니다.
void Instantiate(HASH_DRBG* state, BYTE* EntropyInput, BYTE* Nonce, BYTE* PersonalizationString, int seedlen) {

	BYTE* seed_material = NULL;
	int len = state->Entropylen + state->Noncelen + state->perStringlen;
	BYTE* seed = NULL;

	seed_material = (BYTE*)calloc(len, sizeof(BYTE));
	seed = (BYTE*)calloc(SEED_Len, sizeof(BYTE));


	int cnt_i = 0;
	int cnt_j = 0;

	//seed_material=Entropy||Nonce||Personalization
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		seed_material[cnt_j] = EntropyInput[cnt_i];
		cnt_j++;
	}
	for (cnt_i = 0; cnt_i < state->Noncelen; cnt_i++) {
		seed_material[cnt_j] = Nonce[cnt_i];
		cnt_j++;
	}

	if (PersonalizationString != NULL) {
		//개별화문자열이 안들어가는 경우도 있어 위의 조건문을 추가하였습니다.
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			seed_material[cnt_j] = PersonalizationString[cnt_i];
			cnt_j++;
		}
	}

	//유도함수
	Hash_df(seed, seed_material, seedlen, len);


	//v update
	memcpy(state->V, seed, sizeof(BYTE) * 55);

	//c update
	seed = (BYTE*)realloc(seed, SEED_Len + 1);

	//realloc 시 할당되는 메모리공간이 제일 끝 인덱스에 생기는데 그것을 0번째 인덱스로 값을 가져오기위한 함수입니다.
	Rotate2(seed);
	seed[0] = 0;
	//유도함수
	Hash_df(state->C, seed, seedlen, 56);

	//reseedcounter = 1
	memset(state->reseed_counter, 0, sizeof(BYTE) * RESEED_INTERVAL);
	state->reseed_counter[RESEED_INTERVAL - 1] = 1;
	return;
}
void Reseed_Function(HASH_DRBG* state, BYTE* Entropy, BYTE* additionalinput, int seedlen) {
	//입력데이터 길이정보
	int len = SEED_Len + state->Entropylen + state->Additionaldatalen + 1;

	BYTE* Temp = NULL;
	int cnt_i = 0;
	BYTE* seed = NULL;
	seed = (BYTE*)calloc(SEED_Len, sizeof(BYTE));

	Temp = (BYTE*)calloc(len, sizeof(BYTE));
	Temp[0] = 0x01;

	for (cnt_i = 0; cnt_i < SEED_Len; cnt_i++) {
		Temp[cnt_i + 1] = state->V[cnt_i];
	}
	for (cnt_i = 0; cnt_i < state->Entropylen; cnt_i++) {
		Temp[cnt_i + SEED_Len + 1] = Entropy[cnt_i];
	}
	if (additionalinput != NULL) {
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			Temp[cnt_i + SEED_Len + state->Entropylen + 1] = additionalinput[cnt_i];
		}
	}

	//유도함수
	Hash_df(seed, Temp, seedlen, len);
	//v date
	memcpy(state->V, seed, sizeof(BYTE) * SEED_Len);

	//유도함수를 통해 나온 seed값의 맨 앞 인덱스에 0을 추가하기 위해 realloc를 하고 Rotate2함수로 할당받은 메모리의 위치를 맨 앞으로 가져옵니다.
	seed = (BYTE*)realloc(seed, (SEED_Len + 1) * sizeof(BYTE));
	Rotate2(seed);
	seed[0] = 0;
	//유도함수
	Hash_df(state->C, seed, seedlen, SEED_Len + 1);

	//Reseed함수가 수행되었으니 reseed_counter 초기화
	memset(state->reseed_counter, 0, sizeof(BYTE) * RESEED_INTERVAL);
	state->reseed_counter[RESEED_INTERVAL - 1] = 1;


	//additionalInput=NULL// 이미 v와c를 업데이트하였기 때문에 Generate함수에서 또 다시 v와 c 업데이트가 되는 것을 막기위함입니다. 
	additionalinput = NULL;

	return;
}
//Generate 함수에서 유한체 더하기가 들어가는데 길이정보에 따라 유한체 덧셈을 하기 위한 함수입니다.
void Addition(BYTE* c, BYTE* a, BYTE* b, int len) {
	int carry = 0;
	int carry2 = 0;
	int cnt_i = 0;

	//len 55가 아닐때는 해시값과 seed_len(55Byte)의 값을 더하기 위한 코드입니다.
	if (len != 55) {
		//reverse 함수는 Addition 함수가 0번째 인덱스에는 0번째 자리가 들어가서 계산이 되게 만들었는데 저의 소스코드에는 최상위자리의 값이 0번째 인덱스로 되어있어
		//인덱스의 위치를 맞춰주기위한 함수입니다.
		reverse(a, 55);

		reverse(b, len);

		for (cnt_i = 0; cnt_i < len; cnt_i++) {
			carry2 = 0;
			c[cnt_i] = a[cnt_i] + b[cnt_i];
			if (a[cnt_i] > c[cnt_i]) {
				carry2 = 1;
			}
			else if (a[cnt_i] < c[cnt_i]) {
				carry2 = 0;
			}
			c[cnt_i] += carry;
			if (c[cnt_i] < carry) {
				carry2 = 1;
			}
			carry = carry2;
		}
		if (carry == 1) {
			c[cnt_i] = a[cnt_i] + 1;
			cnt_i++;
			for (cnt_i; cnt_i < 55; cnt_i++) {
				c[cnt_i] = a[cnt_i];
			}
		}
		else {
			for (cnt_i; cnt_i < 55; cnt_i++) {
				c[cnt_i] = a[cnt_i];
			}
		}
		//계산 종료 후 다시 인덱스를 맞추어줍니다.
		reverse(a, 55);

		reverse(b, len);

	}
	else if (len == 55) {
		//55Byte+55Byte를 위한 소스코드입니다.
		reverse(a, 55);
		reverse(b, 55);
		for (cnt_i = 0; cnt_i < SEED_Len; cnt_i++) {
			carry2 = 0;
			c[cnt_i] = a[cnt_i] + b[cnt_i];
			if (a[cnt_i] > c[cnt_i]) {
				carry2 = 1;
			}
			else if (a[cnt_i] < c[cnt_i]) {
				carry2 = 0;
			}
			c[cnt_i] += carry;
			if (c[cnt_i] < carry) {
				carry2 = 1;
			}
			carry = carry2;
		}
		//계산 종료 후 다시 인덱스를 맞추어줍니다.
		reverse(a, 55);
		reverse(b, 55);
	}
	//최종 결과 값도 최상위 자리에는 0번째 인덱스로 되어있어 다시 자리를 맞추어줍니다.
	reverse(c, 55);
	return;

}
//배열의 인덱스를 역순으로 맞추어주는 함수입니다.
void reverse(BYTE* a, int len) {
	int cnt_i = 0;
	BYTE TEMP = 0;

	for (cnt_i = 0; cnt_i < len / 2; cnt_i++) {
		TEMP = a[len - 1 - cnt_i];
		a[len - 1 - cnt_i] = a[cnt_i];
		a[cnt_i] = TEMP;
	}

	return;
}
//Gerate_Function 함수입니다.
void Generate_Function(HASH_DRBG* state, BYTE* Randombit, BYTE* Entropy, BYTE* additionaldata, int seedlen, int Randombitlen) {
	int len = SEED_Len + 1 + (state->Additionaldatalen);
	//입력데이터의 len 길이(엔트로피+추가입력데이터+1)
	BYTE TEMP2[SEED_Len + 1] = { 0x00, };
	BYTE seed[32] = { 0x00, };
	BYTE result[SEED_Len] = { 0x00, };
	BYTE result2[SEED_Len] = { 0x00, };
	BYTE* TEMP = NULL;
	int HASH_len = Randombitlen / 256; // 함수의 인수로 들어오는 랜덤비트랜은 난수열의 비트길이

	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	BYTE reseed_interval[RESEED_INTERVAL] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

	TEMP = (BYTE*)calloc(len, sizeof(BYTE));
	//외부갱신함수 사용및 미사용을 조건문으로 나누었습니다. 예측내성이 켜져있거나 리시드인터벌보다 리시드카운터가 클 경우 리시드 함수가 수행됩니다.
	if ((Compare(reseed_interval, state->reseed_counter, RESEED_INTERVAL) == RightBigger) || (state->prediction_resistance_flag == ON)) {

		Reseed_Function(state, Entropy, additionaldata, seedlen);
	}
	else if (additionaldata != NULL) {
		//추가입력데이터가 NULL이 아닌 경우에는 리씨드함수를 지나기 않았기 때문에 V와C를 업데이트합니다.
		TEMP[0] = 0x02;
		cnt_j = 1;
		for (cnt_i = 0; cnt_i < SEED_Len; cnt_i++) {
			TEMP[cnt_j] = state->V[cnt_i];
			cnt_j++;
		}
		for (cnt_i = 0; cnt_i < state->Additionaldatalen; cnt_i++) {
			TEMP[cnt_j] = additionaldata[cnt_i];
			cnt_j++;
		}

		SHA256_Encrpyt(TEMP, len, seed); // 왜 88?? 55(seedlen)+32(hash)+1??= 88 맞네  
									   //  길이 고정 확실히해야할듯..

		memcpy(result, state->V, sizeof(BYTE) * SEED_Len);
		Addition(state->V, result, seed, 32);

	}

	//난수열을 출력하기 위한 소스코드입니다.
	memcpy(result, state->V, sizeof(BYTE) * SEED_Len);
	for (cnt_i = 0; cnt_i < HASH_len; cnt_i++) {
		SHA256_Encrpyt(result, SEED_Len, seed);
		for (cnt_j = 0; cnt_j < 32; cnt_j++) {
			Randombit[cnt_k] = seed[cnt_j];
			cnt_k++;
		}

		CTR_ADD(result, SEED_Len);
	}
	/*
	printf("난수열 출력 : ");
	for (cnt_i = 0; cnt_i < Randombitlen / 8; cnt_i++) {
		printf("%X ", Randombit[cnt_i]);
	}
	printf("\n");
	*/

	//내부상태 V 업데이트

	TEMP2[0] = 0x03;
	for (cnt_i = 0; cnt_i < SEED_Len; cnt_i++) {
		TEMP2[cnt_i + 1] = state->V[cnt_i];
	}

	SHA256_Encrpyt(TEMP2, 56, seed);

	//a위치는 시드랜, b위치는 해시값

	Addition(result2, state->C, seed, 32);
	memcpy(result, state->V, sizeof(BYTE) * SEED_Len);
	Addition(state->V, result, result2, 55);
	memcpy(result, state->V, sizeof(BYTE) * SEED_Len);

	Addition(state->V, result, state->reseed_counter, RESEED_INTERVAL);


	// reseed_counter +1

	CTR_ADD(state->reseed_counter, RESEED_INTERVAL);


	return;
}
//초기 HASH_DRBG 구조체 값을 초기화하기 위한 함수입니다.
void Set_HASH_DRBG(HASH_DRBG* state) {
	memset((state)->V, 0, 55 * sizeof(BYTE));
	memset((state)->C, 0, 55 * sizeof(BYTE));
	memset((state)->reseed_counter, 0, RESEED_INTERVAL * sizeof(BYTE));
	state->prediction_resistance_flag = OFF;
	state->Additionaldatalen = 0;
	state->Entropylen = 0;
	state->Noncelen = 0;
	state->perStringlen = 0;

	(state)->security_strength = 0;
	(state)->reseed_counter[RESEED_INTERVAL - 1] = 1;

	return;


}
//파일에서 읽어온 길이정보를 통해 메모리를 할당하거나 NULL로 만들어주는 함수입니다.
void Set_Init(HASH_DRBG* state, BYTE** perString, BYTE** AdditionalInput, BYTE** AdditionalEntropy, BYTE** AdditionalDataReseed, BYTE** AdditionalInput2) {
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

//HASH_DRBG 함수입니다.
void HASH_DRBG_Function(HASH_DRBG* state, BYTE* Randombit, int Randombitlen, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* AdditionalData, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* AdditionalData2) {
	//예측내성이 꺼져있을 경우
	if (state->prediction_resistance_flag == OFF) {
		Instantiate(state, Entropy, Nonce, perString, SEED_Len);

		Generate_Function(state, Randombit, EntropyReseed, AdditionalData, SEED_Len, Randombitlen);

		if (state->prediction_resistance_flag == OFF) {
			Reseed_Function(state, EntropyReseed, AdditionalInputReseed, SEED_Len);
		}
		Generate_Function(state, Randombit, EntropyReseed, AdditionalData2, SEED_Len, Randombitlen);
	}
	//예측내성이 켜져있을 경우
	else {
		Instantiate(state, Entropy, Nonce, perString, SEED_Len);

		Generate_Function(state, Randombit, EntropyReseed, AdditionalData, SEED_Len, Randombitlen);

		if (state->prediction_resistance_flag == OFF) {
			Reseed_Function(state, EntropyReseed, AdditionalInputReseed, SEED_Len);
		}
		Generate_Function(state, Randombit, AdditionalData2, AdditionalInputReseed, SEED_Len, Randombitlen);
	}
	printf("Randombit : ");
	int cnt_i = 0;
	for (cnt_i = 0; cnt_i < 32; cnt_i++) {
		printf("%X ", Randombit[cnt_i]);
	}printf("\n\n");

	return;
}