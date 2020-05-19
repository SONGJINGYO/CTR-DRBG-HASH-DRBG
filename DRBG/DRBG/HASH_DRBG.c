#include"HASH_DRBG.h"
//���� len��ŭ �� �迭�� ���ϴ� �Լ��Դϴ�.
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
//�迭�� 1�� ĳ���� ����Ͽ� ���ϴ� �Լ��Դϴ�.
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
//realloc �Լ� ��� �� �߰��� ������� �޸��� ������ �迭�� �� ��ĭ�� ����°� �װ��� �� ������ 0��° �ε����� �������� ���� �Լ��Դϴ�.
void Rotate2(BYTE* a) {
	int cnt_i = 0;
	BYTE Temp = 0;
	for (cnt_i = SEED_Len + 1; cnt_i >= 0; cnt_i--) {
		a[cnt_i] = a[cnt_i - 1];
	}
	a[0] = 0;
	return;
}
//HASH_DRBG�� �����Լ��Դϴ�.
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
//HASH_DRBG�� �ν��Ͻ� �����Լ��Դϴ�.
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
		//����ȭ���ڿ��� �ȵ��� ��쵵 �־� ���� ���ǹ��� �߰��Ͽ����ϴ�.
		for (cnt_i = 0; cnt_i < state->perStringlen; cnt_i++) {
			seed_material[cnt_j] = PersonalizationString[cnt_i];
			cnt_j++;
		}
	}

	//�����Լ�
	Hash_df(seed, seed_material, seedlen, len);


	//v update
	memcpy(state->V, seed, sizeof(BYTE) * 55);

	//c update
	seed = (BYTE*)realloc(seed, SEED_Len + 1);

	//realloc �� �Ҵ�Ǵ� �޸𸮰����� ���� �� �ε����� ����µ� �װ��� 0��° �ε����� ���� ������������ �Լ��Դϴ�.
	Rotate2(seed);
	seed[0] = 0;
	//�����Լ�
	Hash_df(state->C, seed, seedlen, 56);

	//reseedcounter = 1
	memset(state->reseed_counter, 0, sizeof(BYTE) * RESEED_INTERVAL);
	state->reseed_counter[RESEED_INTERVAL - 1] = 1;
	return;
}
void Reseed_Function(HASH_DRBG* state, BYTE* Entropy, BYTE* additionalinput, int seedlen) {
	//�Էµ����� ��������
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

	//�����Լ�
	Hash_df(seed, Temp, seedlen, len);
	//v date
	memcpy(state->V, seed, sizeof(BYTE) * SEED_Len);

	//�����Լ��� ���� ���� seed���� �� �� �ε����� 0�� �߰��ϱ� ���� realloc�� �ϰ� Rotate2�Լ��� �Ҵ���� �޸��� ��ġ�� �� ������ �����ɴϴ�.
	seed = (BYTE*)realloc(seed, (SEED_Len + 1) * sizeof(BYTE));
	Rotate2(seed);
	seed[0] = 0;
	//�����Լ�
	Hash_df(state->C, seed, seedlen, SEED_Len + 1);

	//Reseed�Լ��� ����Ǿ����� reseed_counter �ʱ�ȭ
	memset(state->reseed_counter, 0, sizeof(BYTE) * RESEED_INTERVAL);
	state->reseed_counter[RESEED_INTERVAL - 1] = 1;


	//additionalInput=NULL// �̹� v��c�� ������Ʈ�Ͽ��� ������ Generate�Լ����� �� �ٽ� v�� c ������Ʈ�� �Ǵ� ���� ���������Դϴ�. 
	additionalinput = NULL;

	return;
}
//Generate �Լ����� ����ü ���ϱⰡ ���µ� ���������� ���� ����ü ������ �ϱ� ���� �Լ��Դϴ�.
void Addition(BYTE* c, BYTE* a, BYTE* b, int len) {
	int carry = 0;
	int carry2 = 0;
	int cnt_i = 0;

	//len 55�� �ƴҶ��� �ؽð��� seed_len(55Byte)�� ���� ���ϱ� ���� �ڵ��Դϴ�.
	if (len != 55) {
		//reverse �Լ��� Addition �Լ��� 0��° �ε������� 0��° �ڸ��� ���� ����� �ǰ� ������µ� ���� �ҽ��ڵ忡�� �ֻ����ڸ��� ���� 0��° �ε����� �Ǿ��־�
		//�ε����� ��ġ�� �����ֱ����� �Լ��Դϴ�.
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
		//��� ���� �� �ٽ� �ε����� ���߾��ݴϴ�.
		reverse(a, 55);

		reverse(b, len);

	}
	else if (len == 55) {
		//55Byte+55Byte�� ���� �ҽ��ڵ��Դϴ�.
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
		//��� ���� �� �ٽ� �ε����� ���߾��ݴϴ�.
		reverse(a, 55);
		reverse(b, 55);
	}
	//���� ��� ���� �ֻ��� �ڸ����� 0��° �ε����� �Ǿ��־� �ٽ� �ڸ��� ���߾��ݴϴ�.
	reverse(c, 55);
	return;

}
//�迭�� �ε����� �������� ���߾��ִ� �Լ��Դϴ�.
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
//Gerate_Function �Լ��Դϴ�.
void Generate_Function(HASH_DRBG* state, BYTE* Randombit, BYTE* Entropy, BYTE* additionaldata, int seedlen, int Randombitlen) {
	int len = SEED_Len + 1 + (state->Additionaldatalen);
	//�Էµ������� len ����(��Ʈ����+�߰��Էµ�����+1)
	BYTE TEMP2[SEED_Len + 1] = { 0x00, };
	BYTE seed[32] = { 0x00, };
	BYTE result[SEED_Len] = { 0x00, };
	BYTE result2[SEED_Len] = { 0x00, };
	BYTE* TEMP = NULL;
	int HASH_len = Randombitlen / 256; // �Լ��� �μ��� ������ ������Ʈ���� �������� ��Ʈ����

	int cnt_i = 0;
	int cnt_j = 0;
	int cnt_k = 0;
	BYTE reseed_interval[RESEED_INTERVAL] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

	TEMP = (BYTE*)calloc(len, sizeof(BYTE));
	//�ܺΰ����Լ� ���� �̻���� ���ǹ����� ���������ϴ�. ���������� �����ְų� ���õ����͹����� ���õ�ī���Ͱ� Ŭ ��� ���õ� �Լ��� ����˴ϴ�.
	if ((Compare(reseed_interval, state->reseed_counter, RESEED_INTERVAL) == RightBigger) || (state->prediction_resistance_flag == ON)) {

		Reseed_Function(state, Entropy, additionaldata, seedlen);
	}
	else if (additionaldata != NULL) {
		//�߰��Էµ����Ͱ� NULL�� �ƴ� ��쿡�� �������Լ��� ������ �ʾұ� ������ V��C�� ������Ʈ�մϴ�.
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

		SHA256_Encrpyt(TEMP, len, seed); // �� 88?? 55(seedlen)+32(hash)+1??= 88 �³�  
									   //  ���� ���� Ȯ�����ؾ��ҵ�..

		memcpy(result, state->V, sizeof(BYTE) * SEED_Len);
		Addition(state->V, result, seed, 32);

	}

	//�������� ����ϱ� ���� �ҽ��ڵ��Դϴ�.
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
	printf("������ ��� : ");
	for (cnt_i = 0; cnt_i < Randombitlen / 8; cnt_i++) {
		printf("%X ", Randombit[cnt_i]);
	}
	printf("\n");
	*/

	//���λ��� V ������Ʈ

	TEMP2[0] = 0x03;
	for (cnt_i = 0; cnt_i < SEED_Len; cnt_i++) {
		TEMP2[cnt_i + 1] = state->V[cnt_i];
	}

	SHA256_Encrpyt(TEMP2, 56, seed);

	//a��ġ�� �õ巣, b��ġ�� �ؽð�

	Addition(result2, state->C, seed, 32);
	memcpy(result, state->V, sizeof(BYTE) * SEED_Len);
	Addition(state->V, result, result2, 55);
	memcpy(result, state->V, sizeof(BYTE) * SEED_Len);

	Addition(state->V, result, state->reseed_counter, RESEED_INTERVAL);


	// reseed_counter +1

	CTR_ADD(state->reseed_counter, RESEED_INTERVAL);


	return;
}
//�ʱ� HASH_DRBG ����ü ���� �ʱ�ȭ�ϱ� ���� �Լ��Դϴ�.
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
//���Ͽ��� �о�� ���������� ���� �޸𸮸� �Ҵ��ϰų� NULL�� ������ִ� �Լ��Դϴ�.
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

//HASH_DRBG �Լ��Դϴ�.
void HASH_DRBG_Function(HASH_DRBG* state, BYTE* Randombit, int Randombitlen, BYTE* Entropy, BYTE* Nonce, BYTE* perString, BYTE* AdditionalData, BYTE* EntropyReseed, BYTE* AdditionalInputReseed, BYTE* AdditionalData2) {
	//���������� �������� ���
	if (state->prediction_resistance_flag == OFF) {
		Instantiate(state, Entropy, Nonce, perString, SEED_Len);

		Generate_Function(state, Randombit, EntropyReseed, AdditionalData, SEED_Len, Randombitlen);

		if (state->prediction_resistance_flag == OFF) {
			Reseed_Function(state, EntropyReseed, AdditionalInputReseed, SEED_Len);
		}
		Generate_Function(state, Randombit, EntropyReseed, AdditionalData2, SEED_Len, Randombitlen);
	}
	//���������� �������� ���
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