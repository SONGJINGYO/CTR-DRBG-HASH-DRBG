
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<assert.h>

#define ARIA_BLOCK_SIZE 16
#define ARIA_KEY_SIZE 16

#pragma once

typedef unsigned char Byte;
typedef unsigned char BYTE;


void DL(const Byte* i, Byte* o);
void RotXOR(const Byte* s, int n, Byte* t);
void printBlock(Byte* b);
int EncKeySetup(const Byte* w0, Byte* e, int keyBits);
int DecKeySetup(const Byte* w0, Byte* d, int keyBits);
void Crypt(const Byte* p, int R, const Byte* e, Byte* c);
void printBlockOfLength(Byte* b, int len);

