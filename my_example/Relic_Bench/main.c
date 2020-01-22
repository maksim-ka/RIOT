/*
 * Copyright (C) 2014 Tobias Markmann <tm@ayena.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#define TEST_RELIC_SHOW_OUTPUT (1) /**< set if encoded/decoded string is displayed */

#if (TEST_RELIC_SHOW_OUTPUT == 1)
#include <stdio.h>
#endif
#include <assert.h>
#include <stdlib.h>

#include "relic.h"
#include "embUnit.h"

#include "relic_bench.h"

void print_mem(void *addr, int len)
{
        int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.

            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}

static void setUp(void)
{
        /* Initialize RELIC */
        TEST_ASSERT_EQUAL_INT(STS_OK, core_init());
}

static void tearDown(void)
{
        /* Finalize RELIC */
        core_clean();
}
static void printRSAKey(rsa_t key){
        printf("Modulus n: \n");
        bn_print(key->n);
        printf("Public exponent e: \n");
        bn_print(key->e);
        printf("Private exponent d: \n");
        bn_print(key->d);
        printf("First prime p: \n");
        bn_print(key->p);
        printf("Second prime q: \n");
        bn_print(key->q);
        printf("dp - Inverse of e mod (q-1): \n");
        bn_print(key->dp);
        printf("dq - Inverse of e mod (q-1): \n");
        bn_print(key->dq);
        printf("qi - Inverse of q mod p: \n");
        bn_print(key->qi);
}


static void rsa(void)
{
        rsa_t pub, prv;

        uint8_t plainTXT[13]="Hello World!", 
        newPlainTXT[13], 
        cipherTXT[RELIC_BN_BITS / 8 + 1];
	int plainTXT_len = sizeof(plainTXT), 
        newPlainTXT_len = sizeof(newPlainTXT), 
        cipherTXT_len = RELIC_BN_BITS / 8 + 1; 

        rsa_null(pub);
        rsa_null(prv);

        rsa_new(pub);
        rsa_new(prv);

        // 	BENCH_ONCE("cp_rsa_gen", cp_rsa_gen(pub, prv, RELIC_BN_BITS));
        
        
        TEST_ASSERT_EQUAL_INT(STS_OK, cp_rsa_gen(pub,prv,RELIC_BN_BITS));
        
        printf("rsa User A\n");
        printf("======\n");
        printf("\nprivate key: \n");
        printRSAKey(prv);
        printf("\npublic key:  \n");
        printRSAKey(pub);
        printf("\n");

        printf("Plaintext m:\n");

        print_mem(plainTXT,plainTXT_len);

        TEST_ASSERT_EQUAL_INT(STS_OK, cp_rsa_enc(cipherTXT, &cipherTXT_len, plainTXT, plainTXT_len, pub));

        printf("Encrypted Message m -> Enc(pub, m) = c:\n");
        print_mem(cipherTXT,cipherTXT_len);
        printf("\nDecrypting Message c...\n");
        
        TEST_ASSERT_EQUAL_INT(STS_OK, cp_rsa_dec(newPlainTXT, &newPlainTXT_len, cipherTXT,cipherTXT_len, prv));

        printf("Decrypted Message c -> Dec(prv, c) = m:\n");
        print_mem(newPlainTXT,newPlainTXT_len);

        core_get()->total=0;															\
	util_print("BENCH: %*c = ", (int)(32 - strlen("cp_rsa_gen_basic")), ' ');
       // TEST_ASSERT_EQUAL_INT(STS_OK, memcmp(in, out, ol));
        // 	BENCH_BEGIN("cp_rsa_enc") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_enc(out, &out_len, in, sizeof(in), pub));
        // 		cp_rsa_dec(new, &new_len, out, out_len, prv);
        // 	} BENCH_END;

        // 	BENCH_BEGIN("cp_rsa_dec") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
        // 		BENCH_ADD(cp_rsa_dec(new, &new_len, out, out_len, prv));
        // 	} BENCH_END;

        // #if CP_RSA == BASIC || !defined(STRIP)
        // 	BENCH_ONCE("cp_rsa_gen_basic", cp_rsa_gen_basic(pub, prv, RELIC_BN_BITS));

        // 	BENCH_BEGIN("cp_rsa_dec_basic") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len =out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
        // 		BENCH_ADD(cp_rsa_dec_basic(new, &new_len, out, out_len, prv));
        // 	} BENCH_END;
        // #endif

        // #if CP_RSA == QUICK || !defined(STRIP)
        // 	BENCH_ONCE("cp_rsa_gen_quick", cp_rsa_gen_quick(pub, prv, RELIC_BN_BITS));

        // 	BENCH_BEGIN("cp_rsa_dec_quick") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len =out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
        // 		BENCH_ADD(cp_rsa_dec_quick(new, &new_len, out, out_len, prv));
        // 	} BENCH_END;
        // #endif

        // 	BENCH_ONCE("cp_rsa_gen", cp_rsa_gen(pub, prv, RELIC_BN_BITS));

        // 	BENCH_BEGIN("cp_rsa_sig (h = 0)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv));
        // 	} BENCH_END;

        // 	BENCH_BEGIN("cp_rsa_sig (h = 1)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		md_map(h, in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_sig(out, &out_len, h, MD_LEN, 1, prv));
        // 	} BENCH_END;

        // 	BENCH_BEGIN("cp_rsa_ver (h = 0)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv);
        // 		BENCH_ADD(cp_rsa_ver(out, out_len, in, sizeof(in), 0, pub));
        // 	} BENCH_END;

        // 	BENCH_BEGIN("cp_rsa_ver (h = 1)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		md_map(h, in, sizeof(in));
        // 		cp_rsa_sig(out, &out_len, h, MD_LEN, 1, prv);
        // 		BENCH_ADD(cp_rsa_ver(out, out_len, h, MD_LEN, 1, pub));
        // 	} BENCH_END;

        // #if CP_RSA == BASIC || !defined(STRIP)
        // 	BENCH_ONCE("cp_rsa_gen_basic", cp_rsa_gen_basic(pub, prv, RELIC_BN_BITS));

        // 	BENCH_BEGIN("cp_rsa_sig_basic (h = 0)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_sig_basic(out, &out_len, in, sizeof(in), 0, prv));
        // 	} BENCH_END;

        // 	BENCH_BEGIN("cp_rsa_sig_basic (h = 1)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		md_map(h, in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_sig_basic(out, &out_len, h, MD_LEN, 1, prv));
        // 	} BENCH_END;
        // #endif

        // #if CP_RSA == QUICK || !defined(STRIP)
        // 	BENCH_ONCE("cp_rsa_gen_quick", cp_rsa_gen_quick(pub, prv, RELIC_BN_BITS));

        // 	BENCH_BEGIN("cp_rsa_sig_quick (h = 0)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_sig_quick(out, &out_len, in, sizeof(in), 0, prv));
        // 	} BENCH_END;

        // 	BENCH_BEGIN("cp_rsa_sig_quick (h = 1)") {
        // 		out_len = RELIC_BN_BITS / 8 + 1;
        // 		new_len = out_len;
        // 		rand_bytes(in, sizeof(in));
        // 		md_map(h, in, sizeof(in));
        // 		BENCH_ADD(cp_rsa_sig_quick(out, &out_len, in, sizeof(in), 1, prv));
        // 	} BENCH_END;
        // #endif

        // 	rsa_free(pub);
        // 	rsa_free(prv);
}

static void tests_relic_ecdh(void)
{
        /*  The following is an example for doing an elliptic-curve Diffie-Hellman
        key exchange.
    */

        /* Select an elliptic curve configuration */
        if (ec_param_set_any() == STS_OK)
        {
#if (TEST_RELIC_SHOW_OUTPUT == 1)
                ec_param_print();
#endif

                bn_t privateA;
                ec_t publicA;
                uint8_t sharedKeyA[MD_LEN];

                bn_t privateB;
                ec_t publicB;
                uint8_t sharedKeyB[MD_LEN];

                bn_null(privateA);
                ec_null(publicA);

                bn_new(privateA);
                ec_new(publicA);

                bn_null(privateB);
                ec_null(publicB);

                bn_new(privateB);
                ec_new(publicB);

                /* User A generates private/public key pair */
                TEST_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_gen(privateA, publicA));

#if (TEST_RELIC_SHOW_OUTPUT == 1)
                printf("User A\n");
                printf("======\n");
                printf("private key: \n");
                bn_print(privateA);
                printf("\npublic key: \n");
                ec_print(publicA);
                printf("\n");
#endif

                /* User B generates private/public key pair */
                TEST_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_gen(privateB, publicB));

#if (TEST_RELIC_SHOW_OUTPUT == 1)
                printf("User B\n");
                printf("======\n");
                printf("private key: \n");
                bn_print(privateB);
                printf("\npublic key: \n");
                ec_print(publicB);
                printf("\n");
#endif

                /* In a protocol you would exchange the public keys now */

                /* User A calculates shared secret */
                TEST_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_key(sharedKeyA, MD_LEN, privateA, publicB));

#if (TEST_RELIC_SHOW_OUTPUT == 1)
                printf("\nshared key computed by user A: \n");
                print_mem(sharedKeyA, MD_LEN);
#endif

                /* User B calculates shared secret */
                TEST_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_key(sharedKeyB, MD_LEN, privateB, publicA));

#if (TEST_RELIC_SHOW_OUTPUT == 1)
                printf("\nshared key computed by user B: \n");
                print_mem(sharedKeyB, MD_LEN);
#endif

                /* The secrets should be the same now */
                TEST_ASSERT_EQUAL_INT(CMP_EQ, util_cmp_const(sharedKeyA, sharedKeyB, MD_LEN));

                bn_free(privateA);
                ec_free(publicA);

                bn_free(privateB);
                ec_free(publicB);
#if (TEST_RELIC_SHOW_OUTPUT == 1)
                printf("\nRELIC EC-DH test successful\n");
#endif
        }
        rsa();
}

TestRef tests_relic(void)
{
        EMB_UNIT_TESTFIXTURES(fixtures){
            new_TestFixture(tests_relic_ecdh)};

        EMB_UNIT_TESTCALLER(RELICTest, setUp, tearDown, fixtures);
        return (TestRef)&RELICTest;
}

int main(void)
{
        TESTS_START();
        TESTS_RUN(tests_relic());
        TESTS_END();

        return 0;
}
