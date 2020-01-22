/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Relic Hello World application
 *
 * @author      Max Pengrin <max.pengrin@hft-stuttgart.de
 *
 * @}
 */

#include <stdio.h>
#include <assert.h>
#include "relic.h"
#include "relic_bench.h"

static void rsa(void) {
	rsa_t pub, prv;
	uint8_t in[10], new[10], h[MD_LEN], out[RELIC_BN_BITS / 8 + 1];
	int out_len, new_len;

	rsa_null(pub);
	rsa_null(prv);

	rsa_new(pub);
	rsa_new(prv);

	BENCH_ONCE("cp_rsa_gen", cp_rsa_gen(pub, prv, RELIC_BN_BITS));

	BENCH_BEGIN("cp_rsa_enc") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_enc(out, &out_len, in, sizeof(in), pub));
		cp_rsa_dec(new, &new_len, out, out_len, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_dec") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec(new, &new_len, out, out_len, prv));
	} BENCH_END;

#if CP_RSA == BASIC || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_basic", cp_rsa_gen_basic(pub, prv, RELIC_BN_BITS));

	BENCH_BEGIN("cp_rsa_dec_basic") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len =out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec_basic(new, &new_len, out, out_len, prv));
	} BENCH_END;
#endif

#if CP_RSA == QUICK || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_quick", cp_rsa_gen_quick(pub, prv, RELIC_BN_BITS));

	BENCH_BEGIN("cp_rsa_dec_quick") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len =out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec_quick(new, &new_len, out, out_len, prv));
	} BENCH_END;
#endif

	BENCH_ONCE("cp_rsa_gen", cp_rsa_gen(pub, prv, RELIC_BN_BITS));

	BENCH_BEGIN("cp_rsa_sig (h = 0)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_sig (h = 1)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, h, MD_LEN, 1, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_ver (h = 0)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv);
		BENCH_ADD(cp_rsa_ver(out, out_len, in, sizeof(in), 0, pub));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_ver (h = 1)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		cp_rsa_sig(out, &out_len, h, MD_LEN, 1, prv);
		BENCH_ADD(cp_rsa_ver(out, out_len, h, MD_LEN, 1, pub));
	} BENCH_END;

#if CP_RSA == BASIC || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_basic", cp_rsa_gen_basic(pub, prv, RELIC_BN_BITS));

	BENCH_BEGIN("cp_rsa_sig_basic (h = 0)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_basic(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_sig_basic (h = 1)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_basic(out, &out_len, h, MD_LEN, 1, prv));
	} BENCH_END;
#endif

#if CP_RSA == QUICK || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_quick", cp_rsa_gen_quick(pub, prv, RELIC_BN_BITS));

	BENCH_BEGIN("cp_rsa_sig_quick (h = 0)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_quick(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_sig_quick (h = 1)") {
		out_len = RELIC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_quick(out, &out_len, in, sizeof(in), 1, prv));
	} BENCH_END;
#endif

	rsa_free(pub);
	rsa_free(prv);
}

static void benaloh(void) {
	bdpe_t pub, prv;
	dig_t in, new;
	uint8_t out[RELIC_BN_BITS / 8 + 1];
	int out_len;

	bdpe_null(pub);
	bdpe_null(prv);

	bdpe_new(pub);
	bdpe_new(prv);

	BENCH_ONCE("cp_bdpe_gen", cp_bdpe_gen(pub, prv, bn_get_prime(47), RELIC_BN_BITS));

	BENCH_BEGIN("cp_bdpe_enc") {
		out_len = RELIC_BN_BITS / 8 + 1;
		rand_bytes(out, 1);
		in = out[0] % bn_get_prime(47);
		BENCH_ADD(cp_bdpe_enc(out, &out_len, in, pub));
		cp_bdpe_dec(&new, out, out_len, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_bdpe_dec") {
		out_len = RELIC_BN_BITS / 8 + 1;
		rand_bytes(out, 1);
		in = out[0] % bn_get_prime(47);
		cp_bdpe_enc(out, &out_len, in, pub);
		BENCH_ADD(cp_bdpe_dec(&new, out, out_len, prv));
	} BENCH_END;

	bdpe_free(pub);
	bdpe_free(prv);
}

static void paillier(void) {
	bn_t n, l;
	uint8_t in[1000], new[1000], out[RELIC_BN_BITS / 8 + 1];
	int in_len, out_len;

	bn_null(n);
	bn_null(l);

	bn_new(n);
	bn_new(l);

	BENCH_ONCE("cp_phpe_gen", cp_phpe_gen(n, l, RELIC_BN_BITS / 2));

	BENCH_BEGIN("cp_phpe_enc") {
		in_len = bn_size_bin(n);
		out_len = RELIC_BN_BITS / 8 + 1;
		memset(in, 0, sizeof(in));
		rand_bytes(in + 1, in_len - 1);
		BENCH_ADD(cp_phpe_enc(out, &out_len, in, in_len, n));
		cp_phpe_dec(new, in_len, out, out_len, n, l);
	} BENCH_END;

	BENCH_BEGIN("cp_phpe_dec") {
		in_len = bn_size_bin(n);
		out_len = RELIC_BN_BITS / 8 + 1;
		memset(in, 0, sizeof(in));
		rand_bytes(in + 1, in_len - 1);
		cp_phpe_enc(out, &out_len, in, in_len, n);
		BENCH_ADD(cp_phpe_dec(new, in_len, out, out_len, n, l));
	} BENCH_END;

	bn_free(n);
	bn_free(l);
}

static void sokaka(void) {
	sokaka_t k;
	bn_t s;
	uint8_t key1[MD_LEN];
	char id_a[5] = { 'A', 'l', 'i', 'c', 'e' };
	char id_b[3] = { 'B', 'o', 'b' };

	sokaka_null(k);

	sokaka_new(k);
	bn_new(s);

	BENCH_BEGIN("cp_sokaka_gen") {
		BENCH_ADD(cp_sokaka_gen(s));
	}
	BENCH_END;

	BENCH_BEGIN("cp_sokaka_gen_prv") {
		BENCH_ADD(cp_sokaka_gen_prv(k, id_b, sizeof(id_b), s));
	}
	BENCH_END;

	BENCH_BEGIN("cp_sokaka_key (g1)") {
		BENCH_ADD(cp_sokaka_key(key1, MD_LEN, id_b, sizeof(id_b), k, id_a,
						sizeof(id_a)));
	}
	BENCH_END;

	if (pc_map_is_type3()) {
		cp_sokaka_gen_prv(k, id_a, sizeof(id_a), s);

		BENCH_BEGIN("cp_sokaka_key (g2)") {
			BENCH_ADD(cp_sokaka_key(key1, MD_LEN, id_a, sizeof(id_a), k, id_b,
							sizeof(id_b)));
		}
		BENCH_END;
	}

	sokaka_free(k);
	bn_free(s);
}

static void ibe(void) {
	bn_t s;
	g1_t pub;
	g2_t prv;
	uint8_t in[10], out[10 + 2 * FP_BYTES + 1];
	char id[5] = { 'A', 'l', 'i', 'c', 'e' };
	int in_len, out_len;

	bn_null(s);
	g1_null(pub);
	g2_null(prv);

	bn_new(s);
	g1_new(pub);
	g2_new(prv);

	rand_bytes(in, sizeof(in));

	BENCH_BEGIN("cp_ibe_gen") {
		BENCH_ADD(cp_ibe_gen(s, pub));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ibe_gen_prv") {
		BENCH_ADD(cp_ibe_gen_prv(prv, id, sizeof(id), s));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ibe_enc") {
		in_len = sizeof(in);
		out_len = in_len + 2 * FP_BYTES + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_ibe_enc(out, &out_len, in, in_len, id, sizeof(id), pub));
		cp_ibe_dec(out, &out_len, out, out_len, prv);
	}
	BENCH_END;

	BENCH_BEGIN("cp_ibe_dec") {
		in_len = sizeof(in);
		out_len = in_len + 2 * FP_BYTES + 1;
		rand_bytes(in, sizeof(in));
		cp_ibe_enc(out, &out_len, in, in_len, id, sizeof(id), pub);
		BENCH_ADD(cp_ibe_dec(out, &out_len, out, out_len, prv));
	}
	BENCH_END;

	bn_free(s);
	g1_free(pub);
	g2_free(prv);
}
/*
static int subtraction(void) {
	int code = STS_ERR;
	int s;
	bn_t a, b, c, d;

	bn_null(a);
	bn_null(b);
	bn_null(c);


	bn_rand(a, BN_POS, RELIC_BN_BITS);
	bn_sub(c, a, a);
	assert(bn_is_zero(c));

	code = STS_OK;

	bn_free(a);
	bn_free(b);
	bn_free(c);
	bn_free(d);
	return code;
}
*/

int main(void)
{
	//core_init();
	//subtraction();

	puts("Relic libary says: \"Hello World!\"");

	printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
	printf("This board features a(n) %s MCU.\n", RIOT_MCU);
	if (core_init() != STS_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

	util_banner("Protocols based on integer factorization:\n", 0);
	rsa();
	benaloh();
	paillier();

	util_banner("Protocols based on pairings:\n", 0);
	if (pc_param_set_any() == STS_OK) {
		sokaka();
		ibe();
	} else {
		THROW(ERR_NO_CURVE);
	}

	core_clean();
	return 0;
}
