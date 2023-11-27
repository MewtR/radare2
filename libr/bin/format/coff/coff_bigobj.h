/* radare - LGPL - Copyright 2014 Fedor Sakharov <fedor.sakharov@gmail.com> */

#ifndef COFF_BIGOBJ_H
#define COFF_BIGOBJ_H

#if 0
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "coff_specs.h"

typedef struct r_bin_coff_bigobj {
	struct coff_bigobj_hdr hdr;
	struct coff_scn_hdr *scn_hdrs;
	struct coff_bigobj_symbol *symbols;

	ut16 target_id; /* TI COFF specific */

	RBuffer *b;
	size_t size;
	ut8 endian;
	Sdb *kv;
	bool verbose;
	HtUP *sym_ht;
	HtUP *imp_ht;
	ut64 *scn_va;
} RBinCoffBigObj;

R_IPI RBinCoffBigObj *r_bin_coff_bigobj_new_buf(RBuffer *buf, bool verbose);
R_IPI void r_bin_coff_bigobj_free(RBinCoffBigObj *obj);
R_IPI RBinAddr *r_coff_bigobj_get_entry(RBinCoffBigObj *obj);
R_IPI char *r_coff_bigobj_symbol_name(RBinCoffBigObj *obj, void *ptr);
#endif

#endif /* COFF_BIGOBJ_H */
