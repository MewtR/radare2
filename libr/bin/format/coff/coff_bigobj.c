/* radare - LGPL - Copyright 2008-2022 pancake, inisider */

#include <r_util.h>
#include <stdbool.h>

#define R_BIN_COFF_BIGOBJ 1
#include "coff.c"

#if 0
#include "coff_bigobj.h"

// copied from bfd
static bool r_coff_bigobj_decode_base64(const char *str, ut32 len, ut32 *res) {
	ut32 i;
	ut32 val;

	val = 0;
	for (i = 0; i < len; i++) {
		char c = str[i];
		ut32 d;
		if (c >= 'A' && c <= 'Z') {
			d = c - 'A';
		} else if (c >= 'a' && c <= 'z') {
			d = c - 'a' + 26;
		} else if (c >= '0' && c <= '9') {
			d = c - '0' + 52;
		} else if (c == '+') {
			d = 62;
		} else if (c == '/') {
			d = 63;
		} else {
			return false;
		}

		/* Check for overflow */
		if ((val >> 26) != 0) {
			return false;
		}

		val = (val << 6) + d;
	}

	*res = val;
	return true;
}

R_IPI char *r_coff_bigobj_symbol_name(RBinCoffBigObj *obj, void *ptr) {
	char n[256] = {0};
	int len = 0;
	ut32 offset = 0; // offset into the string table.
	union {
		char name[8];
		struct {
			ut32 zero;
			ut32 offset;
		};
	} *p = ptr;
	if (!ptr) {
		return NULL;
	}

	if (p->zero && *p->name != '/') {
		return r_str_ndup (p->name, 8);
	} else if (*p->name == '/') {
		char *offset_str = (p->name + 1);
		if (*offset_str == '/') {
			r_coff_bigobj_decode_base64 (p->name + 2, 6, &offset);
		} else {
			offset = atoi (offset_str);
		}
	} else {
		offset = p->offset;
	}

	// Calculate the actual pointer to the symbol/section name we're interested in.
	ut64 name_ptr = obj->hdr.f_symptr + (obj->hdr.f_nsyms * sizeof (struct coff_bigobj_symbol) + offset);
	if (name_ptr > obj->size) {
		return NULL;
	}
	len = r_buf_read_at (obj->b, name_ptr, (ut8 *)n, sizeof (n));
	if (len < 1) {
		return NULL;
	}
	/* ensure null terminated string */
	n[sizeof (n) - 1] = 0;
	return strdup (n);
}

static int r_coff_rebase_sym(RBinCoffBigObj *obj, RBinAddr *addr, struct coff_bigobj_symbol *sym) {
	if (sym->n_scnum < 1 || sym->n_scnum > obj->hdr.f_nscns) {
		return 0;
	}
	addr->paddr = obj->scn_hdrs[sym->n_scnum - 1].s_scnptr + sym->n_value;
	return 1;
}

/* Try to get a valid entrypoint using the methods outlined in
 * http://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC24 */
R_IPI RBinAddr *r_coff_bigobj_get_entry(RBinCoffBigObj *obj) {
	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (!addr) {
		return NULL;
	}

	/* No help from the header eh? Use the address of the symbols '_start'
	 * or 'main' if present */
	if (obj->symbols) {
		int i;
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if ((!strcmp (obj->symbols[i].n_name, "_start") ||
				    !strcmp (obj->symbols[i].n_name, "start")) &&
				r_coff_rebase_sym (obj, addr, &obj->symbols[i])) {
				return addr;
			}
		}
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if ((!strcmp (obj->symbols[i].n_name, "_main") ||
				    !strcmp (obj->symbols[i].n_name, "main")) &&
				r_coff_rebase_sym (obj, addr, &obj->symbols[i])) {
				return addr;
			}
		}
	}
#if 0
	/* Still clueless ? Let's just use the address of .text */
	if (obj->scn_hdrs) {
		for (i = 0; i < obj->hdr.f_nscns; i++) {
			// avoid doing string matching and use x bit from the section
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_EXECUTE) {
				addr->paddr = obj->scn_hdrs[i].s_scnptr;
				return addr;
			}
		}
	}
#else
	free (addr);
	return NULL;
#endif
	return addr;
}

static bool r_bin_coff_bigobj_init_hdr(RBinCoffBigObj *obj) {
	ut16 magic = r_buf_read_le16_at (obj->b, 6);
	switch (magic) {
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_MACHINE_AMD29KBE:
		obj->endian = COFF_IS_BIG_ENDIAN;
		break;
	default:
		obj->endian = COFF_IS_LITTLE_ENDIAN;
	}
	int ret = 0;
	ret = r_buf_fread_at (obj->b, 0, (ut8 *)&obj->hdr, obj->endian? "4S12I": "4s12i", 1);
	if (ret != sizeof (struct coff_bigobj_hdr)) {
		return false;
	}

	// relevant for bigobj?
	if (obj->hdr.f_magic == COFF_FILE_TI_COFF) {
		ret = r_buf_fread (obj->b, (ut8 *)&obj->target_id, obj->endian? "S": "s", 1);
		if (ret != sizeof (ut16)) {
			return false;
		}
	}
	return true;
}

static bool r_bin_coff_bigobj_init_scn_hdr(RBinCoffBigObj *obj) {
	int ret, size;
	ut64 offset = sizeof (struct coff_bigobj_hdr);
	if (obj->hdr.f_magic == COFF_FILE_TI_COFF) {
		offset += 2;
	}
	size = obj->hdr.f_nscns * sizeof (struct coff_scn_hdr);
	if (offset > obj->size || offset + size > obj->size || size < 0) {
		return false;
	}
	obj->scn_hdrs = calloc (1, size + sizeof (struct coff_scn_hdr));
	if (!obj->scn_hdrs) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->scn_hdrs, obj->endian? "8c6I2S1I": "8c6i2s1i", obj->hdr.f_nscns);
	if (ret != size) {
		R_FREE (obj->scn_hdrs);
		return false;
	}
	return true;
}

static bool r_bin_coff_bigobj_init_symtable(RBinCoffBigObj *obj) {
	int ret, size;
	ut64 offset = obj->hdr.f_symptr;
	if (!obj->hdr.f_nsyms) {
		return false;
	}
	size = obj->hdr.f_nsyms * sizeof (struct coff_bigobj_symbol);
	if (size < 0 ||
		size > obj->size ||
		offset > obj->size ||
		offset + size > obj->size) {
		return false;
	}
	obj->symbols = calloc (1, size + sizeof (struct coff_bigobj_symbol));
	if (!obj->symbols) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->symbols, obj->endian? "8c2I1S2c": "8c2i1s2c", obj->hdr.f_nsyms);
	if (ret != size) {
		R_FREE (obj->symbols);
		return false;
	}
	return true;
}

static bool r_bin_coff_init_scn_va(RBinCoffBigObj *obj) {
	obj->scn_va = R_NEWS (ut64, obj->hdr.f_nscns);
	if (!obj->scn_va) {
		return false;
	}
	int i;
	ut64 va = 0;
	for (i = 0; i < obj->hdr.f_nscns; i++) {
		ut64 sz = obj->scn_hdrs[i].s_size;
		if (sz < 16) {
			sz = 16;
		}
		obj->scn_va[i] = va;
		va += sz;
		va = R_ROUND (va, 16ULL);
	}
	return true;
}

static bool r_bin_coff_bigobj_init(RBinCoffBigObj *obj, RBuffer *buf, bool verbose) {
	if (!obj || !buf) {
		return false;
	}
	obj->b = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new0 ();
	obj->imp_ht = ht_up_new0 ();
	if (!r_bin_coff_bigobj_init_hdr (obj)) {
		R_LOG_ERROR ("failed to init coff header");
		return false;
	}

	if (!r_bin_coff_bigobj_init_scn_hdr (obj)) {
		R_LOG_WARN ("failed to init section header");
		return false;
	}

	if (!r_bin_coff_init_scn_va (obj)) {
		R_LOG_WARN ("failed to init section VA table");
		return false;
	}
	if (!r_bin_coff_bigobj_init_symtable (obj)) {
		R_LOG_WARN ("failed to init symtable");
		return false;
	}

	return true;
}

R_IPI void r_bin_coff_bigobj_free(RBinCoffBigObj *obj) {
	if (obj) {
		ht_up_free (obj->sym_ht);
		ht_up_free (obj->imp_ht);
		free (obj->scn_va);
		free (obj->scn_hdrs);
		free (obj->symbols);
		r_buf_free (obj->b);
		free (obj);
	}
}

R_IPI RBinCoffBigObj *r_bin_coff_bigobj_new_buf(RBuffer *buf, bool verbose) {
	RBinCoffBigObj* bin = R_NEW0 (RBinCoffBigObj);
	r_bin_coff_bigobj_init (bin, buf, verbose);
	return bin;
}

#endif
