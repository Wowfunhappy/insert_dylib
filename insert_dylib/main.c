#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <copyfile.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define IS_64_BIT(x) ((x) == MH_MAGIC_64 || (x) == MH_CIGAM_64)
#define IS_LITTLE_ENDIAN(x) ((x) == FAT_CIGAM || (x) == MH_CIGAM_64 || (x) == MH_CIGAM)
#define SWAP32(x, magic) (IS_LITTLE_ENDIAN(magic)? OSSwapInt32(x): (x))
#define SWAP64(x, magic) (IS_LITTLE_ENDIAN(magic)? OSSwapInt64(x): (x))

#define ROUND_UP(x, y) (((x) + (y) - 1) & -(y))

#define ABSDIFF(x, y) ((x) > (y)? (uintmax_t)(x) - (uintmax_t)(y): (uintmax_t)(y) - (uintmax_t)(x))

#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE 0x80000033
#endif
#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS 0x80000034
#endif
#ifndef LC_DYLIB_CODE_SIGN_DRS
#define LC_DYLIB_CODE_SIGN_DRS 0x2B
#endif
#ifndef LC_LINKER_OPTIMIZATION_HINT
#define LC_LINKER_OPTIMIZATION_HINT 0x2E
#endif
#ifndef LC_NOTE
#define LC_NOTE 0x31
#endif
#ifndef EXPORT_SYMBOL_FLAGS_REEXPORT
#define EXPORT_SYMBOL_FLAGS_REEXPORT 0x08
#endif
#ifndef EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER 0x10
#endif

#define BUFSIZE 512

void fbzero(FILE *f, off_t offset, size_t len) {
	static unsigned char zeros[BUFSIZE] = {0};
	fseeko(f, offset, SEEK_SET);
	while(len != 0) {
		size_t size = MIN(len, sizeof(zeros));
		fwrite(zeros, size, 1, f);
		len -= size;
	}
}

void fmemmove(FILE *f, off_t dst, off_t src, size_t len) {
	static unsigned char buf[BUFSIZE];
	while(len != 0) {
		size_t size = MIN(len, sizeof(buf));
		fseeko(f, src, SEEK_SET);
		fread(&buf, size, 1, f);
		fseeko(f, dst, SEEK_SET);
		fwrite(buf, size, 1, f);

		len -= size;
		src += size;
		dst += size;
	}
}

void fmemmove_backward(FILE *f, off_t dst, off_t src, size_t len) {
	static unsigned char buf[BUFSIZE];
	off_t src_end = src + (off_t)len;
	off_t dst_end = dst + (off_t)len;
	while(len != 0) {
		size_t size = MIN(len, sizeof(buf));
		src_end -= size;
		dst_end -= size;
		fseeko(f, src_end, SEEK_SET);
		fread(buf, size, 1, f);
		fseeko(f, dst_end, SEEK_SET);
		fwrite(buf, size, 1, f);
		len -= size;
	}
}

int inplace_flag = false;
int weak_flag = false;
int overwrite_flag = false;
int codesig_flag = 0;
int yes_flag = false;

static struct option long_options[] = {
	{"inplace",          no_argument, &inplace_flag,   true},
	{"weak",             no_argument, &weak_flag,      true},
	{"overwrite",        no_argument, &overwrite_flag, true},
	{"strip-codesig",    no_argument, &codesig_flag,   1},
	{"no-strip-codesig", no_argument, &codesig_flag,   2},
	{"all-yes",          no_argument, &yes_flag,       true},
	{NULL,               0,           NULL,            0}
};

__attribute__((noreturn)) void usage(void) {
	printf("Usage: insert_dylib dylib_path binary_path [new_binary_path]\n");

	printf("Option flags:");

	struct option *opt = long_options;
	while(opt->name != NULL) {
		printf(" --%s", opt->name);
		opt++;
	}

	printf("\n");

	exit(1);
}

__attribute__((format(printf, 1, 2))) bool ask(const char *format, ...) {
	char *question;
	asprintf(&question, "%s [y/n] ", format);

	va_list args;
	va_start(args, format);
	vprintf(question, args);
	va_end(args);

	free(question);

	while(true) {
		char line_buf[256];
		char *line;
		if(yes_flag) {
			puts("y");
			line = "y";
		} else {
			line = fgets(line_buf, sizeof(line_buf), stdin);
			if(!line) return false;
		}

		switch(line[0]) {
			case 'y':
			case 'Y':
				return true;
				break;
			case 'n':
			case 'N':
				return false;
				break;
			default:
				printf("Please enter y or n: ");
		}
	}
}

size_t fpeek(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream) {
	off_t pos = ftello(stream);
	size_t result = fread(ptr, size, nitems, stream);
	fseeko(stream, pos, SEEK_SET);
	return result;
}

void *read_load_command(FILE *f, uint32_t cmdsize) {
	void *lc = malloc(cmdsize);

	fpeek(lc, cmdsize, 1, f);

	return lc;
}

bool check_load_commands(FILE *f, struct mach_header *mh, size_t header_offset, size_t commands_offset, const char *dylib_path, off_t *slice_size) {
	fseeko(f, commands_offset, SEEK_SET);

	uint32_t ncmds = SWAP32(mh->ncmds, mh->magic);

	off_t linkedit_32_pos = -1;
	off_t linkedit_64_pos = -1;
	struct segment_command linkedit_32;
	struct segment_command_64 linkedit_64;

	off_t symtab_pos = -1;
	uint32_t symtab_size = 0;

	for(int i = 0; i < ncmds; i++) {
		struct load_command lc;
		fpeek(&lc, sizeof(lc), 1, f);

		uint32_t cmdsize = SWAP32(lc.cmdsize, mh->magic);
		uint32_t cmd = SWAP32(lc.cmd, mh->magic);

		switch(cmd) {
			case LC_CODE_SIGNATURE:
				if(i == ncmds - 1) {
					if(codesig_flag == 2) {
						return true;
					}

					if(codesig_flag == 0 && !ask("LC_CODE_SIGNATURE load command found. Remove it?")) {
						return true;
					}

					struct linkedit_data_command *cmd = read_load_command(f, cmdsize);

					fbzero(f, ftello(f), cmdsize);

					uint32_t dataoff = SWAP32(cmd->dataoff, mh->magic);
					uint32_t datasize = SWAP32(cmd->datasize, mh->magic);

					free(cmd);

					uint64_t linkedit_fileoff = 0;
					uint64_t linkedit_filesize = 0;

					if(linkedit_32_pos != -1) {
						linkedit_fileoff = SWAP32(linkedit_32.fileoff, mh->magic);
						linkedit_filesize = SWAP32(linkedit_32.filesize, mh->magic);
					} else if(linkedit_64_pos != -1) {
						linkedit_fileoff = SWAP64(linkedit_64.fileoff, mh->magic);
						linkedit_filesize = SWAP64(linkedit_64.filesize, mh->magic);
					} else {
						fprintf(stderr, "Warning: __LINKEDIT segment not found.\n");
					}

					if(linkedit_32_pos != -1 || linkedit_64_pos != -1) {
						if(linkedit_fileoff + linkedit_filesize != *slice_size) {
							fprintf(stderr, "Warning: __LINKEDIT segment is not at the end of the file, so codesign will not work on the patched binary.\n");
						} else {
							if(dataoff + datasize != *slice_size) {
								fprintf(stderr, "Warning: Codesignature is not at the end of __LINKEDIT segment, so codesign will not work on the patched binary.\n");
							} else {
								*slice_size -= datasize;
								//int64_t diff_size = 0;
								if(symtab_pos == -1) {
									fprintf(stderr, "Warning: LC_SYMTAB load command not found. codesign might not work on the patched binary.\n");
								} else {
									fseeko(f, symtab_pos, SEEK_SET);
									struct symtab_command *symtab = read_load_command(f, symtab_size);

									uint32_t strsize = SWAP32(symtab->strsize, mh->magic);
									int64_t diff_size = SWAP32(symtab->stroff, mh->magic) + strsize - (int64_t)*slice_size;
									if(-0x10 <= diff_size && diff_size <= 0) {
										symtab->strsize = SWAP32((uint32_t)(strsize - diff_size), mh->magic);
										fwrite(symtab, symtab_size, 1, f);
									} else {
										fprintf(stderr, "Warning: String table doesn't appear right before code signature. codesign might not work on the patched binary. (0x%llx)\n", diff_size);
									}

									free(symtab);
								}

								linkedit_filesize -= datasize;
								uint64_t linkedit_vmsize = ROUND_UP(linkedit_filesize, 0x1000);

								if(linkedit_32_pos != -1) {
									linkedit_32.filesize = SWAP32((uint32_t)linkedit_filesize, mh->magic);
									linkedit_32.vmsize = SWAP32((uint32_t)linkedit_vmsize, mh->magic);

									fseeko(f, linkedit_32_pos, SEEK_SET);
									fwrite(&linkedit_32, sizeof(linkedit_32), 1, f);
								} else {
									linkedit_64.filesize = SWAP64(linkedit_filesize, mh->magic);
									linkedit_64.vmsize = SWAP64(linkedit_vmsize, mh->magic);

									fseeko(f, linkedit_64_pos, SEEK_SET);
									fwrite(&linkedit_64, sizeof(linkedit_64), 1, f);
								}

								goto fix_header;
							}
						}
					}

					// If we haven't truncated the file, zero out the code signature
					fbzero(f, header_offset + dataoff, datasize);

				fix_header:
					mh->ncmds = SWAP32(ncmds - 1, mh->magic);
					mh->sizeofcmds = SWAP32(SWAP32(mh->sizeofcmds, mh->magic) - cmdsize, mh->magic);

					return true;
				} else {
					printf("LC_CODE_SIGNATURE is not the last load command, so couldn't remove.\n");
				}
				break;
			case LC_LOAD_DYLIB:
			case LC_LOAD_WEAK_DYLIB: {
				struct dylib_command *dylib_command = read_load_command(f, cmdsize);

				union lc_str offset = dylib_command->dylib.name;
				char *name = &((char *)dylib_command)[SWAP32(offset.offset, mh->magic)];

				int cmp = strcmp(name, dylib_path);

				free(dylib_command);

				if(cmp == 0) {
					if(!ask("Binary already contains a load command for that dylib. Continue anyway?")) {
						return false;
					}
				}

				break;
			}
			case LC_SEGMENT:
			case LC_SEGMENT_64:
				if(cmd == LC_SEGMENT) {
					struct segment_command *cmd = read_load_command(f, cmdsize);
					if(strcmp(cmd->segname, "__LINKEDIT") == 0) {
						linkedit_32_pos = ftello(f);
						linkedit_32 = *cmd;
					}
					free(cmd);
				} else {
					struct segment_command_64 *cmd = read_load_command(f, cmdsize);
					if(strcmp(cmd->segname, "__LINKEDIT") == 0) {
						linkedit_64_pos = ftello(f);
						linkedit_64 = *cmd;
					}
					free(cmd);
				}
			break;
			case LC_SYMTAB:
				symtab_pos = ftello(f);
				symtab_size = cmdsize;
			break;
		}

		fseeko(f, SWAP32(lc.cmdsize, mh->magic), SEEK_CUR);
	}

	return true;
}

// --- Export trie rebuilder ---
// The export trie encodes symbol addresses as offsets from the image base
// (__TEXT vmaddr). When we change __TEXT vmaddr, these offsets must be updated.

static uint64_t trie_read_uleb(const uint8_t **p, const uint8_t *end) {
	uint64_t r = 0; int b = 0;
	do {
		if(*p >= end) break;
		r |= ((uint64_t)(**p & 0x7f)) << b;
		b += 7;
	} while(*(*p)++ & 0x80);
	return r;
}

static int trie_uleb_size(uint64_t v) {
	int s = 0;
	do { v >>= 7; s++; } while(v);
	return s;
}

static int trie_write_uleb(uint8_t *buf, uint64_t v) {
	int l = 0;
	do {
		buf[l] = v & 0x7f;
		v >>= 7;
		if(v) buf[l] |= 0x80;
		l++;
	} while(v);
	return l;
}

#define TRIE_MAX_EDGES 128

struct trie_node {
	uint8_t payload[64];
	uint32_t payload_len;
	uint8_t nch;
	struct { char lbl[256]; int ci; } ch[TRIE_MAX_EDGES];
	uint32_t out_off, out_sz;
};

static struct trie_node *trie_nodes_pool = NULL;
static int trie_node_count = 0;
static int trie_node_cap = 0;

static int trie_parse(const uint8_t *d, uint32_t dsz, uint32_t off, uint32_t shift) {
	if(off >= dsz) return -1;
	if(trie_node_count >= trie_node_cap) {
		int new_cap = trie_node_cap ? trie_node_cap * 2 : 256;
		struct trie_node *tmp = realloc(trie_nodes_pool, (size_t)new_cap * sizeof(struct trie_node));
		if(!tmp) { fprintf(stderr, "Out of memory for trie nodes\n"); return -1; }
		trie_nodes_pool = tmp;
		trie_node_cap = new_cap;
	}
	int idx = trie_node_count++;
	struct trie_node *n = &trie_nodes_pool[idx];
	memset(n, 0, sizeof(*n));

	const uint8_t *p = d + off, *end = d + dsz;
	uint64_t ts = trie_read_uleb(&p, end);

	if(ts > 0) {
		const uint8_t *te = p + ts;
		uint8_t *w = n->payload;
		uint64_t fl = trie_read_uleb(&p, te);
		w += trie_write_uleb(w, fl);

		if(fl & EXPORT_SYMBOL_FLAGS_REEXPORT) {
			// Re-export: ordinal + import name, no address to fix
			w += trie_write_uleb(w, trie_read_uleb(&p, te));
			while(p < te && *p) *w++ = *p++;
			*w++ = 0;
			if(p < te) p++;
		} else if(fl & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
			uint64_t stub = trie_read_uleb(&p, te);
			uint64_t resolver = trie_read_uleb(&p, te);
			w += trie_write_uleb(w, stub ? stub + shift : 0);
			w += trie_write_uleb(w, resolver ? resolver + shift : 0);
		} else {
			// Regular export: address offset from image base
			uint64_t addr = trie_read_uleb(&p, te);
			w += trie_write_uleb(w, addr ? addr + shift : 0);
		}
		n->payload_len = (uint32_t)(w - n->payload);
		p = te;
	}

	n->nch = (p < end) ? *p++ : 0;
	for(int i = 0; i < n->nch && i < TRIE_MAX_EDGES; i++) {
		int j = 0;
		while(p < end && *p) n->ch[i].lbl[j++] = *p++;
		n->ch[i].lbl[j] = 0;
		if(p < end) p++;
		n->ch[i].ci = trie_parse(d, dsz, (uint32_t)trie_read_uleb(&p, end), shift);
	}
	return idx;
}

static uint32_t trie_compute_size(int idx) {
	struct trie_node *n = &trie_nodes_pool[idx];
	uint32_t sz = 0;
	if(n->payload_len) {
		sz += trie_uleb_size(n->payload_len) + n->payload_len;
	} else {
		sz += 1;
	}
	sz += 1; // child count
	for(int i = 0; i < n->nch; i++) {
		sz += strlen(n->ch[i].lbl) + 1;
		sz += (n->ch[i].ci >= 0) ? trie_uleb_size(trie_nodes_pool[n->ch[i].ci].out_off) : 1;
	}
	return n->out_sz = sz;
}

static uint32_t trie_layout(void) {
	for(int iter = 0; iter < 10; iter++) {
		bool changed = false;
		uint32_t off = 0;
		for(int i = 0; i < trie_node_count; i++) {
			if(trie_nodes_pool[i].out_off != off) {
				trie_nodes_pool[i].out_off = off;
				changed = true;
			}
			trie_compute_size(i);
			off += trie_nodes_pool[i].out_sz;
		}
		if(!changed) break;
	}
	uint32_t total = 0;
	for(int i = 0; i < trie_node_count; i++) total += trie_nodes_pool[i].out_sz;
	return total;
}

static void trie_serialize(uint8_t *buf, int idx) {
	struct trie_node *n = &trie_nodes_pool[idx];
	uint8_t *p = buf + n->out_off;
	if(n->payload_len) {
		p += trie_write_uleb(p, n->payload_len);
		memcpy(p, n->payload, n->payload_len);
		p += n->payload_len;
	} else {
		*p++ = 0;
	}
	*p++ = n->nch;
	for(int i = 0; i < n->nch; i++) {
		size_t len = strlen(n->ch[i].lbl);
		memcpy(p, n->ch[i].lbl, len + 1);
		p += len + 1;
		if(n->ch[i].ci >= 0)
			p += trie_write_uleb(p, trie_nodes_pool[n->ch[i].ci].out_off);
		else
			p += trie_write_uleb(p, 0);
	}
}

static uint32_t shift_offset32(uint32_t value, uint32_t shift, uint32_t magic) {
	uint32_t v = SWAP32(value, magic);
	if(v == 0) return value;
	return SWAP32(v + shift, magic);
}

bool make_room_for_load_commands(FILE *f, size_t header_offset, struct mach_header *mh, uint32_t space_needed, off_t *slice_size) {
	bool is_64 = IS_64_BIT(mh->magic);
	uint32_t magic = mh->magic;

	if(!is_64) {
		fprintf(stderr, "Cannot expand header space for 32-bit binaries.\n");
		return false;
	}

	size_t hdr_size = sizeof(struct mach_header_64);
	size_t cmds_off = header_offset + hdr_size;
	uint32_t ncmds = SWAP32(mh->ncmds, magic);
	uint32_t sizeofcmds = SWAP32(mh->sizeofcmds, magic);

	// Find the lowest section file offset (relative to slice start)
	uint32_t first_sect_off = UINT32_MAX;
	fseeko(f, cmds_off, SEEK_SET);
	for(uint32_t i = 0; i < ncmds; i++) {
		struct load_command lc;
		off_t pos = ftello(f);
		fpeek(&lc, sizeof(lc), 1, f);
		uint32_t cmd = SWAP32(lc.cmd, magic);
		uint32_t cs = SWAP32(lc.cmdsize, magic);

		if(cmd == LC_SEGMENT_64) {
			struct segment_command_64 *seg = read_load_command(f, cs);
			uint32_t nsects = SWAP32(seg->nsects, magic);
			struct section_64 *sects = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
			for(uint32_t j = 0; j < nsects; j++) {
				uint32_t off = SWAP32(sects[j].offset, magic);
				if(off != 0 && off < first_sect_off) first_sect_off = off;
			}
			free(seg);
		}

		fseeko(f, pos + cs, SEEK_SET);
	}

	if(first_sect_off == UINT32_MAX) {
		fprintf(stderr, "No section data found in binary.\n");
		return false;
	}

	uint32_t available = first_sect_off - (uint32_t)(hdr_size + sizeofcmds);
	if(available >= space_needed) return true;

	uint32_t shift = 0x1000;
	while(available + shift < space_needed) shift += 0x1000;

	// Verify __PAGEZERO exists and can be shrunk
	bool found_pagezero = false;
	fseeko(f, cmds_off, SEEK_SET);
	for(uint32_t i = 0; i < ncmds; i++) {
		struct load_command lc;
		off_t pos = ftello(f);
		fpeek(&lc, sizeof(lc), 1, f);
		uint32_t cmd = SWAP32(lc.cmd, magic);
		uint32_t cs = SWAP32(lc.cmdsize, magic);

		if(cmd == LC_SEGMENT_64) {
			struct segment_command_64 *seg = read_load_command(f, cs);
			if(strcmp(seg->segname, "__PAGEZERO") == 0) {
				uint64_t vmsize = SWAP64(seg->vmsize, magic);
				if(vmsize <= shift) {
					fprintf(stderr, "__PAGEZERO vmsize too small to shrink.\n");
					free(seg);
					return false;
				}
				found_pagezero = true;
			}
			free(seg);
		}

		fseeko(f, pos + cs, SEEK_SET);
		if(found_pagezero) break;
	}

	if(!found_pagezero) {
		fprintf(stderr, "__PAGEZERO segment not found, cannot expand header.\n");
		return false;
	}

	printf("WARNING: Not enough header space. Expanding by 0x%x bytes (shrinking __PAGEZERO, extending __TEXT).\n", shift);

	// Shift all file content from first_sect_off onward
	fseeko(f, 0, SEEK_END);
	off_t total_size = ftello(f);
	off_t new_total = total_size + shift;

	fflush(f);
	ftruncate(fileno(f), new_total);

	size_t move_len = (size_t)(total_size - (header_offset + first_sect_off));
	fmemmove_backward(f, header_offset + first_sect_off + shift,
	                  header_offset + first_sect_off, move_len);
	fbzero(f, header_offset + first_sect_off, shift);

	*slice_size += shift;

	// Update all load commands with new offsets
	fseeko(f, cmds_off, SEEK_SET);
	for(uint32_t i = 0; i < ncmds; i++) {
		struct load_command lc;
		off_t pos = ftello(f);
		fpeek(&lc, sizeof(lc), 1, f);
		uint32_t cmd = SWAP32(lc.cmd, magic);
		uint32_t cs = SWAP32(lc.cmdsize, magic);

		switch(cmd) {
			case LC_SEGMENT_64: {
				struct segment_command_64 *seg = read_load_command(f, cs);
				bool modified = false;

				if(strcmp(seg->segname, "__PAGEZERO") == 0) {
					uint64_t vmsize = SWAP64(seg->vmsize, magic);
					seg->vmsize = SWAP64(vmsize - shift, magic);
					modified = true;
				} else if(strcmp(seg->segname, "__TEXT") == 0) {
					// Extend __TEXT downward: shrink vmaddr, grow vmsize and filesize
					uint64_t vmaddr = SWAP64(seg->vmaddr, magic);
					uint64_t vmsize = SWAP64(seg->vmsize, magic);
					uint64_t filesize = SWAP64(seg->filesize, magic);
					seg->vmaddr = SWAP64(vmaddr - shift, magic);
					seg->vmsize = SWAP64(vmsize + shift, magic);
					seg->filesize = SWAP64(filesize + shift, magic);
					// fileoff stays 0

					// Shift section file offsets (vmaddrs stay the same!)
					uint32_t nsects = SWAP32(seg->nsects, magic);
					struct section_64 *sects = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
					for(uint32_t j = 0; j < nsects; j++) {
						sects[j].offset = shift_offset32(sects[j].offset, shift, magic);
						sects[j].reloff = shift_offset32(sects[j].reloff, shift, magic);
					}
					modified = true;
				} else {
					// Other segments: shift fileoff (vmaddr stays the same)
					uint64_t fileoff = SWAP64(seg->fileoff, magic);
					if(fileoff > 0) {
						seg->fileoff = SWAP64(fileoff + shift, magic);

						uint32_t nsects = SWAP32(seg->nsects, magic);
						struct section_64 *sects = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
						for(uint32_t j = 0; j < nsects; j++) {
							sects[j].offset = shift_offset32(sects[j].offset, shift, magic);
							sects[j].reloff = shift_offset32(sects[j].reloff, shift, magic);
						}
						modified = true;
					}
				}

				if(modified) {
					fseeko(f, pos, SEEK_SET);
					fwrite(seg, cs, 1, f);
				}
				free(seg);
				break;
			}
			case LC_SYMTAB: {
				struct symtab_command *sc = read_load_command(f, cs);
				sc->symoff = shift_offset32(sc->symoff, shift, magic);
				sc->stroff = shift_offset32(sc->stroff, shift, magic);
				fseeko(f, pos, SEEK_SET);
				fwrite(sc, cs, 1, f);
				free(sc);
				break;
			}
			case LC_DYSYMTAB: {
				struct dysymtab_command *dc = read_load_command(f, cs);
				dc->tocoff = shift_offset32(dc->tocoff, shift, magic);
				dc->modtaboff = shift_offset32(dc->modtaboff, shift, magic);
				dc->extrefsymoff = shift_offset32(dc->extrefsymoff, shift, magic);
				dc->indirectsymoff = shift_offset32(dc->indirectsymoff, shift, magic);
				dc->extreloff = shift_offset32(dc->extreloff, shift, magic);
				dc->locreloff = shift_offset32(dc->locreloff, shift, magic);
				fseeko(f, pos, SEEK_SET);
				fwrite(dc, cs, 1, f);
				free(dc);
				break;
			}
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY: {
				struct dyld_info_command *di = read_load_command(f, cs);
				di->rebase_off = shift_offset32(di->rebase_off, shift, magic);
				di->bind_off = shift_offset32(di->bind_off, shift, magic);
				di->weak_bind_off = shift_offset32(di->weak_bind_off, shift, magic);
				di->lazy_bind_off = shift_offset32(di->lazy_bind_off, shift, magic);
				di->export_off = shift_offset32(di->export_off, shift, magic);
				fseeko(f, pos, SEEK_SET);
				fwrite(di, cs, 1, f);
				free(di);
				break;
			}
			case LC_FUNCTION_STARTS:
			case LC_DATA_IN_CODE:
			case LC_CODE_SIGNATURE:
			case LC_SEGMENT_SPLIT_INFO:
			case LC_DYLIB_CODE_SIGN_DRS:
			case LC_LINKER_OPTIMIZATION_HINT:
			case LC_DYLD_EXPORTS_TRIE:
			case LC_DYLD_CHAINED_FIXUPS: {
				struct linkedit_data_command *ld = read_load_command(f, cs);
				ld->dataoff = shift_offset32(ld->dataoff, shift, magic);
				fseeko(f, pos, SEEK_SET);
				fwrite(ld, cs, 1, f);
				free(ld);
				break;
			}
			case LC_MAIN: {
				// entryoff is file offset of main() from __TEXT start
				void *raw = read_load_command(f, cs);
				uint64_t *entryoff = (uint64_t *)((char *)raw + 8);
				uint64_t val = SWAP64(*entryoff, magic);
				if(val != 0) {
					*entryoff = SWAP64(val + shift, magic);
				}
				fseeko(f, pos, SEEK_SET);
				fwrite(raw, cs, 1, f);
				free(raw);
				break;
			}
			case LC_NOTE: {
				// note_command: cmd(4) + cmdsize(4) + data_owner(16) + offset(8) + size(8)
				void *raw = read_load_command(f, cs);
				uint64_t *note_off = (uint64_t *)((char *)raw + 24);
				uint64_t val = SWAP64(*note_off, magic);
				if(val != 0) {
					*note_off = SWAP64(val + shift, magic);
				}
				fseeko(f, pos, SEEK_SET);
				fwrite(raw, cs, 1, f);
				free(raw);
				break;
			}
		}

		fseeko(f, pos + cs, SEEK_SET);
	}

	// Fix structures that reference the image base (__TEXT vmaddr), which changed.
	// This includes the export trie, nlist entries, and data pointers.
	uint64_t new_text_vmaddr = 0;
	uint64_t old_text_vmaddr = 0; // = new + shift
	uint32_t export_off = 0, export_size = 0;
	off_t export_lc_pos = -1;
	int export_lc_type = 0;
	uint32_t linkedit_fileoff_val = 0, linkedit_filesize_val = 0;
	off_t linkedit_lc_pos = -1;
	uint32_t symoff_val = 0, nsyms_val = 0, stroff_val = 0;
	// Collect all DATA section file offsets+sizes for pointer fixup
	uint32_t program_vars_off = 0, program_vars_size = 0;

	fseeko(f, cmds_off, SEEK_SET);
	for(uint32_t i = 0; i < ncmds; i++) {
		struct load_command lc;
		off_t pos = ftello(f);
		fpeek(&lc, sizeof(lc), 1, f);
		uint32_t cmd = SWAP32(lc.cmd, magic);
		uint32_t cs = SWAP32(lc.cmdsize, magic);

		if(cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
			struct dyld_info_command *di = read_load_command(f, cs);
			export_off = SWAP32(di->export_off, magic);
			export_size = SWAP32(di->export_size, magic);
			export_lc_pos = pos;
			export_lc_type = cmd;
			free(di);
		} else if(cmd == LC_DYLD_EXPORTS_TRIE) {
			struct linkedit_data_command *ld = read_load_command(f, cs);
			export_off = SWAP32(ld->dataoff, magic);
			export_size = SWAP32(ld->datasize, magic);
			export_lc_pos = pos;
			export_lc_type = cmd;
			free(ld);
		} else if(cmd == LC_SYMTAB) {
			struct symtab_command *sc = read_load_command(f, cs);
			symoff_val = SWAP32(sc->symoff, magic);
			nsyms_val = SWAP32(sc->nsyms, magic);
			stroff_val = SWAP32(sc->stroff, magic);
			free(sc);
		} else if(cmd == LC_SEGMENT_64) {
			struct segment_command_64 *seg = read_load_command(f, cs);
			if(strcmp(seg->segname, "__LINKEDIT") == 0) {
				linkedit_fileoff_val = (uint32_t)SWAP64(seg->fileoff, magic);
				linkedit_filesize_val = (uint32_t)SWAP64(seg->filesize, magic);
				linkedit_lc_pos = pos;
			} else if(strcmp(seg->segname, "__TEXT") == 0) {
				new_text_vmaddr = SWAP64(seg->vmaddr, magic);
				old_text_vmaddr = new_text_vmaddr + shift;
			} else if(strcmp(seg->segname, "__DATA") == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {
				// Find __program_vars section for mh pointer fixup
				uint32_t nsects = SWAP32(seg->nsects, magic);
				struct section_64 *sects = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
				for(uint32_t j = 0; j < nsects; j++) {
					if(strcmp(sects[j].sectname, "__program_vars") == 0) {
						program_vars_off = SWAP32(sects[j].offset, magic);
						program_vars_size = (uint32_t)SWAP64(sects[j].size, magic);
						break;
					}
				}
			}
			free(seg);
		}

		fseeko(f, pos + cs, SEEK_SET);
	}

	if(export_off != 0 && export_size != 0) {
		uint8_t *trie_data = malloc(export_size);
		fseeko(f, header_offset + export_off, SEEK_SET);
		fread(trie_data, export_size, 1, f);

		trie_node_count = 0;
		trie_node_cap = 0;
		free(trie_nodes_pool);
		trie_nodes_pool = NULL;
		trie_parse(trie_data, export_size, 0, shift);
		free(trie_data);

		uint32_t new_size = trie_layout();
		uint8_t *new_trie = calloc(new_size + 8, 1);
		for(int i = 0; i < trie_node_count; i++)
			trie_serialize(new_trie, i);

		uint32_t final_export_off = export_off;
		uint32_t final_export_size = new_size;

		if(new_size <= export_size) {
			// Fits in place - zero old data and overwrite
			fbzero(f, header_offset + export_off, export_size);
			fseeko(f, header_offset + export_off, SEEK_SET);
			fwrite(new_trie, new_size, 1, f);
			// Keep original export_size to avoid shifting other LINKEDIT data
			final_export_size = export_size;
		} else {
			// Write at end of __LINKEDIT
			final_export_off = linkedit_fileoff_val + linkedit_filesize_val;
			fseeko(f, header_offset + final_export_off, SEEK_SET);
			fwrite(new_trie, new_size, 1, f);

			// Update __LINKEDIT segment size
			uint32_t new_le_fsz = linkedit_filesize_val + new_size;
			uint64_t new_le_vmsz = ROUND_UP(new_le_fsz, 0x1000);

			if(linkedit_lc_pos >= 0) {
				fseeko(f, linkedit_lc_pos, SEEK_SET);
				struct load_command lc2;
				fpeek(&lc2, sizeof(lc2), 1, f);
				uint32_t cs2 = SWAP32(lc2.cmdsize, magic);
				struct segment_command_64 *seg = read_load_command(f, cs2);
				seg->filesize = SWAP64(new_le_fsz, magic);
				seg->vmsize = SWAP64(new_le_vmsz, magic);
				fseeko(f, linkedit_lc_pos, SEEK_SET);
				fwrite(seg, cs2, 1, f);
				free(seg);
			}

			// Ensure file is large enough
			off_t needed = header_offset + final_export_off + new_size;
			fseeko(f, 0, SEEK_END);
			if(ftello(f) < needed) {
				fflush(f);
				ftruncate(fileno(f), needed);
			}

			*slice_size = final_export_off + new_size;
			final_export_size = new_size;
		}

		free(new_trie);

		// Update the export trie pointer in the load command
		if(export_lc_pos >= 0) {
			fseeko(f, export_lc_pos, SEEK_SET);
			struct load_command lc2;
			fpeek(&lc2, sizeof(lc2), 1, f);
			uint32_t cs2 = SWAP32(lc2.cmdsize, magic);

			if(export_lc_type == LC_DYLD_INFO || export_lc_type == LC_DYLD_INFO_ONLY) {
				struct dyld_info_command *di = read_load_command(f, cs2);
				di->export_off = SWAP32(final_export_off, magic);
				di->export_size = SWAP32(final_export_size, magic);
				fseeko(f, export_lc_pos, SEEK_SET);
				fwrite(di, cs2, 1, f);
				free(di);
			} else {
				struct linkedit_data_command *ld = read_load_command(f, cs2);
				ld->dataoff = SWAP32(final_export_off, magic);
				ld->datasize = SWAP32(final_export_size, magic);
				fseeko(f, export_lc_pos, SEEK_SET);
				fwrite(ld, cs2, 1, f);
				free(ld);
			}
		}
	}

	// Fix __program_vars.mh pointer (first 8 bytes of __program_vars section).
	// This is the pointer returned by _NSGetMachExecuteHeader() and must equal __TEXT vmaddr.
	if(old_text_vmaddr != 0 && old_text_vmaddr != new_text_vmaddr && program_vars_off != 0 && program_vars_size >= 8) {
		uint64_t old_val = SWAP64(old_text_vmaddr, magic);
		uint64_t new_val = SWAP64(new_text_vmaddr, magic);
		uint64_t current;
		fseeko(f, header_offset + program_vars_off, SEEK_SET);
		fread(&current, 8, 1, f);
		if(current == old_val) {
			fseeko(f, header_offset + program_vars_off, SEEK_SET);
			fwrite(&new_val, 8, 1, f);
		}
	}

	// Fix nlist n_value for symbols at the old __TEXT vmaddr (e.g. __mh_execute_header)
	if(symoff_val != 0 && nsyms_val != 0 && old_text_vmaddr != new_text_vmaddr) {
		// nlist_64: n_un(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8) = 16 bytes
		for(uint32_t i = 0; i < nsyms_val; i++) {
			off_t entry_off = header_offset + symoff_val + (off_t)i * 16;
			fseeko(f, entry_off + 8, SEEK_SET); // skip to n_value
			uint64_t nval;
			fread(&nval, 8, 1, f);
			if(nval == SWAP64(old_text_vmaddr, magic)) {
				nval = SWAP64(new_text_vmaddr, magic);
				fseeko(f, entry_off + 8, SEEK_SET);
				fwrite(&nval, 8, 1, f);
			}
		}
	}

	return true;
}

bool insert_dylib(FILE *f, size_t header_offset, const char *dylib_path, off_t *slice_size) {
	fseeko(f, header_offset, SEEK_SET);

	struct mach_header mh;
	fread(&mh, sizeof(struct mach_header), 1, f);

	if(mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64 && mh.magic != MH_MAGIC && mh.magic != MH_CIGAM) {
		printf("Unknown magic: 0x%x\n", mh.magic);
		return false;
	}

	size_t commands_offset = header_offset + (IS_64_BIT(mh.magic)? sizeof(struct mach_header_64): sizeof(struct mach_header));

	bool cont = check_load_commands(f, &mh, header_offset, commands_offset, dylib_path, slice_size);

	if(!cont) {
		return true;
	}

	// Even though a padding of 4 works for x86_64, codesign doesn't like it
	size_t path_padding = 8;

	size_t dylib_path_len = strlen(dylib_path);
	size_t dylib_path_size = (dylib_path_len & ~(path_padding - 1)) + path_padding;
	uint32_t cmdsize = (uint32_t)(sizeof(struct dylib_command) + dylib_path_size);

	struct dylib_command dylib_command = {
		.cmd = SWAP32(weak_flag? LC_LOAD_WEAK_DYLIB: LC_LOAD_DYLIB, mh.magic),
		.cmdsize = SWAP32(cmdsize, mh.magic),
		.dylib = {
			.name = SWAP32(sizeof(struct dylib_command), mh.magic),
			.timestamp = 0,
			.current_version = 0,
			.compatibility_version = 0
		}
	};

	uint32_t sizeofcmds = SWAP32(mh.sizeofcmds, mh.magic);

	fseeko(f, commands_offset + sizeofcmds, SEEK_SET);
	char space[cmdsize];

	fread(&space, cmdsize, 1, f);

	bool empty = true;
	for(int i = 0; i < cmdsize; i++) {
		if(space[i] != 0) {
			empty = false;
			break;
		}
	}

	if(!empty) {
		if(make_room_for_load_commands(f, header_offset, &mh, cmdsize, slice_size)) {
			// Re-check space after expansion
			fseeko(f, commands_offset + sizeofcmds, SEEK_SET);
			fread(&space, cmdsize, 1, f);
			empty = true;
			for(int i = 0; i < cmdsize; i++) {
				if(space[i] != 0) {
					empty = false;
					break;
				}
			}
		}
		if(!empty) {
			if(!ask("It doesn't seem like there is enough empty space. Continue anyway?")) {
				return false;
			}
		}
	}

	fseeko(f, -((off_t)cmdsize), SEEK_CUR);

	char *dylib_path_padded = calloc(dylib_path_size, 1);
	memcpy(dylib_path_padded, dylib_path, dylib_path_len);

	fwrite(&dylib_command, sizeof(dylib_command), 1, f);
	fwrite(dylib_path_padded, dylib_path_size, 1, f);

	free(dylib_path_padded);

	mh.ncmds = SWAP32(SWAP32(mh.ncmds, mh.magic) + 1, mh.magic);
	sizeofcmds += cmdsize;
	mh.sizeofcmds = SWAP32(sizeofcmds, mh.magic);

	fseeko(f, header_offset, SEEK_SET);
	fwrite(&mh, sizeof(mh), 1, f);

	// Write shadow copies of the Mach-O header at every page boundary in the
	// padding area between the load commands and the first section. When header
	// expansion shifts __TEXT vmaddr down, RIP-relative references to
	// _mh_execute_header baked into the code still point at the old vmaddr.
	// A shadow copy at that file offset ensures they read a valid header.
	if(IS_64_BIT(mh.magic)) {
		// Find first section offset to know the padding extent
		uint32_t nc = SWAP32(mh.ncmds, mh.magic);
		uint32_t first_sect = UINT32_MAX;
		fseeko(f, commands_offset, SEEK_SET);
		for(uint32_t i = 0; i < nc; i++) {
			struct load_command lc;
			off_t p = ftello(f);
			fpeek(&lc, sizeof(lc), 1, f);
			uint32_t cmd = SWAP32(lc.cmd, mh.magic);
			uint32_t cs = SWAP32(lc.cmdsize, mh.magic);
			if(cmd == LC_SEGMENT_64) {
				struct segment_command_64 *seg = read_load_command(f, cs);
				uint32_t nsects = SWAP32(seg->nsects, mh.magic);
				struct section_64 *sects = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
				for(uint32_t j = 0; j < nsects; j++) {
					uint32_t off = SWAP32(sects[j].offset, mh.magic);
					if(off != 0 && off < first_sect) first_sect = off;
				}
				free(seg);
			}
			fseeko(f, p + cs, SEEK_SET);
		}

		if(first_sect != UINT32_MAX && first_sect > 0x1000) {
			uint8_t hdr_shadow[32]; // sizeof(mach_header_64)
			fseeko(f, header_offset, SEEK_SET);
			fread(hdr_shadow, sizeof(hdr_shadow), 1, f);
			// Zero ncmds(offset 16) and sizeofcmds(offset 20) so code
			// won't try to walk non-existent load commands from the shadow
			memset(hdr_shadow + 16, 0, 8);
			for(uint32_t off = 0x1000; off + 32 <= first_sect; off += 0x1000) {
				fseeko(f, header_offset + off, SEEK_SET);
				fwrite(hdr_shadow, sizeof(hdr_shadow), 1, f);
			}
		}
	}

	return true;
}

int main(int argc, const char *argv[]) {
	while(true) {
		int option_index = 0;

		int c = getopt_long(argc, (char *const *)argv, "", long_options, &option_index);

		if(c == -1) {
			break;
		}

		switch(c) {
			case 0:
				break;
			case '?':
				usage();
				break;
			default:
				abort();
				break;
		}
	}

	argv = &argv[optind - 1];
	argc -= optind - 1;

	if(argc < 3 || argc > 4) {
		usage();
	}

	const char *lc_name = weak_flag? "LC_LOAD_WEAK_DYLIB": "LC_LOAD_DYLIB";

	const char *dylib_path = argv[1];
	const char *binary_path = argv[2];

	struct stat s;

	if(stat(binary_path, &s) != 0) {
		perror(binary_path);
		exit(1);
	}

	if(dylib_path[0] != '@' && stat(dylib_path, &s) != 0) {
		if(!ask("The provided dylib path doesn't exist. Continue anyway?")) {
			exit(1);
		}
	}

	bool binary_path_was_malloced = false;
	if(!inplace_flag) {
		char *new_binary_path;
		if(argc == 4) {
			new_binary_path = (char *)argv[3];
		} else {
			asprintf(&new_binary_path, "%s_patched", binary_path);
			binary_path_was_malloced = true;
		}

		if(!overwrite_flag && stat(new_binary_path, &s) == 0) {
			if(!ask("%s already exists. Overwrite it?", new_binary_path)) {
				exit(1);
			}
		}

		if(copyfile(binary_path, new_binary_path, NULL, COPYFILE_DATA | COPYFILE_UNLINK)) {
			printf("Failed to create %s\n", new_binary_path);
			exit(1);
		}

		binary_path = new_binary_path;
	}

	FILE *f = fopen(binary_path, "r+");

	if(!f) {
		printf("Couldn't open file %s\n", binary_path);
		exit(1);
	}

	bool success = true;

	fseeko(f, 0, SEEK_END);
	off_t file_size = ftello(f);
	rewind(f);

	uint32_t magic;
	fread(&magic, sizeof(uint32_t), 1, f);

	switch(magic) {
		case FAT_MAGIC:
		case FAT_CIGAM: {
			fseeko(f, 0, SEEK_SET);

			struct fat_header fh;
			fread(&fh, sizeof(fh), 1, f);

			uint32_t nfat_arch = SWAP32(fh.nfat_arch, magic);

			printf("Binary is a fat binary with %d archs.\n", nfat_arch);

			struct fat_arch archs[nfat_arch];
			fread(archs, sizeof(archs), 1, f);

			int fails = 0;

			uint32_t offset = 0;
			if(nfat_arch > 0) {
				offset = SWAP32(archs[0].offset, magic);
			}

			for(int i = 0; i < nfat_arch; i++) {
				off_t orig_offset = SWAP32(archs[i].offset, magic);
				off_t orig_slice_size = SWAP32(archs[i].size, magic);
				offset = ROUND_UP(offset, 1 << SWAP32(archs[i].align, magic));
				if(orig_offset != offset) {
					fmemmove(f, offset, orig_offset, orig_slice_size);
					fbzero(f, MIN(offset, orig_offset) + orig_slice_size, ABSDIFF(offset, orig_offset));

					archs[i].offset = SWAP32(offset, magic);
				}

				off_t slice_size = orig_slice_size;
				bool r = insert_dylib(f, offset, dylib_path, &slice_size);
				if(!r) {
					printf("Failed to add %s to arch #%d!\n", lc_name, i + 1);
					fails++;
				}

				if(slice_size > orig_slice_size && i < nfat_arch - 1) {
					// Header expansion shifted subsequent slices in the file
					uint32_t growth = (uint32_t)(slice_size - orig_slice_size);
					for(int j = i + 1; j < nfat_arch; j++) {
						uint32_t o = SWAP32(archs[j].offset, magic);
						archs[j].offset = SWAP32(o + growth, magic);
					}
				} else if(slice_size < orig_slice_size && i < nfat_arch - 1) {
					fbzero(f, offset + slice_size, orig_slice_size - slice_size);
				}

				file_size = offset + slice_size;
				offset += slice_size;
				archs[i].size = SWAP32((uint32_t)slice_size, magic);
			}

			rewind(f);
			fwrite(&fh, sizeof(fh), 1, f);
			fwrite(archs, sizeof(archs), 1, f);

			// We need to flush before truncating
			fflush(f);
			ftruncate(fileno(f), file_size);

			if(fails == 0) {
				printf("Added %s to all archs in %s\n", lc_name, binary_path);
			} else if(fails == nfat_arch) {
				printf("Failed to add %s to any archs.\n", lc_name);
				success = false;
			} else {
				printf("Added %s to %d/%d archs in %s\n", lc_name, nfat_arch - fails, nfat_arch, binary_path);
			}

			break;
		}
		case MH_MAGIC_64:
		case MH_CIGAM_64:
		case MH_MAGIC:
		case MH_CIGAM:
			if(insert_dylib(f, 0, dylib_path, &file_size)) {
				ftruncate(fileno(f), file_size);
				printf("Added %s to %s\n", lc_name, binary_path);
			} else {
				printf("Failed to add %s!\n", lc_name);
				success = false;
			}
			break;
		default:
			printf("Unknown magic: 0x%x\n", magic);
			exit(1);
	}

	fclose(f);

	if(!success) {
		if(!inplace_flag) {
			unlink(binary_path);
		}
		exit(1);
	}

	if(binary_path_was_malloced) {
		free((void *)binary_path);
	}

    return 0;
}
