/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_BUILTIN_C2C_H_
#define _PERF_BUILTIN_C2C_H_ 1

struct hist_entry;

/* Opaque declarations - defined in builtin-c2c.c */
struct perf_c2c;

/* Global C2C context - defined in builtin-c2c.c */
extern struct perf_c2c c2c;

/**
 * perf_c2c__browse_cacheline - Display cacheline details browser
 * @he: Histogram entry for the cacheline to browse
 * 
 * Opens a detailed view of the specified cacheline, showing all
 * memory accesses, symbols, and HITM statistics.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_cacheline(struct hist_entry *he);

/**
 * build_cacheline_symbol_index - Build performance index
 * 
 * Builds an index mapping cachelines to symbols for fast lookup.
 * This function is idempotent - subsequent calls do nothing if
 * index is already built.
 */
void build_cacheline_symbol_index(void);

/**
 * populate_symbol_children - Create child entries for symbol
 * @he: Parent histogram entry to populate children for
 * 
 * Creates related symbol entries as children of the parent symbol,
 * showing which other symbols share cachelines with it.
 */
void populate_symbol_children(struct hist_entry *he);


#endif /* _PERF_BUILTIN_C2C_H_ */

