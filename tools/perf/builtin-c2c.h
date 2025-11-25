/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_BUILTIN_C2C_H_
#define _PERF_BUILTIN_C2C_H_ 1

#include "ui/browser.h"
#include "ui/browsers/hists.h"

/* Opaque declarations - defined in builtin-c2c.c */
struct perf_c2c;

/* Global C2C context - defined in builtin-c2c.c */
extern struct perf_c2c c2c;

/**
 * struct c2c_symbol_browser - Symbol browser for C2C analysis
 * @hb: Base histogram browser
 * @hists: Symbol histograms to display
 * @session: Perf session for data access
 *
 * This browser displays symbol-level view of cacheline sharing,
 * allowing users to see which symbols (functions) share cachelines
 * and cause false sharing issues.
 */
struct c2c_symbol_browser {
	struct hist_browser	hb;
	struct hists		*hists;
	struct perf_session	*session;
};

/**
 * c2c_symbol_browser__new - Create a new C2C symbol browser
 * @hists: Symbol histograms to display
 * @session: Perf session for accessing symbol information
 *
 * Returns: Pointer to newly created browser, or NULL on error
 */
struct c2c_symbol_browser *c2c_symbol_browser__new(struct hists *hists,
						   struct perf_session *session);

/**
 * c2c_symbol_browser__delete - Free a C2C symbol browser
 * @browser: Browser to free
 */
void c2c_symbol_browser__delete(struct c2c_symbol_browser *browser);

/**
 * c2c_symbol_browser__handle_expand - Handle expand/collapse operation
 * @browser: Symbol browser instance
 *
 * Returns: 0 on success, negative value on error
 */
int c2c_symbol_browser__handle_expand(struct c2c_symbol_browser *browser);

/**
 * c2c_symbol_browser__browse_cacheline_detail - Handle cacheline detail view
 * @browser: Symbol browser instance
 * @he_selection: Selected histogram entry
 * @main_hists: Main cacheline hists
 *
 * Returns: 0 on success, negative value on error
 */
int c2c_symbol_browser__browse_cacheline_detail(struct c2c_symbol_browser *browser,
					       struct hist_entry *he_selection,
					       struct hists *main_hists);

/**
 * perf_c2c__browse_cacheline - Display cacheline details browser
 * @he: Histogram entry for the cacheline to browse
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_cacheline(struct hist_entry *he);

/**
 * build_cacheline_symbol_index - Build cacheline to symbol index
 */
void build_cacheline_symbol_index(void);

/**
 * populate_symbol_children - Create child entries for symbol
 * @he: Parent histogram entry
 */
void populate_symbol_children(struct hist_entry *he);

#endif /* _PERF_BUILTIN_C2C_H_ */

