/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_UI_BROWSER_C2C_SYMBOL_H_
#define _PERF_UI_BROWSER_C2C_SYMBOL_H_ 1

#include "ui/browser.h"
#include "ui/browsers/hists.h"

struct perf_session;
struct perf_env;
struct hists;

/* Forward declaration for perf_c2c */
struct perf_c2c;

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
 * c2c_symbol_browser__title - Get title string for browser
 * @browser: Browser instance
 * @bf: Buffer to store title
 * @size: Size of buffer
 *
 * Returns: Number of characters written
 */
int c2c_symbol_browser__title(struct hist_browser *browser,
			      char *bf, size_t size);

/**
 * c2c_symbol_browser__handle_expand - Handle expand/collapse operation
 * @browser: Symbol browser instance
 *
 * Returns: 0 on success, negative value on error
 */
int c2c_symbol_browser__handle_expand(struct c2c_symbol_browser *browser);

/**
 * c2c_symbol_browser__browse_cacheline_detail - Handle cacheline detail view for symbol browser
 * @browser: Symbol browser instance
 * @he_selection: Selected histogram entry (should be a grandchild node)
 * @main_hists: Main cacheline hists to search for corresponding entry
 *
 * This function handles the 'd' key press in symbol view when a grandchild
 * (cacheline) node is selected. It finds the corresponding cacheline entry
 * in the main cacheline view and displays its details.
 *
 * Returns: 0 on success, negative value on error
 */
int c2c_symbol_browser__browse_cacheline_detail(struct c2c_symbol_browser *browser,
					       struct hist_entry *he_selection,
					       struct hists *main_hists);


#endif /* _PERF_UI_BROWSER_C2C_SYMBOL_H_ */

