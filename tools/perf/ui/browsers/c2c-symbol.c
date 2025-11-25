// SPDX-License-Identifier: GPL-2.0
/**
 * C2C Symbol Browser - Display symbol-level cacheline sharing analysis
 * 
 * This browser provides a symbol-centric view of cache-to-cache (C2C) data,
 * showing which symbols share cachelines and may experience false sharing.
 */

#include "../../builtin-c2c.h"
#include "../browser.h"
#include "../ui.h"
#include "../../util/hist.h"
#include "../../util/sort.h"
#include "../../util/symbol.h"
#include "../../util/session.h"
#include "../../util/mem-info.h"
#include "../../util/cacheline.h"
#include "../../util/debug.h"
#include <linux/zalloc.h>
#include <linux/string.h>
#include <sys/ttydefaults.h>


struct c2c_hist_entry;


/**
 * c2c_symbol_browser__title - Generate title for symbol browser
 */
static int c2c_symbol_browser__title(struct hist_browser *browser,
			      char *bf, size_t size)
{
	scnprintf(bf, size,
		  "Shared Data Symbols Table     "
		  "(%lu entries, sorted on Cycles Percent)",
		  browser->nr_non_filtered_entries);
	return 0;
}

/**
 * c2c_symbol_browser__new - Create new symbol browser instance
 */
struct c2c_symbol_browser *c2c_symbol_browser__new(struct hists *hists,
						   struct perf_session *session)
{
	struct c2c_symbol_browser *browser;

	if (!hists || !session)
		return NULL;

	browser = zalloc(sizeof(*browser));
	if (!browser)
		return NULL;

	/* Store references */
	browser->hists = hists;
	browser->session = session;

	/* Initialize base histogram browser */
	hist_browser__init(&browser->hb, hists);

	/* Configure browser for symbol view */
	browser->hb.title = c2c_symbol_browser__title;
	browser->hb.c2c_filter = true;
	browser->hb.show_headers = true;
	browser->hb.min_pcnt = 0.0;

	return browser;
}

/**
 * c2c_symbol_browser__delete - Free symbol browser
 */
void c2c_symbol_browser__delete(struct c2c_symbol_browser *browser)
{
	if (browser) {
		/* Base browser cleanup is handled by hist_browser__delete */
		free(browser);
	}
}

/**
 * c2c_symbol_browser__handle_expand - Handle expand/collapse operation
 */
int c2c_symbol_browser__handle_expand(struct c2c_symbol_browser *browser)
{
	struct hist_entry *he = browser->hb.he_selection;

	if (!he || !he->has_children)
		return 0;

	/* Create child entries if not already done */
	if (RB_EMPTY_ROOT(&he->hroot_out.rb_root)) {
		/* Ensure index is built for interactive use */
		build_cacheline_symbol_index();
		populate_symbol_children(he);
	}

	/* Toggle the folded state */
	he->unfolded = !he->unfolded;

	/* Update the browser to reflect hierarchy changes */
	ui_browser__update_nr_entries(&browser->hb.b, browser->hb.hists->nr_entries);
	browser->hb.b.seek(&browser->hb.b, SEEK_SET, 0);

	return 0;
}

/**
 * c2c_symbol_browser__browse_cacheline_detail - Handle cacheline detail view
 */
int c2c_symbol_browser__browse_cacheline_detail(struct c2c_symbol_browser *browser,
					       struct hist_entry *he_selection,
					       struct hists *main_hists)
{
	struct rb_node *nd;
	u64 cl_addr = 0;

	(void)browser; /* Suppress unused parameter warning */

	if (!he_selection || !he_selection->parent_he || !he_selection->parent_he->parent_he)
		return -1;

	/* Get the cacheline address from the grandchild */
	if (he_selection->mem_info && mem_info__daddr(he_selection->mem_info))
		cl_addr = cl_address(mem_info__daddr(he_selection->mem_info)->addr, chk_double_cl);
	else
		return -1;

	/* Find the cacheline entry in the main hists */
	nd = rb_first_cached(&main_hists->entries);
	while (nd) {
		struct hist_entry *he_cl = rb_entry(nd, struct hist_entry, rb_node);

		if (he_cl->mem_info && mem_info__daddr(he_cl->mem_info)) {
			u64 this_cl = cl_address(mem_info__daddr(he_cl->mem_info)->addr, chk_double_cl);

			if (this_cl == cl_addr) {
				/* Found the cacheline, call the browse function */
				return perf_c2c__browse_cacheline(he_cl);
			}
		}
		nd = rb_next(nd);
	}

	return -1; /* Cacheline not found */
}

