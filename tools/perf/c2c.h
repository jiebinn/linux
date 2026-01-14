/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_C2C_H_
#define _PERF_C2C_H_ 1

struct compute_stats {
	struct stats		 lcl_hitm;
	struct stats		 rmt_hitm;
	struct stats		 lcl_peer;
	struct stats		 rmt_peer;
	struct stats		 load;
};

struct c2c_hists {
	struct hists		hists;
	struct perf_hpp_list	list;
	struct c2c_stats	stats;
};

struct c2c_hist_entry {
	struct c2c_hists	*hists;
	struct c2c_stats	 stats;
	unsigned long		*cpuset;
	unsigned long		*nodeset;
	struct c2c_stats	*node_stats;
	unsigned int		 cacheline_idx;

	struct compute_stats	 cstats;

	unsigned long		 paddr;
	unsigned long		 paddr_cnt;
	bool			 paddr_zero;
	char			*nodestr;

	/* Symbol view: list of accessed cachelines (references only) */
	struct list_head	 _symbol_accessed_cachelines;

	/*
	 * must be at the end,
	 * because of its callchain dynamic entry
	 */
	struct hist_entry	he;
};

/** Reference to a cacheline accessed by a symbol (avoids data duplication) */
struct symbol_cacheline_ref {
	struct list_head	 list;
	struct c2c_hist_entry	*cacheline;
};

struct perf_c2c {
	struct perf_tool	tool;
	struct c2c_hists	hists;
	struct mem2node		mem2node;

	unsigned long		**nodes;
	int			 nodes_cnt;
	int			 cpus_cnt;
	int			*cpu2node;
	int			 node_info;

	bool			 show_src;
	bool			 show_all;
	bool			 use_stdio;
	bool			 stats_only;
	bool			 symbol_full;
	bool			 stitch_lbr;

	/* Shared cache line stats */
	struct c2c_stats	shared_clines_stats;
	int			shared_clines;

	int			 display;

	const char		*coalesce;
	char			*cl_sort;
	char			*cl_resort;
	char			*cl_output;
};

extern struct perf_c2c c2c;

/**
 * perf_c2c__browse_cacheline - Display cacheline details browser
 * @he: Histogram entry for the cacheline to browse
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_cacheline(struct hist_entry *he);

/**
 * perf_c2c__browse_symbol_view - Browse symbol view browser
 * @hists: Main cacheline histograms
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_symbol_view(struct hists *hists);

#endif /* _PERF_C2C_H_ */
