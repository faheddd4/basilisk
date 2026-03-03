/*
 * Basilisk Token Analyzer — C Header
 */

#ifndef BASILISK_TOKENS_H
#define BASILISK_TOKENS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Approximate BPE token count */
int basilisk_estimate_tokens(const char *text);

/* Shannon entropy (bits per byte) */
double basilisk_entropy(const char *text);

/* Levenshtein edit distance */
int basilisk_levenshtein(const char *s1, const char *s2);

/* Normalized similarity 0.0-1.0 */
double basilisk_similarity(const char *s1, const char *s2);

/* Count Unicode confusable characters */
int basilisk_count_confusables(const char *text);

/* Pairwise similarity matrix (upper-triangular, flattened) */
double *basilisk_similarity_matrix(const char **strings, int count);
void basilisk_free_matrix(double *matrix);

/* Boyer-Moore-Horspool fast substring search */
int basilisk_fast_search(const char *text, const char *pattern);

/* Multi-pattern occurrence counter */
int *basilisk_multi_count(const char *text, const char **patterns,
                          int num_patterns);
void basilisk_free_counts(int *counts);

#ifdef __cplusplus
}
#endif

#endif /* BASILISK_TOKENS_H */
