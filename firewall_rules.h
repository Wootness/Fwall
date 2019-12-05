#ifndef _FW_RULES_H_
#define _FW_RULES_H_

#include "fw.h"


/* Init to NULLs */
extern rule_t rules_table[MAX_RULES];
extern char active_rules_count;
extern int rule_size;

#define RULES_UPDATE_SUCCESS 1
#define RULES_UPDATE_FAIL 0

/*
 * Input: encoded form of the new rules list
 * Output: RULES_UPDATE_SUCCESS if successful, RULES_UPDATE_FAIL if failed to update
 */
int update_rules_table(const char *encoded_rules,int leng);

#endif // _FW_RULES_H_
