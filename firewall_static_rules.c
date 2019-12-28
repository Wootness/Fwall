#include "firewall_main.h"
#include "firewall_static_rules.h"

rule_t rules_table[MAX_RULES];
char active_rules_count = 0;
int rule_size = sizeof(rule_t);

#define ENCODED_RULE_SIZE 46

/* Rules Table API */

int update_rules_table(const char *encoded_rules,int leng)
{
    int offset;
    int curr_rule_index;
    ushort temp_port = 0;
    rule_t *curr_rule;
    int rules_count;
    
    if((leng % ENCODED_RULE_SIZE) != 0)
        return RULES_UPDATE_FAIL;

    // Calculate number of rules
    rules_count = leng / ENCODED_RULE_SIZE;

    // Make sure we werent provided too many rules
    if(rules_count > MAX_RULES)
        return RULES_UPDATE_FAIL;

    // Iterate encoded rules, check for errors
    offset = 0;
    while(offset < leng)
    {
        // Name
        //  No checks
        offset += 20;

        // Direction
        //  Should be 0x01,0x02 or 0x03
        if(encoded_rules[offset] == 0 || encoded_rules[offset] > 0x03)
            return RULES_UPDATE_FAIL;
        offset += 1;

        // IPs,Masks and /k values
        //  No checks
        offset += 18;

        // Ports
        //  Make sure both (src & dst) aren't bigger than the 1023 limit
        //  Source port:
        memcpy(&temp_port,encoded_rules + offset,2);
        temp_port = ntohs(temp_port);
        if(temp_port > ABOVE_1023_INDICATOR)
            return RULES_UPDATE_FAIL;    
        offset += 2;
        //  Dest port:
        memcpy(&temp_port,encoded_rules + offset,2);
        temp_port = ntohs(temp_port);
        if(temp_port > ABOVE_1023_INDICATOR)
            return RULES_UPDATE_FAIL;
        offset += 2;

        // Protocol
        //  Make sure it's one of the expected protocols
        switch ((unsigned char)encoded_rules[offset])
        {
            case PROT_ICMP:
            case PROT_TCP:
            case PROT_UDP:
            case PROT_OTHER:
            case PROT_ANY:
                break;
            default:
                return RULES_UPDATE_FAIL;
        }
        offset += 1;
        // ACK bit
        //  Should be 0x01,0x02 or 0x03
        if(encoded_rules[offset] == 0 || encoded_rules[offset] > 0x03)
            return RULES_UPDATE_FAIL;
        offset += 1;
        // Action
        //  Should be 0x00 (DROP) or 0x01 (ACCEPT)
        if(encoded_rules[offset] > 0x01)
            return RULES_UPDATE_FAIL;
        offset += 1;
    }


    // If nothing triggered a return in the last loop, all rules are valid and we can copy them.
    // 'Reset' table before updating 
    active_rules_count = 0;

    offset = 0;
    curr_rule_index = 0;
    while(curr_rule_index < rules_count)
    {
        // Get pointer to currently modified rule
        curr_rule = rules_table + curr_rule_index;

        // Name
        memcpy(curr_rule->rule_name,encoded_rules + offset,20);
        offset += 20;
        

        // Direction
        curr_rule->direction = (direction_t)encoded_rules[offset];
        offset += 1;


        // Source _
        //  _ IP
        memcpy(&curr_rule->src_ip,encoded_rules + offset,4);
        // Convert from network to host 
        offset += 4;
        //  _ MASK
        memcpy(&curr_rule->src_prefix_mask,encoded_rules + offset,4);
        offset += 4;
        //  _ /k value
        curr_rule->src_prefix_size = encoded_rules[offset];
        offset += 1;


        // Destination _
        //  _ IP
        memcpy(&curr_rule->dst_ip,encoded_rules + offset,4);
        offset += 4;
        //  _ MASK
        memcpy(&curr_rule->dst_prefix_mask,encoded_rules + offset,4);
        offset += 4;
        //  _ /k value
        curr_rule->dst_prefix_size = encoded_rules[offset];
        offset += 1;
        
        // Port _
        //  _ Source
        memcpy(&curr_rule->src_port,encoded_rules + offset,2);
        offset += 2;
        //  _ Destination
        memcpy(&curr_rule->dst_port,encoded_rules + offset,2);
        offset += 2;


        // Protocol
        //  No checks
        curr_rule->protocol = encoded_rules[offset];
        offset += 1;

        // ACK bit
        curr_rule->ack = encoded_rules[offset];
        offset += 1;

        // Action
        curr_rule->action = encoded_rules[offset];
        offset += 1;

        curr_rule_index++;
    }

    // Finally set static rules counter to the amount of loaded rules
    active_rules_count = rules_count;

    return RULES_UPDATE_SUCCESS;
}