// utility stuff and functions

#define hexdump(buf, len) print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (buf), (len))

#define MAX_GET_LINE_LEN    (512) // good enough for us
#define GET_PREFIX          "GET "
#define GET_PREFIX_LEN      (sizeof(GET_PREFIX) - 1)

// string filters;
struct sfilter {
    size_t num_matches;
    char **matches;
};
extern struct sfilter sfilters[];
extern size_t num_sfilters;

struct sk_buff;
void send_reset(struct sk_buff *oldskb, int hook);
bool run_sfilters(char *s);
