// utility stuff and functions

#define hexdump(buf, len) print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (buf), (len))

#define MAX_GET_PARAMS_LEN  (512) // good enough for us
#define GET_PREFIX          "GET "
#define GET_PREFIX_LEN      (sizeof(GET_PREFIX) - 1)

#define MAX_DNS_QUERY_LEN   (2048)

#define MAX_MATCHES         (5)

// string filters;
struct sfilter {
    size_t num_matches;
    char *matches[MAX_MATCHES];
};

extern const struct sfilter get_sfilters[];
extern const size_t num_get_sfilters;

extern const struct sfilter dns_sfilters[];
extern const size_t num_dns_sfilters;

struct sk_buff;
void send_reset(struct sk_buff *oldskb, int hook);
void send_reset_server(struct sk_buff *oldskb, int hook);
void send_empty_html(struct sk_buff *oldskb, int hook);

// like kvec (but not)
struct buf {
    char *data;
    size_t len;
    bool should_free;
};
bool run_get_sfilters(const struct buf *buf);
bool run_dns_sfilters(const struct buf *buf);

void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen);
