// utility stuff and functions

#define hexdump(buf, len) print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, (buf), (len))

void send_reset(struct sk_buff *oldskb, int hook);
bool filter(unsigned char *data, size_t len);