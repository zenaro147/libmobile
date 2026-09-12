// Feeds the exact 66-byte body captured from production into the parser and
// checks it gets past the format check. The signature can't verify here (it
// was made with the real account key, not the test key), so the point is
// precisely which rejection we land on: "isn't in the expected form" would
// mean the parser disagrees with the real server; "failed its signature" is
// the expected outcome and proves the format was accepted.
//
// This is the "old"/no-echo response form (DeviceAuthUtil.php): a request
// that doesn't carry a local counter to echo gets "<counter> <sig>" back --
// two fields, not three. It's what this core's own query request produces
// today, and this exact capture is the very first answer a brand new
// device gets (counter 0), so it's worth pinning down on its own.
#include <stdio.h>
#include <string.h>
#include "mobile_data.h"
#include "commands.h"
#include "config.h"

static unsigned char store[MOBILE_CONFIG_SIZE];
static bool cb_config_read(void *u, void *d, uintptr_t o, size_t s){(void)u;memcpy(d,store+o,s);return true;}
static bool cb_config_write(void *u, const void *s, uintptr_t o, size_t n){(void)u;memcpy(store+o,s,n);return true;}
static char log_buf[4096];
static void cb_debug_log(void *u, const char *l){(void)u;strncat(log_buf,l,sizeof(log_buf)-strlen(log_buf)-1);}
static unsigned cb_ident(void *u, void *d, unsigned s){(void)u;const char*i="reon-test-host";unsigned n=strlen(i);if(n>s)return 0;memcpy(d,i,n);return n;}
static uint16_t ck(unsigned char *b, unsigned l){uint16_t s=0;while(l--)s+=*b++;return s;}

int main(void) {
    memset(store, 0xFF, sizeof(store));
    unsigned char da[0x2D];
    da[0]='D'; da[1]='A'; da[2]=0;
    for (int i=0;i<32;i++) da[5+i]=(unsigned char)(0x40+i);
    for (int i=0;i<8;i++) da[0x25+i]=0;
    uint16_t s=ck(da+5,sizeof(da)-5); da[3]=s&0xff; da[4]=s>>8;
    memcpy(store+0x160, da, sizeof(da));

    struct mobile_adapter *a = mobile_new(NULL);
    mobile_def_config_read(a, cb_config_read);
    mobile_def_config_write(a, cb_config_write);
    mobile_def_device_identity(a, cb_ident, "test");
    mobile_def_debug_log(a, cb_debug_log);
    mobile_config_load(a);
    mobile_start(a);

    a->commands.ppp_id_size = 10;
    memcpy(a->commands.ppp_id, "g000000034", 10);
    a->device_auth.query_inflight = true;

    // The bytes exactly as od -tx1 reported them on the server: "0 " then
    // 64 lowercase hex chars, no echo field.
    static const unsigned char body[] = {
        0x30,0x20,0x33,0x64,0x37,0x30,0x66,0x61,0x63,0x62,0x30,0x62,0x38,0x36,0x33,0x38,
        0x31,0x31,0x34,0x35,0x33,0x62,0x33,0x65,0x34,0x66,0x36,0x63,0x39,0x63,0x30,0x35,
        0x34,0x64,0x33,0x61,0x32,0x61,0x64,0x32,0x39,0x33,0x30,0x32,0x63,0x62,0x37,0x30,
        0x32,0x38,0x33,0x32,0x34,0x65,0x30,0x61,0x36,0x64,0x38,0x66,0x32,0x61,0x65,0x36,
        0x61,0x35
    };
    printf("body is %zu bytes: %.*s\n", sizeof(body), (int)sizeof(body), body);
    mobile_device_auth_query_result(a, body, (unsigned)sizeof(body));

    bool form = strstr(log_buf, "expected form") != NULL;
    bool sig  = strstr(log_buf, "failed its signature") != NULL;
    printf("log: %s\n", log_buf);
    printf("%s parser accepted the real production no-echo format\n", !form && sig ? "PASS" : "FAIL");
    return (!form && sig) ? 0 : 1;
}
