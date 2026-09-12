// The pairing code has to exist before anything happens: power on, open the
// web UI, claim the device on the site, never having run a game. So it must
// be readable right after the callbacks are registered -- no session, no
// device-auth event, and with or without a provisioned key -- and must not
// change from one session to the next.
#include <stdio.h>
#include <string.h>
#include "mobile_data.h"
#include "commands.h"
#include "config.h"

static unsigned char store[MOBILE_CONFIG_SIZE];
static bool have_key = true;
static bool cb_cr(void *u, void *d, uintptr_t o, size_t s){(void)u;memcpy(d,store+o,s);return true;}
static bool cb_cw(void *u, const void *s, uintptr_t o, size_t n){(void)u;memcpy(store+o,s,n);return true;}
static unsigned cb_id(void *u, void *d, unsigned s){(void)u;const char*i="reon-test-host";unsigned n=strlen(i);if(n>s)return 0;memcpy(d,i,n);return n;}
static uint16_t ck(unsigned char*b,unsigned l){uint16_t s=0;while(l--)s+=*b++;return s;}
static int checks, failures;
static void check(const char *l, bool c){checks++;if(!c)failures++;printf("%s %s\n",c?"PASS":"FAIL",l);}

static struct mobile_adapter *make(void) {
    memset(store, 0xFF, sizeof(store));
    if (have_key) {
        unsigned char da[0x2D];
        da[0]='D'; da[1]='A'; da[2]=0;
        for (int i=0;i<32;i++) da[5+i]=(unsigned char)(0x40+i);
        for (int i=0;i<8;i++) da[0x25+i]=0;
        uint16_t s=ck(da+5,sizeof(da)-5); da[3]=s&0xff; da[4]=s>>8;
        memcpy(store+0x160, da, sizeof(da));
    }
    struct mobile_adapter *a = mobile_new(NULL);
    mobile_def_config_read(a, cb_cr);
    mobile_def_config_write(a, cb_cw);
    mobile_def_device_identity(a, cb_id, "picoadaptergb");
    mobile_config_load(a);
    return a;
}

int main(void) {
    char code[MOBILE_PAIRING_CODE_STR_SIZE], again[MOBILE_PAIRING_CODE_STR_SIZE];

    // Straight after registering: no mobile_start(), no session, no event.
    struct mobile_adapter *a = make();
    check("readable right after registration, before mobile_start()",
        mobile_device_auth_get_pairing_code(a, code));
    printf("     -> %s\n", code);

    // Sessions come and go; the code must not.
    mobile_start(a);
    for (int i = 0; i < 3; i++) {
        a->commands.ppp_id_size = 10;
        memcpy(a->commands.ppp_id, "g000000034", 10);
        mobile_device_auth_session_start(a);
    }
    check("unchanged across three sessions",
        mobile_device_auth_get_pairing_code(a, again) && strcmp(code, again) == 0);

    // A device with no key provisioned still has an identity to show.
    have_key = false;
    struct mobile_adapter *b = make();
    check("still readable with no device-auth key provisioned",
        mobile_device_auth_get_pairing_code(b, again) && strcmp(code, again) == 0);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
