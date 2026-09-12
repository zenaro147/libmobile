// The relay handshake carries the device id (version 1), so the relay can
// refuse a device its owner blocked -- the only enforcement point for a
// session that is P2P from the start, where no ISP login means no ppp_id
// and so no device-auth query. Checks the bytes on the wire, the reason byte
// on refusal (logged, never trusted), the core-side refusal of TEL and
// WAIT_CALL once a block is known, and that an identity absent at first is
// asked for again rather than remembered as absent.
#include <stdio.h>
#include <string.h>
#include "mobile_data.h"
#include "commands.h"
#include "config.h"
#include "relay.h"

static unsigned char store[MOBILE_CONFIG_SIZE];
static bool cb_cr(void *u, void *d, uintptr_t o, size_t n){(void)u;memcpy(d,store+o,n);return true;}
static bool cb_cw(void *u, const void *s, uintptr_t o, size_t n){(void)u;memcpy(store+o,s,n);return true;}
static bool cb_open(void *u, unsigned c, enum mobile_socktype t, enum mobile_addrtype a, unsigned b){(void)u;(void)c;(void)t;(void)a;(void)b;return true;}
static void cb_close(void *u, unsigned c){(void)u;(void)c;}
static int cb_connect(void *u, unsigned c, const struct mobile_addr *a){(void)u;(void)c;(void)a;return 1;}

static unsigned char sent[64]; static unsigned sent_len;
static int cb_send(void *u, unsigned c, const void *d, unsigned n, const struct mobile_addr *a){(void)u;(void)c;(void)a; if(n<=sizeof sent){memcpy(sent,d,n);sent_len=n;} return (int)n;}

// Scripted receive: hand out `reply` once, then report the remote closed.
static const unsigned char *reply; static unsigned reply_len; static bool reply_given;
static int cb_recv(void *u, unsigned c, void *d, unsigned n, struct mobile_addr *a){(void)u;(void)c;(void)a;
    if(!reply) return 0;
    if(reply_given) return -2;
    unsigned k=reply_len<n?reply_len:n; memcpy(d,reply,k); reply_given=true; return (int)k;}

static bool identity_available = true;
static unsigned cb_identity(void *u, void *d, unsigned s){(void)u; if(!identity_available) return 0;
    const char*i="reon-test-host"; unsigned n=strlen(i); if(n>s) return 0; memcpy(d,i,n); return n;}

static char last_log[256];
static void cb_log(void *u, const char *l){(void)u; snprintf(last_log,sizeof last_log,"%s",l); fputs(l,stderr);}
static bool cb_time(void *u, unsigned t, unsigned ms){(void)u;(void)t;(void)ms;return false;}

static uint16_t ck(unsigned char*b,unsigned l){uint16_t s=0;while(l--)s+=*b++;return s;}
static int checks, failures;
static void check(const char *l, bool c){checks++;if(!c)failures++;printf("%s %s\n",c?"PASS":"FAIL",l);}

static struct mobile_adapter *A;
static struct mobile_addr4 relay_addr = {.type=MOBILE_ADDRTYPE_IPV4,.port=31227,.host={10,0,0,1}};

// Drives the relay call state machine until the handshake has been sent.
static int handshake(void) {
    sent_len=0; reply_given=false;
    mobile_relay_init(A);
    int rc=0;
    for (int i=0;i<10 && sent_len==0;i++) rc=mobile_relay_proc_call(A,0,(struct mobile_addr*)&relay_addr,"1234567",7);
    return rc;
}
static int command_error(enum mobile_command cmd, const void *data, unsigned len) {
    unsigned char buf[64]; memcpy(buf,data,len);
    struct mobile_packet pk={.command=cmd,.length=(unsigned char)len,.data=buf};
    A->buffer.commands.processing=0;
    struct mobile_packet *r=mobile_commands_process(A,&pk);
    if(!r) return -1;
    return r->command==MOBILE_COMMAND_ERROR ? r->data[1] : -1;
}

int main(void) {
    memset(store,0xFF,sizeof store);
    unsigned char da[0x2D]; da[0]='D';da[1]='A';da[2]=0;
    for(int i=0;i<32;i++) da[5+i]=(unsigned char)(0x40+i);
    for(int i=0;i<8;i++) da[0x25+i]=0;
    uint16_t s=ck(da+5,sizeof(da)-5); da[3]=s&0xff; da[4]=s>>8; memcpy(store+0x160,da,sizeof da);

    A=mobile_new(NULL);
    mobile_def_config_read(A,cb_cr); mobile_def_config_write(A,cb_cw);
    mobile_def_sock_open(A,cb_open); mobile_def_sock_close(A,cb_close); mobile_def_sock_connect(A,cb_connect);
    mobile_def_sock_send(A,cb_send); mobile_def_sock_recv(A,cb_recv);
    mobile_def_device_identity(A,cb_identity,"mgba"); mobile_def_debug_log(A,cb_log); mobile_def_time_check_ms(A,cb_time);
    mobile_config_load(A); mobile_start(A);
    A->serial.device = MOBILE_ADAPTER_BLUE;
    unsigned char token[16]; for(int i=0;i<16;i++) token[i]=(unsigned char)(0xA0+i);
    mobile_config_set_relay_token_internal(A,token);
    mobile_config_set_relay(A,(struct mobile_addr*)&relay_addr);

    static const unsigned char raw_mgba[8]={0xa4,0xa2,0x90,0xf8,0xb2,0xbd,0x1a,0x42};

    // ---- Handshake on the wire, with an identity.
    reply=NULL; handshake();
    check("handshake is 33 bytes: [1]MOBILE + has_token + token + has_device + device", sent_len==33);
    check("version byte is 1", sent[0]==1);
    check("magic MOBILE", memcmp(sent+1,"MOBILE",6)==0);
    check("has_token=1 and the token follows", sent[7]==1 && memcmp(sent+8,token,16)==0);
    check("has_device=1", sent[24]==1);
    check("device is the raw sha256(\"mgba\"|0|identity)[:8], same as device= in hex",
        memcmp(sent+25,raw_mgba,8)==0);

    // ---- No identity yet: has_device=0, nothing after it. Then it appears,
    // and the very next handshake carries it -- absence was not remembered.
    mobile_def_device_identity(A,cb_identity,"mgba");   // clears the cached id
    identity_available=false; reply=NULL; handshake();
    check("without identity: 25 bytes, has_device=0", sent_len==25 && sent[24]==0);
    identity_available=true; reply=NULL; handshake();
    check("identity available later -> next handshake has it (failure not cached)",
        sent_len==33 && sent[24]==1 && memcmp(sent+25,raw_mgba,8)==0);

    // ---- Refused with reason 0x02: logged as blocked, but NOT trusted.
    static const unsigned char blocked_byte[1]={0x02};
    reply=blocked_byte; reply_len=1;
    int rc=handshake();
    for (int i=0;i<10 && rc==0;i++) rc=mobile_relay_proc_call(A,0,(struct mobile_addr*)&relay_addr,"1234567",7);
    check("relay refusal -> call fails", rc<0);
    check("reason byte 0x02 logged as blocked on the site", strstr(last_log,"blocked on the site")!=NULL);
    check("...but the unauthenticated byte did NOT set block_state (fail open)",
        mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN);

    // ---- Core-side refusal of TEL / WAIT_CALL once a block is known.
    A->commands.session_started=true; A->commands.state=MOBILE_CONNECTION_DISCONNECTED;
    static const unsigned char tel[]={0x00,'1','2','3','4','5','6','7'};
    A->device_auth.block_state=MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN;
    check("UNKNOWN: TEL over relay not refused by the block check", command_error(MOBILE_COMMAND_TEL,tel,sizeof tel)!=3);
    A->commands.state=MOBILE_CONNECTION_DISCONNECTED;
    A->device_auth.block_state=MOBILE_DEVICE_AUTH_BLOCK_YES;
    check("YES: TEL over relay refused with error 3", command_error(MOBILE_COMMAND_TEL,tel,sizeof tel)==3);
    A->commands.state=MOBILE_CONNECTION_DISCONNECTED;
    check("YES: WAIT_CALL over relay refused with error 0", command_error(MOBILE_COMMAND_WAIT_CALL,"",0)==0);

    // Without a relay configured, blocking cannot be enforced anywhere, and
    // the core doesn't pretend otherwise: direct P2P is out of scope.
    // Whatever the direct path does with this number, it must do the same
    // whether or not the device is blocked -- the block check lives inside
    // the relay branch and nowhere else.
    struct mobile_addr none={.type=MOBILE_ADDRTYPE_NONE};
    mobile_config_set_relay(A,&none);
    A->commands.state=MOBILE_CONNECTION_DISCONNECTED; A->device_auth.block_state=MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN;
    int direct_unknown=command_error(MOBILE_COMMAND_TEL,tel,sizeof tel);
    A->commands.state=MOBILE_CONNECTION_DISCONNECTED; A->device_auth.block_state=MOBILE_DEVICE_AUTH_BLOCK_YES;
    int direct_yes=command_error(MOBILE_COMMAND_TEL,tel,sizeof tel);
    check("no relay configured: block state makes no difference to a direct call (out of scope, not pretended)",
        direct_unknown==direct_yes);

    printf("\n%d/%d checks passed\n",checks-failures,checks);
    return failures?1:0;
}
