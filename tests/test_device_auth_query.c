// The counter query, end to end: signed request carrying a fresh counter,
// signed answer echoing it, and the rules that keep a hostile or stale
// answer from stranding the device or locking it out.
//
// Every query consumes a counter (that is what makes the echo fresh even for
// a device nothing else changes about), so the values below follow the
// counter through catch-up and authorization: queries go out at 1, 2, 3, 4,
// then -- after catching up to 500 and one authorize at 501 -- at 502.
//
// Vectors computed independently (Python hashlib/hmac), key = 0x40..0x5f,
// ppp_id g000000034, identity "reon-test-host", frontend "mgba" -> device
// a4a290f8b2bd1a42.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mobile_data.h"
#include "commands.h"
#include "config.h"

static unsigned char store[MOBILE_CONFIG_SIZE];
static bool cb_config_read(void *u, void *d, uintptr_t o, size_t n){(void)u;memcpy(d,store+o,n);return true;}
static bool cb_config_write(void *u, const void *s, uintptr_t o, size_t n){(void)u;memcpy(store+o,s,n);return true;}
static bool cb_sock_open(void *u, unsigned c, enum mobile_socktype t, enum mobile_addrtype a, unsigned b){(void)u;(void)c;(void)t;(void)a;(void)b;return true;}
static void cb_sock_close(void *u, unsigned c){(void)u;(void)c;}
static int cb_sock_connect(void *u, unsigned c, const struct mobile_addr *a){(void)u;(void)c;(void)a;return 1;}

static unsigned char dns_reply[512]; static unsigned dns_reply_len, dns_reply_pos;
static struct mobile_addr last_send_addr;
static int cb_sock_send(void *u, unsigned c, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)u;(void)c; if (addr) last_send_addr = *addr;
    unsigned char *q=(unsigned char*)data, r[512]; unsigned n=0;
    r[n++]=q[0];r[n++]=q[1];r[n++]=0x81;r[n++]=0x80;r[n++]=0;r[n++]=1;r[n++]=0;r[n++]=1;r[n++]=0;r[n++]=0;r[n++]=0;r[n++]=0;
    unsigned ql=0; unsigned char *qq=q+12; while(qq[ql]!=0) ql+=qq[ql]+1; ql+=1+4;
    memcpy(r+n,q+12,ql); n+=ql;
    r[n++]=0xC0;r[n++]=12;r[n++]=0;r[n++]=1;r[n++]=0;r[n++]=1;r[n++]=0;r[n++]=0;r[n++]=0;r[n++]=60;r[n++]=0;r[n++]=4;
    r[n++]=7;r[n++]=7;r[n++]=7;r[n++]=7;
    memcpy(dns_reply,r,n); dns_reply_len=n; dns_reply_pos=0; return (int)size;
}
static int cb_sock_recv(void *u, unsigned c, void *data, unsigned size, struct mobile_addr *addr) {
    (void)u;(void)c; unsigned avail=dns_reply_len-dns_reply_pos; if(!avail) return 0;
    unsigned n=avail<size?avail:size; memcpy(data,dns_reply+dns_reply_pos,n); dns_reply_pos+=n;
    if (addr){struct mobile_addr4*a4=(struct mobile_addr4*)addr;a4->type=MOBILE_ADDRTYPE_IPV4;
        a4->port=((struct mobile_addr4*)&last_send_addr)->port;memcpy(a4->host,((struct mobile_addr4*)&last_send_addr)->host,4);}
    return (int)n;
}
static unsigned cb_identity(void *u, void *d, unsigned s){(void)u;const char*i="reon-test-host";unsigned n=strlen(i);if(n>s)return 0;memcpy(d,i,n);return n;}

static int query_calls; static char query_sig[65]; static uint64_t query_counter; static unsigned char query_addr[4];
static bool cb_query(void *u, const unsigned char *addr, const unsigned char *ppp, unsigned pn, uint64_t counter, const unsigned char *sig, const char *dev) {
    (void)u;(void)ppp;(void)pn;(void)dev; query_calls++; query_counter=counter; memcpy(query_addr,addr,4);
    for (int i=0;i<32;i++) sprintf(query_sig+i*2,"%02x",sig[i]);
    return true;
}
static int auth_calls; static uint64_t last_counter;
static void cb_auth(void *u, enum mobile_device_auth_action a, const unsigned char *p, unsigned pn, uint64_t counter, const unsigned char *sig, const unsigned char *addr, const char *dev) {
    (void)u;(void)a;(void)p;(void)pn;(void)sig;(void)addr;(void)dev; auth_calls++; last_counter=counter;
}
static int dns_lookups; static char last_log[256];
static void cb_log(void *u, const char *l){(void)u; if(strstr(l,"Resolving")) dns_lookups++; snprintf(last_log,sizeof last_log,"%s",l); fputs(l,stderr);}
static bool cb_time(void *u, unsigned t, unsigned ms){(void)u;(void)t;(void)ms;return false;}

static uint16_t ck(unsigned char*b,unsigned l){uint16_t s=0;while(l--)s+=*b++;return s;}
static int checks, failures;
static void check(const char *l, bool c){checks++;if(!c)failures++;printf("%s %s\n",c?"PASS":"FAIL",l);}

static struct mobile_adapter *A;
static void tick(int n){for(int i=0;i<n;i++){A->global.active=true;mobile_actions_process(A,mobile_actions_get(A));}}
static void session(void){A->commands.session_started=true;A->commands.state=MOBILE_CONNECTION_INTERNET;A->commands.ppp_id_size=10;memcpy(A->commands.ppp_id,"g000000034",10);mobile_device_auth_session_start(A);}
static void answer(const char *body){mobile_device_auth_query_result(A,body,(unsigned)strlen(body));}
static const char *sigs(void){return query_sig;}

// Runs one game command through the processor and returns its error code,
// or -1 if the command was accepted (started processing / answered).
static int command_error(enum mobile_command cmd, const void *data, unsigned len) {
    unsigned char buf[64]; memcpy(buf,data,len);
    struct mobile_packet pk={.command=cmd,.length=(unsigned char)len,.data=buf};
    A->buffer.commands.processing=0;
    struct mobile_packet *r=mobile_commands_process(A,&pk);
    if (!r) return -1;
    return r->command==MOBILE_COMMAND_ERROR ? r->data[1] : -1;
}

int main(void) {
    memset(store,0xFF,sizeof store);
    unsigned char da[0x2D]; da[0]='D';da[1]='A';da[2]=0;
    for(int i=0;i<32;i++) da[5+i]=(unsigned char)(0x40+i);
    for(int i=0;i<8;i++) da[0x25+i]=0;
    uint16_t s=ck(da+5,sizeof(da)-5); da[3]=s&0xff; da[4]=s>>8; memcpy(store+0x160,da,sizeof da);

    A=mobile_new(NULL);
    mobile_def_config_read(A,cb_config_read); mobile_def_config_write(A,cb_config_write);
    mobile_def_sock_open(A,cb_sock_open); mobile_def_sock_close(A,cb_sock_close); mobile_def_sock_connect(A,cb_sock_connect);
    mobile_def_sock_send(A,cb_sock_send); mobile_def_sock_recv(A,cb_sock_recv);
    mobile_def_update_device_auth(A,cb_auth); mobile_def_device_identity(A,cb_identity,"mgba");
    mobile_def_device_auth_query(A,cb_query); mobile_def_debug_log(A,cb_log); mobile_def_time_check_ms(A,cb_time);
    mobile_config_load(A); mobile_start(A);
    struct mobile_addr4 dns1={.type=MOBILE_ADDRTYPE_IPV4,.port=53}; memcpy(dns1.host,(unsigned char[]){9,9,9,9},4);
    mobile_config_set_dns(A,(struct mobile_addr*)&dns1,MOBILE_DNS1);

    // ---- Session A: the query goes out, counter 1, and the server says blocked.
    session(); tick(8);
    check("A: query fired on session bring-up", query_calls==1);
    check("A: query spent counter 1", query_counter==1);
    check("A: query signed over ppp|device|query|1",
        strcmp(sigs(),"bb1c69863c3bf6fcbd95f21637293d37e38a22670bac1a2795d2d6ee01c90d3f")==0);
    check("A: carried the resolved address", memcmp(query_addr,"\x07\x07\x07\x07",4)==0);
    check("A: state is UNKNOWN until an answer verifies", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN);
    answer("blocked 1 6bec8a6ea634ed4703f4cf66077a327e7844c78780d96ddb4671de7db25a783c");
    check("A: verified blocked answer -> YES", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_YES);
    check("A: DNS_REQUEST refused with the ordinary lookup failure (2)",
        command_error(MOBILE_COMMAND_DNS_REQUEST,"pop.reon.dion.ne.jp",19)==2);
    check("A: TCP_CONNECT refused with the ordinary connection failure (3)",
        command_error(MOBILE_COMMAND_TCP_CONNECT,"\x01\x02\x03\x04\x00\x6e",6)==3);

    // ---- Session B: block state is per-session; a replayed old answer is not fresh.
    session(); tick(8);
    check("B: new session starts UNKNOWN again (never persisted)", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN);
    check("B: query spent counter 2", query_counter==2 && query_calls==2);
    answer("blocked 1 6bec8a6ea634ed4703f4cf66077a327e7844c78780d96ddb4671de7db25a783c");
    check("B: replayed 'blocked 1' rejected: echo is not this query's", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN);
    check("B: ...and the log says why", strstr(last_log,"echoes a different query")!=NULL);
    check("B: UNKNOWN fails open: DNS_REQUEST not refused", command_error(MOBILE_COMMAND_DNS_REQUEST,"pop.reon.dion.ne.jp",19)!=2);

    // ---- Session C: garbage fails open too, and is logged rather than dropped silently.
    session(); tick(8);
    check("C: query spent counter 3", query_counter==3);
    answer("definitely not a counter");
    check("C: malformed answer leaves UNKNOWN", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN);
    check("C: ...and is logged", strstr(last_log,"expected form")!=NULL);

    // ---- Session D: a genuine answer, with a stray newline, confirms NOT blocked and catches up.
    session(); tick(8);
    check("D: query spent counter 4", query_counter==4);
    answer("500 4 cd2334519611770fea4efa54401c1834210456f405190c0fc6b6f7964267178f\n");
    check("D: verified normal answer -> NO", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_NO);
    mobile_device_auth_notify(A,MOBILE_DEVICE_AUTH_AUTHORIZE,(const unsigned char*)"g000000034",10); tick(8);
    check("D: counter caught up: authorize went out at 501", auth_calls==1 && last_counter==501);

    // ---- Session E: an authorize waiting on the query is dropped, not sent, once blocked.
    session(); tick(8);
    check("E: query spent counter 502 (past the authorize)", query_counter==502);
    check("E: query signed over ...|query|502",
        strcmp(sigs(),"5ca62f48c07e451709379471b91a0008e1742b74fee75a26ba1d2c592341b5c9")==0);
    mobile_device_auth_notify(A,MOBILE_DEVICE_AUTH_AUTHORIZE,(const unsigned char*)"g000000034",10); tick(8);
    check("E: authorize held while the answer is on its way", auth_calls==1 && A->device_auth.pending);
    answer("blocked 502 666ad8e74ff593963d4d646b00fc135640b4b9ae0ce0c376f4c6567324fcfadb");
    check("E: fresh blocked answer -> YES", mobile_device_auth_block_state(A)==MOBILE_DEVICE_AUTH_BLOCK_YES);
    tick(8);
    check("E: the held authorize was dropped, not sent into a 403", auth_calls==1 && !A->device_auth.pending);

    check("one DNS lookup across five sessions", dns_lookups==1);
    printf("\n%d/%d checks passed\n",checks-failures,checks);
    return failures?1:0;
}
