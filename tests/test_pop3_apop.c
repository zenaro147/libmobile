// Exercises the APOP path in pop3_auth.c end to end: a real Dovecot-style
// greeting, the faked local USER ack, the APOP command sent to the server
// (checked byte-for-byte against a digest computed independently in
// Python), a rejected APOP with no fallback, and the legacy no-key
// passthrough. Talks to pop3_auth.c directly (not through commands.c's
// connection dispatch), simulating the real server with a scripted byte
// stream, same style as the other /tmp harnesses.
#include <stdio.h>
#include <string.h>
#include "mobile_data.h"
#include "commands.h"
#include "pop3_auth.h"

static struct mobile_adapter adapter_storage;
static struct mobile_adapter *adapter;

// --- fake "real server" on the other end of sock_send/sock_recv ---
static unsigned char server_inbox[4096];
static unsigned server_inbox_len;
static const unsigned char *server_script;
static unsigned server_script_len, server_script_pos;

static bool cb_config_write(void *user, const void *src, uintptr_t offset, size_t size)
{ (void)user; (void)src; (void)offset; (void)size; return true; }

static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr)
{
    (void)user; (void)conn; (void)addr;
    memcpy(server_inbox + server_inbox_len, data, size);
    server_inbox_len += size;
    return (int)size;
}

static int cb_sock_recv(void *user, unsigned conn, void *data, unsigned size, struct mobile_addr *addr)
{
    (void)user; (void)conn; (void)addr;
    unsigned avail = server_script_len - server_script_pos;
    if (!avail) return 0;
    unsigned n = avail < size ? avail : size;
    memcpy(data, server_script + server_script_pos, n);
    server_script_pos += n;
    return (int)n;
}

static char debug_buf[8192];
static unsigned debug_len;
static void cb_debug_log(void *user, const char *line)
{ (void)user; debug_len += (unsigned)snprintf(debug_buf + debug_len, sizeof(debug_buf) - debug_len, "%s", line); }

static void reset_adapter(void)
{
    memset(&adapter_storage, 0, sizeof(adapter_storage));
    adapter = &adapter_storage;
    mobile_def_config_write(adapter, cb_config_write);
    mobile_def_sock_send(adapter, cb_sock_send);
    mobile_def_sock_recv(adapter, cb_sock_recv);
    mobile_def_debug_log(adapter, cb_debug_log);

    static const unsigned char ppp_id[] = "USER1234";
    memcpy(adapter->commands.ppp_id, ppp_id, sizeof(ppp_id) - 1);
    adapter->commands.ppp_id_size = sizeof(ppp_id) - 1;

    server_inbox_len = 0;
    debug_len = 0;
}

static int checks, failures;
static void check(const char *label, bool cond)
{
    checks++;
    if (!cond) failures++;
    printf("%s %s\n", cond ? "PASS" : "FAIL", label);
}

// Feeds `data` to mobile_pop3_auth_send() as the game's outgoing bytes.
static void game_sends(const char *data)
{
    mobile_pop3_auth_send(adapter, 0, data, (unsigned)strlen(data));
}

// Pumps mobile_pop3_auth_recv() until it stops returning progress, into buf.
static unsigned game_recvs(unsigned char *buf, unsigned cap)
{
    unsigned total = 0;
    for (int guard = 0; guard < 20; guard++) {
        int n = mobile_pop3_auth_recv(adapter, 0, buf + total, cap - total);
        if (n <= 0) break;
        total += (unsigned)n;
    }
    return total;
}

int main(void)
{
    // Key used for both the "real vector" case and the reject case: bytes
    // 0x00..0x1f, hex = "000102...1e1f" -- matches the Python reference.
    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    for (unsigned i = 0; i < sizeof(key); i++) key[i] = (unsigned char)i;

    // === Case 1: real Dovecot-style greeting, key provisioned -> APOP ===
    {
        reset_adapter();
        mobile_config_set_device_auth_key(adapter, key);
        mobile_pop3_auth_start(adapter, 0);

        static const unsigned char greeting[] =
            "+OK Dovecot ready. <6e185.1.6aa4b34e.dsgVuOBZQTokS8OajKgT1A==@instance-20260829-1803>\r\n";
        server_script = greeting;
        server_script_len = sizeof(greeting) - 1;
        server_script_pos = 0;

        unsigned char out[256];
        unsigned n = game_recvs(out, sizeof(out));
        check("greeting forwarded to game verbatim",
            n == server_script_len && memcmp(out, greeting, n) == 0);

        game_sends("USER anything\r\n");
        n = game_recvs(out, sizeof(out));
        check("USER gets a faked local +OK (never touches the server)",
            n >= 3 && memcmp(out, "+OK", 3) == 0 && server_inbox_len == 0);

        game_sends("PASS whatever\r\n");
        // queue_send() only stages the line; the actual sock_send() happens
        // inside recv()'s flush_send_retry() -- pump it once (with no
        // server bytes available yet) to drive that flush.
        server_script = (const unsigned char *)""; server_script_len = 0; server_script_pos = 0;
        game_recvs(out, sizeof(out));
        check("APOP line sent to the server, not USER/PASS",
            memcmp(server_inbox, "APOP ", 5) == 0);
        check("APOP carries ppp_id as the user",
            memcmp(server_inbox + 5, "USER1234 ", 9) == 0);
        check("APOP digest matches the independently-computed reference",
            memcmp(server_inbox + 5 + 9, "0efb4ab40b73501675e0a259a51eb4c5", 32) == 0);
        check("APOP line is exactly 5+8+1+32+2 bytes, CRLF-terminated",
            server_inbox_len == 5 + 8 + 1 + 32 + 2 &&
            server_inbox[server_inbox_len - 2] == '\r' &&
            server_inbox[server_inbox_len - 1] == '\n');

        static const unsigned char resp[] = "+OK Logged in.\r\n";
        server_script = resp;
        server_script_len = sizeof(resp) - 1;
        server_script_pos = 0;
        n = game_recvs(out, sizeof(out));
        check("successful APOP response passed straight to the game",
            n == server_script_len && memcmp(out, resp, n) == 0);
        check("no extra round trip afterwards (no XPROVISION exists anymore)",
            mobile_pop3_auth_done(adapter, 0));
    }

    // === Case 2: APOP rejected -- no fallback, error goes straight through ===
    {
        reset_adapter();
        mobile_config_set_device_auth_key(adapter, key);
        mobile_pop3_auth_start(adapter, 0);

        static const unsigned char greeting[] =
            "+OK Dovecot ready. <different.token@host>\r\n";
        server_script = greeting; server_script_len = sizeof(greeting) - 1; server_script_pos = 0;
        unsigned char out[256];
        game_recvs(out, sizeof(out));
        game_sends("USER x\r\n");
        game_recvs(out, sizeof(out));
        game_sends("PASS y\r\n");

        static const unsigned char err[] = "-ERR [AUTH] authentication failed\r\n";
        server_script = err; server_script_len = sizeof(err) - 1; server_script_pos = 0;
        unsigned n = game_recvs(out, sizeof(out));
        check("rejected APOP is passed to the game as a real error",
            n == server_script_len && memcmp(out, err, n) == 0);
        check("no second attempt was made against the server (send_retry not reused)",
            server_inbox_len == 5 + 8 + 1 + 32 + 2); // only the one APOP line, ever
        check("the rejection was logged loudly",
            strstr(debug_buf, "REJECTED") != NULL);
        check("session ends in DONE either way", mobile_pop3_auth_done(adapter, 0));
    }

    // === Case 3: no key provisioned -- classic transparent passthrough ===
    {
        reset_adapter();
        // device_auth_key_init left false: mobile_config_set_device_auth_key()
        // is simply never called.
        mobile_pop3_auth_start(adapter, 0);

        static const unsigned char greeting[] =
            "+OK Dovecot ready. <tok@host>\r\n";
        server_script = greeting; server_script_len = sizeof(greeting) - 1; server_script_pos = 0;
        unsigned char out[256];
        game_recvs(out, sizeof(out));

        game_sends("USER realuser\r\n");
        server_script = (const unsigned char *)""; server_script_len = 0; server_script_pos = 0;
        game_recvs(out, sizeof(out));
        check("USER forwarded verbatim to the server (no key)",
            server_inbox_len == strlen("USER realuser\r\n") &&
            memcmp(server_inbox, "USER realuser\r\n", server_inbox_len) == 0);

        static const unsigned char user_ok[] = "+OK\r\n";
        server_script = user_ok; server_script_len = sizeof(user_ok) - 1; server_script_pos = 0;
        game_recvs(out, sizeof(out));

        server_inbox_len = 0;
        game_sends("PASS realpass\r\n");
        server_script = (const unsigned char *)""; server_script_len = 0; server_script_pos = 0;
        game_recvs(out, sizeof(out));
        check("PASS forwarded verbatim to the server (no key)",
            server_inbox_len == strlen("PASS realpass\r\n") &&
            memcmp(server_inbox, "PASS realpass\r\n", server_inbox_len) == 0);
    }

    // === Case 4: greeting has no "<...>" token -- degrades like no key ===
    {
        reset_adapter();
        mobile_config_set_device_auth_key(adapter, key);
        mobile_pop3_auth_start(adapter, 0);

        static const unsigned char greeting[] = "+OK hello there\r\n";
        server_script = greeting; server_script_len = sizeof(greeting) - 1; server_script_pos = 0;
        unsigned char out[256];
        game_recvs(out, sizeof(out));

        game_sends("USER realuser\r\n");
        server_script = (const unsigned char *)""; server_script_len = 0; server_script_pos = 0;
        game_recvs(out, sizeof(out));
        check("no challenge in greeting -> USER forwarded, not faked",
            server_inbox_len == strlen("USER realuser\r\n"));
    }

    // === Case 5: greeting mentions '<' earlier -- the LAST token wins ===
    {
        reset_adapter();
        mobile_config_set_device_auth_key(adapter, key);
        mobile_pop3_auth_start(adapter, 0);

        static const unsigned char greeting[] =
            "+OK <decoy> service ready <real.one@host>\r\n";
        server_script = greeting; server_script_len = sizeof(greeting) - 1; server_script_pos = 0;
        unsigned char out[256];
        game_recvs(out, sizeof(out));
        game_sends("USER x\r\n");
        game_recvs(out, sizeof(out));
        game_sends("PASS y\r\n");
        server_script = (const unsigned char *)""; server_script_len = 0; server_script_pos = 0;
        game_recvs(out, sizeof(out));

        // Digest for "<real.one@host>" (the last token), computed
        // independently in Python -- if find_challenge() had picked the
        // earlier "<decoy>" instead, this would not match.
        check("the LAST '<...>' token was used, not the first",
            memcmp(server_inbox + 5 + 9, "191d64b4a7309d77682270af66773d48", 32) == 0);
    }

    // === Case 6: our own POP3 on 110, dual nonce (bare form kept for
    // legacy XAPOP clients, bracketed RFC 1939 form appended at the end) ===
    {
        reset_adapter();
        mobile_config_set_device_auth_key(adapter, key);
        mobile_pop3_auth_start(adapter, 0);

        static const unsigned char greeting[] =
            "+OK service ready a360860c55044640df4e4def793039d2@reon.dion.ne.jp "
            "<a360860c55044640df4e4def793039d2@reon.dion.ne.jp>\r\n";
        server_script = greeting; server_script_len = sizeof(greeting) - 1; server_script_pos = 0;
        unsigned char out[256];
        game_recvs(out, sizeof(out));
        game_sends("USER x\r\n");
        game_recvs(out, sizeof(out));
        game_sends("PASS y\r\n");
        server_script = (const unsigned char *)""; server_script_len = 0; server_script_pos = 0;
        game_recvs(out, sizeof(out));

        // Digest for the bracketed token only -- if the parser had grabbed
        // the bare nonce (no brackets) or the whole tail instead, this
        // exact digest, computed independently in Python, would not match.
        check("dual-nonce greeting: the bracketed RFC 1939 token is used",
            memcmp(server_inbox, "APOP ", 5) == 0 &&
            memcmp(server_inbox + 5 + 9, "f3be1249443864b166865d2c718dd937", 32) == 0);
    }

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
