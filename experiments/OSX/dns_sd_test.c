// DNSServiceQueryRecord experiment for macOS. Mirrors the Windows
// DnsQueryEx / DnsQueryRaw experiments to allow side-by-side comparison
// of how each OS DNS API surfaces results — in particular, whether the
// additional section (A/AAAA glue for SRV targets) is preserved.
//
// Build: cmake -S . -B build && cmake --build build
// Run:   ./build/dns_sd_test [query-name]
//
// Reference wire truth with:
//   dig +noall +answer +additional SRV _caldavs._tcp.google.com @8.8.8.8

#include <dns_sd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int recordCount;
    int done;
    int verbose;
} QueryContext;

static void HexDump(const unsigned char* data, int len) {
    for (int i = 0; i < len; i += 16) {
        printf("    %04x: ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", data[i + j]);
            else             printf("   ");
        }
        printf(" |");
        for (int j = 0; j < 16 && i + j < len; j++) {
            unsigned char b = data[i + j];
            putchar((b >= 32 && b < 127) ? b : '.');
        }
        printf("|\n");
    }
}

// Decode a DNS label sequence from rdata starting at `offset` into a dotted
// string. Pointer compression is not expected inside rdata surfaced by
// DNSServiceQueryRecord (mDNSResponder decompresses), but bail out defensively
// if we see a pointer.
static int DecodeDnsName(const unsigned char* data, int len, int offset,
                         char* out, int outsize) {
    int opos = 0;
    while (offset < len) {
        int labelLen = data[offset++];
        if (labelLen == 0) break;
        if ((labelLen & 0xC0) == 0xC0) break;       // compression pointer — give up
        if (offset + labelLen > len) break;
        if (opos > 0 && opos < outsize - 1) out[opos++] = '.';
        for (int i = 0; i < labelLen && opos < outsize - 1; i++) {
            out[opos++] = (char)data[offset++];
        }
    }
    if (opos < outsize) out[opos] = '\0';
    else if (outsize > 0)    out[outsize - 1] = '\0';
    return offset;
}

static void PrintRdata(uint16_t rrtype, const unsigned char* rdata, int rdlen) {
    char buf[INET6_ADDRSTRLEN] = {0};
    switch (rrtype) {
    case kDNSServiceType_A:
        if (rdlen == 4) {
            inet_ntop(AF_INET, rdata, buf, sizeof(buf));
            printf("    A: %s\n", buf);
        }
        break;
    case kDNSServiceType_AAAA:
        if (rdlen == 16) {
            inet_ntop(AF_INET6, rdata, buf, sizeof(buf));
            printf("    AAAA: %s\n", buf);
        }
        break;
    case kDNSServiceType_SRV: {
        if (rdlen < 7) break;
        uint16_t priority = (uint16_t)((rdata[0] << 8) | rdata[1]);
        uint16_t weight   = (uint16_t)((rdata[2] << 8) | rdata[3]);
        uint16_t port     = (uint16_t)((rdata[4] << 8) | rdata[5]);
        char target[256] = {0};
        DecodeDnsName(rdata, rdlen, 6, target, sizeof(target));
        printf("    SRV: prio=%u weight=%u port=%u target=%s\n",
               priority, weight, port, target);
        break;
    }
    case kDNSServiceType_CNAME:
    case kDNSServiceType_PTR:
    case kDNSServiceType_NS: {
        char name[256] = {0};
        DecodeDnsName(rdata, rdlen, 0, name, sizeof(name));
        const char* label = rrtype == kDNSServiceType_CNAME ? "CNAME"
                          : rrtype == kDNSServiceType_PTR   ? "PTR"
                                                            : "NS";
        printf("    %s: %s\n", label, name);
        break;
    }
    case kDNSServiceType_TXT: {
        int off = 0;
        while (off < rdlen) {
            int l = rdata[off++];
            if (off + l > rdlen) break;
            printf("    TXT: \"%.*s\"\n", l, rdata + off);
            off += l;
        }
        break;
    }
    default:
        break;
    }
}

static void QueryCallback(
    DNSServiceRef sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    DNSServiceErrorType errorCode,
    const char* fullname,
    uint16_t rrtype,
    uint16_t rrclass,
    uint16_t rdlen,
    const void* rdata,
    uint32_t ttl,
    void* context)
{
    QueryContext* ctx = (QueryContext*)context;
    (void)sdRef; (void)interfaceIndex; (void)rrclass;

    if (errorCode != kDNSServiceErr_NoError) {
        printf("  [err=%d]\n", errorCode);
        ctx->done = 1;
        return;
    }

    ctx->recordCount++;

    // Compose a flag string: MoreComing signals batching, Add means "record
    // is being added" (vs removed for long-lived queries), Intermediate tags
    // CNAME hops when kDNSServiceFlagsReturnIntermediates was set.
    char flagStr[64] = {0};
    if (flags & kDNSServiceFlagsAdd)                 strcat(flagStr, "ADD ");
    if (flags & kDNSServiceFlagsMoreComing)          strcat(flagStr, "MORE-COMING ");
#ifdef kDNSServiceFlagsReturnIntermediates
    if (flags & kDNSServiceFlagsReturnIntermediates) strcat(flagStr, "INTERMEDIATE ");
#endif

    printf("  Name: %s  Type: %u  TTL: %u  rdlen: %u  [%s]\n",
           fullname, rrtype, ttl, rdlen, flagStr);
    PrintRdata(rrtype, (const unsigned char*)rdata, rdlen);
    if (ctx->verbose) {
        HexDump((const unsigned char*)rdata, rdlen);
    }

    if (!(flags & kDNSServiceFlagsMoreComing)) {
        ctx->done = 1;
    }
}

static void RunQuery(const char* name, uint16_t rrtype,
                     DNSServiceFlags flags, int verbose)
{
    QueryContext ctx = { 0, 0, verbose };
    DNSServiceRef sdRef = NULL;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    DNSServiceErrorType err = DNSServiceQueryRecord(
        &sdRef, flags, 0, name, rrtype, kDNSServiceClass_IN,
        QueryCallback, &ctx);

    if (err != kDNSServiceErr_NoError) {
        printf("  DNSServiceQueryRecord failed: %d\n", err);
        return;
    }

    int fd = DNSServiceRefSockFD(sdRef);
    while (!ctx.done) {
        fd_set rset; FD_ZERO(&rset); FD_SET(fd, &rset);
        struct timeval tv = { 5, 0 };      // 5s cap per batch
        int r = select(fd + 1, &rset, NULL, NULL, &tv);
        if (r <= 0) {
            printf("  (timeout or select error)\n");
            break;
        }
        DNSServiceProcessResult(sdRef);
    }

    DNSServiceRefDeallocate(sdRef);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
                      (t1.tv_nsec - t0.tv_nsec) / 1000000;
    printf("  Total: %d record(s), %ld ms\n", ctx.recordCount, elapsed_ms);
}

int main(int argc, char** argv) {
    const char* queryName = "example.com";
    if (argc > 1) queryName = argv[1];

    printf("Query target: %s\n", queryName);

    // Test 0: A record — baseline
    printf("\n=== Test 0: A record, default flags ===\n");
    RunQuery(queryName, kDNSServiceType_A, 0, 0);

    // Test 1: AAAA record — baseline
    printf("\n=== Test 1: AAAA record, default flags ===\n");
    RunQuery(queryName, kDNSServiceType_AAAA, 0, 0);

    // Test 2: SRV record — the headline experiment.
    // Does mDNSResponder surface A/AAAA glue from the additional section,
    // or only the SRV records matching the queried rrtype?
    printf("\n=== Test 2: SRV _caldavs._tcp.google.com (additional section?) ===\n");
    RunQuery("_caldavs._tcp.google.com", kDNSServiceType_SRV, 0, 0);

    // Test 3: A record on a CNAME — default behavior transparently chases
    // the CNAME and reports only terminal A records with the canonical name.
    printf("\n=== Test 3: A record for www.github.com (transparent CNAME chase) ===\n");
    RunQuery("www.github.com", kDNSServiceType_A, 0, 0);

    // Test 4: Same query, but with kDNSServiceFlagsReturnIntermediates —
    // each CNAME hop should be surfaced as its own callback.
    printf("\n=== Test 4: Same with kDNSServiceFlagsReturnIntermediates ===\n");
    RunQuery("www.github.com", kDNSServiceType_A,
             kDNSServiceFlagsReturnIntermediates, 0);

    // Test 5: Query CNAME record directly — should return the CNAME itself.
    printf("\n=== Test 5: CNAME record for www.github.com ===\n");
    RunQuery("www.github.com", kDNSServiceType_CNAME, 0, 0);

    // Test 6: NXDOMAIN — expect a single callback with errorCode set.
    printf("\n=== Test 6: NXDOMAIN for this-name-does-not-exist.example ===\n");
    RunQuery("this-name-does-not-exist.example", kDNSServiceType_A, 0, 0);

    return 0;
}
