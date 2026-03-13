#include "../include/np_types.hh"
#include "../src/security/ratelimit.cc"
#include <cassert>
#include <cstdio>
#include <thread>
#include <chrono>
static int ok=0,fail=0;
#define CHK(c,m) do{if(c){ok++;printf("  ✓ %s\n",m);}else{fail++;printf("  ✗ FAIL: %s\n",m);}}while(0)

void test_allow_within_burst(){
    RateLimiter rl({1000.0,50.0,0,10}); // 1000/s rate, burst=50
    int blocked=0;
    for(int i=0;i<50;i++) if(rl.check("1.2.3.4")) blocked++;
    CHK(blocked==0,"50 requests within burst all pass");
}
void test_block_over_burst(){
    RateLimiter rl({1.0/60.0,5.0,0,10}); // 1/min = very slow refill, burst=5
    int blocked=0,allowed=0;
    for(int i=0;i<20;i++){
        if(rl.check("10.0.0.1")) blocked++;
        else allowed++;
    }
    CHK(allowed==5,   "exactly burst=5 allowed");
    CHK(blocked==15,  "15 blocked after burst");
}
void test_different_ips_independent(){
    RateLimiter rl({1.0/60.0,3.0,0,10}); // burst=3
    for(int i=0;i<3;i++){rl.check("1.1.1.1");rl.check("2.2.2.2");}
    bool b1=rl.check("1.1.1.1"), b2=rl.check("2.2.2.2");
    CHK(b1, "IP 1.1.1.1 blocked after burst=3");
    CHK(b2, "IP 2.2.2.2 blocked after burst=3");
}
void test_retry_after(){
    RateLimiter rl({1.0,2.0,0,10}); // 1 token/sec, burst=2
    rl.check("5.5.5.5"); rl.check("5.5.5.5"); // drain burst
    int64_t retry=0;
    bool blocked=rl.check("5.5.5.5",&retry);
    CHK(blocked,    "blocked after burst exhausted");
    CHK(retry>0,    "retry_after_ms > 0");
    CHK(retry<2000, "retry_after_ms < 2000ms (1 token/sec)");
}
void test_conn_limit(){
    RateLimiter rl({100.0,100.0,3,10}); // max 3 concurrent conns
    CHK(!rl.conn_add("7.7.7.7"), "conn 1 allowed");
    CHK(!rl.conn_add("7.7.7.7"), "conn 2 allowed");
    CHK(!rl.conn_add("7.7.7.7"), "conn 3 allowed");
    CHK( rl.conn_add("7.7.7.7"), "conn 4 blocked (max=3)");
    rl.conn_remove("7.7.7.7");
    CHK(!rl.conn_add("7.7.7.7"), "conn allowed after removal");
}
int main(){
    printf("=== Rate Limiter ===\n\n");
    test_allow_within_burst(); test_block_over_burst();
    test_different_ips_independent(); test_retry_after(); test_conn_limit();
    printf("\n%d passed, %d failed\n",ok,fail);
    return fail>0?1:0;
}
