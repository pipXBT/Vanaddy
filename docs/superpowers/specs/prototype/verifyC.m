#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <CommonCrypto/CommonKeyDerivation.h>

typedef struct { uint32_t count, iters, finalize, pad; } Params;

static id<MTLDevice> dev; static id<MTLCommandQueue> q; static id<MTLLibrary> lib;
static id<MTLComputePipelineState> PRO, ITER;

static void pack_keyblock(const char *phrase, uint64_t *out16) {
    size_t n = strlen(phrase);
    assert(n <= 128);
    uint8_t b[128]; memset(b,0,128); memcpy(b,phrase,n);
    for (int i=0;i<16;i++){ uint64_t v=0; for(int j=0;j<8;j++) v=(v<<8)|b[8*i+j]; out16[i]=v; }
}
static void pack_saltblock(const char *salt, uint64_t *out16) {
    size_t n = strlen(salt);
    assert(n <= 107);
    uint8_t b[128]; memset(b,0,128); memcpy(b,salt,n);
    b[n]=0; b[n+1]=0; b[n+2]=0; b[n+3]=1;          // INT(1), big-endian
    b[n+4]=0x80;
    uint64_t bits = (uint64_t)(128 + n + 4) * 8;
    for (int j=0;j<16;j++) b[112+j] = (uint8_t)(j<8 ? 0 : (bits >> (8*(15-j))));
    for (int i=0;i<16;i++){ uint64_t v=0; for(int j=0;j<8;j++) v=(v<<8)|b[8*i+j]; out16[i]=v; }
}
static NSUInteger tgsize(id<MTLComputePipelineState> p){ NSUInteger t=p.maxTotalThreadsPerThreadgroup; return t>256?256:t; }

static void encode(id<MTLCommandBuffer> cb, id<MTLComputePipelineState> p,
                   id<MTLBuffer>b0, id<MTLBuffer>b1, const void*u2, size_t u2len,
                   const void*u3, size_t u3len, NSUInteger threads){
    id<MTLComputeCommandEncoder> e=[cb computeCommandEncoder];
    [e setComputePipelineState:p];
    [e setBuffer:b0 offset:0 atIndex:0];
    [e setBuffer:b1 offset:0 atIndex:1];
    [e setBytes:u2 length:u2len atIndex:2];
    if (u3) [e setBytes:u3 length:u3len atIndex:3];
    [e dispatchThreads:MTLSizeMake(threads,1,1) threadsPerThreadgroup:MTLSizeMake(tgsize(p),1,1)];
    [e endEncoding];
}

// Run a whole wave with an explicit chunk schedule. Returns seeds buffer.
static void run_wave(id<MTLBuffer> keys, id<MTLBuffer> states, id<MTLBuffer> seeds,
                     const uint64_t *saltblock, uint32_t count,
                     const uint32_t *chunks, int nchunks) {
    Params p = { count, 0, 0, 0 };
    id<MTLCommandBuffer> cb=[q commandBuffer];
    encode(cb, PRO, keys, states, saltblock, 128, &p, sizeof(p), count);
    [cb commit]; [cb waitUntilCompleted];
    for (int c=0;c<nchunks;c++){
        Params ip = { count, chunks[c], (uint32_t)(c==nchunks-1), 0 };
        id<MTLCommandBuffer> cb2=[q commandBuffer];
        id<MTLComputeCommandEncoder> e=[cb2 computeCommandEncoder];
        [e setComputePipelineState:ITER];
        [e setBuffer:states offset:0 atIndex:0];
        [e setBuffer:seeds  offset:0 atIndex:1];
        [e setBytes:&ip length:sizeof(ip) atIndex:2];
        [e dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tgsize(ITER),1,1)];
        [e endEncoding];[cb2 commit];[cb2 waitUntilCompleted];
    }
}
static void hexs(const uint8_t*b,int n,char*o){ for(int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); o[2*n]=0; }

int main(void){@autoreleasepool{
 dev=MTLCreateSystemDefaultDevice(); q=[dev newCommandQueue]; NSError*e=nil;
 NSString*src=[NSString stringWithContentsOfFile:@"pbkdf2_bip39.metal" encoding:NSUTF8StringEncoding error:&e];
 CFAbsoluteTime c0=CFAbsoluteTimeGetCurrent();
 MTLCompileOptions*op=[MTLCompileOptions new];
 lib=[dev newLibraryWithSource:src options:op error:&e];
 if(!lib){ printf("COMPILE FAIL: %s\n",[[e localizedDescription] UTF8String]); return 1; }
 double compile_ms=(CFAbsoluteTimeGetCurrent()-c0)*1e3;
 CFAbsoluteTime p0=CFAbsoluteTimeGetCurrent();
 PRO =[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pbkdf2_prologue"] error:&e];
 ITER=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pbkdf2_iterate"]  error:&e];
 id<MTLComputePipelineState> ABC=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"sha512_abc"] error:&e];
 double pipe_ms=(CFAbsoluteTimeGetCurrent()-p0)*1e3;
 printf("device: %s\n", [[dev name] UTF8String]);
 printf("newLibraryWithSource: %.1f ms   pipelines: %.1f ms\n", compile_ms, pipe_ms);
 printf("pbkdf2_iterate  maxTotalThreadsPerThreadgroup=%lu threadExecutionWidth=%lu\n",
   (unsigned long)ITER.maxTotalThreadsPerThreadgroup,(unsigned long)ITER.threadExecutionWidth);
 printf("pbkdf2_prologue maxTotalThreadsPerThreadgroup=%lu\n",(unsigned long)PRO.maxTotalThreadsPerThreadgroup);

 // ---- self-test 0: SHA-512("abc")
 id<MTLBuffer> ob=[dev newBufferWithLength:64 options:MTLResourceStorageModeShared];
 { id<MTLCommandBuffer> cb=[q commandBuffer]; id<MTLComputeCommandEncoder> en=[cb computeCommandEncoder];
   [en setComputePipelineState:ABC]; [en setBuffer:ob offset:0 atIndex:0];
   [en dispatchThreads:MTLSizeMake(32,1,1) threadsPerThreadgroup:MTLSizeMake(32,1,1)];
   [en endEncoding];[cb commit];[cb waitUntilCompleted]; }
 uint64_t*w=(uint64_t*)ob.contents; uint8_t d[64]; for(int i=0;i<8;i++) for(int j=0;j<8;j++) d[8*i+j]=(uint8_t)(w[i]>>(56-8*j));
 char hx[200]; hexs(d,64,hx);
 printf("sha512(\"abc\") %s  %s\n", strcmp(hx,"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")?"MISMATCH":"OK", hx);

 // ---- buffers
 const uint32_t MAXC = 8192;
 id<MTLBuffer> keys  =[dev newBufferWithLength:MAXC*128 options:MTLResourceStorageModeShared];
 id<MTLBuffer> states=[dev newBufferWithLength:MAXC*256 options:MTLResourceStorageModeShared];
 id<MTLBuffer> seeds =[dev newBufferWithLength:MAXC*64  options:MTLResourceStorageModeShared];
 uint64_t sb[16]; pack_saltblock("mnemonic", sb);

 const char *VEC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
 const char *EXP="5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

 // ---- test 1..N: BIP-39 canonical vector under many chunk schedules
 struct { const char*name; uint32_t ch[300]; int n; } S[] = {
   {"one dispatch (2047)",              {2047},1},
   {"16 x 127 + 15",                    {0},0},
   {"1 x 2047",                         {0},0},
   {"irregular [1,1000,46,1000]",       {1,1000,46,1000},4},
   {"irregular [2046,1]",               {2046,1},2},
   {"irregular [1,1,2045]",             {1,1,2045},3},
 };
 // build the regular schedules
 S[1].n=0; { int rem=2047; while(rem>0){int r=rem<16?rem:16; S[1].ch[S[1].n++]=r; rem-=r;} }
 S[2].n=0; // 2047 chunks of 1 is too many for the array; use 64 chunks of 32 minus tail
 { int rem=2047; while(rem>0 && S[2].n<299){int r=rem<32?rem:32; S[2].ch[S[2].n++]=r; rem-=r;} if(rem>0) S[2].ch[S[2].n++]=rem; }
 S[2].name="32 x 63 + 31";
 for (int t=0;t<6;t++){
   pack_keyblock(VEC,(uint64_t*)keys.contents);
   run_wave(keys,states,seeds,sb,1,S[t].ch,S[t].n);
   hexs((uint8_t*)seeds.contents,64,hx);
   printf("BIP-39 vector, %-24s (%2d dispatches): %s\n",S[t].name,S[t].n, strcmp(hx,EXP)?"MISMATCH":"OK");
   if(strcmp(hx,EXP)) printf("   got %s\n",hx);
 }

 // ---- test: full wave of distinct phrases vs CommonCrypto PBKDF2-HMAC-SHA512
 const uint32_t N=2048;
 char **pw=malloc(sizeof(char*)*N);
 for (uint32_t i=0;i<N;i++){
   // vary length across the whole 1..128 range, including the boundaries
   int len = (int)(i % 128) + 1;
   pw[i]=malloc(len+1);
   for(int j=0;j<len;j++) pw[i][j]=(char)('a'+((i*31+j*7)%26));
   pw[i][len]=0;
   pack_keyblock(pw[i], (uint64_t*)keys.contents + 16*i);
 }
 uint32_t ch16[128]; int n16=0; { int rem=2047; while(rem>0){int r=rem<16?rem:16; ch16[n16++]=r; rem-=r;} }
 run_wave(keys,states,seeds,sb,N,ch16,n16);
 int bad=0;
 for (uint32_t i=0;i<N;i++){
   uint8_t ref[64];
   CCKeyDerivationPBKDF(kCCPBKDF2, pw[i], strlen(pw[i]), (const uint8_t*)"mnemonic", 8,
                        kCCPRFHmacAlgSHA512, 2048, ref, 64);
   if (memcmp(ref, (uint8_t*)seeds.contents + 64*i, 64)) { if(bad<5) printf("  MISMATCH i=%u len=%zu\n",i,strlen(pw[i])); bad++; }
 }
 printf("wave of %u distinct passwords (len 1..128) vs CommonCrypto: %s (%d bad)\n", N, bad?"FAIL":"OK", bad);

 // ---- throughput WITH the T accumulator (the prototype had none)
 printf("\n== sustained throughput, prologue + %d chunks of 16, wave=%u ==\n", n16, MAXC);
 for (int rep=0;rep<3;rep++){
   CFAbsoluteTime t0=CFAbsoluteTimeGetCurrent();
   run_wave(keys,states,seeds,sb,MAXC,ch16,n16);
   double s=CFAbsoluteTimeGetCurrent()-t0;
   double comps=(double)MAXC*4098.0;
   printf("  wave %.3f s   %.2f Mcomp/s   %.0f seeds/s   %.2f ms/dispatch\n",
     s, comps/s/1e6, MAXC/s, s*1e3/(n16+1));
 }
 return 0;}}
