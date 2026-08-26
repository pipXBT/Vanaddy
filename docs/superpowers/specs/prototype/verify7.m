#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
typedef struct { uint32_t count, iters, finalize, pad; } Params;
static id<MTLDevice> dev; static id<MTLCommandQueue> q; static id<MTLLibrary> lib;
static id<MTLComputePipelineState> PRO, ITER; static NSUInteger TG=256;
static void pack_keyblock(const char*p,uint64_t*o){size_t n=strlen(p);uint8_t b[128];memset(b,0,128);memcpy(b,p,n);
  for(int i=0;i<16;i++){uint64_t v=0;for(int j=0;j<8;j++)v=(v<<8)|b[8*i+j];o[i]=v;}}
static void pack_saltblock(const char*s,uint64_t*o){size_t n=strlen(s);uint8_t b[128];memset(b,0,128);memcpy(b,s,n);
  b[n+3]=1;b[n+4]=0x80;uint64_t bits=(uint64_t)(128+n+4)*8;for(int j=0;j<16;j++)b[112+j]=(uint8_t)(j<8?0:(bits>>(8*(15-j))));
  for(int i=0;i<16;i++){uint64_t v=0;for(int j=0;j<8;j++)v=(v<<8)|b[8*i+j];o[i]=v;}}
static double run_wave(id<MTLBuffer>keys,id<MTLBuffer>states,id<MTLBuffer>seeds,const uint64_t*sb,
                       uint32_t count,uint32_t R,int cpb,int depth){
  CFAbsoluteTime t0=CFAbsoluteTimeGetCurrent(); Params p={count,0,0,0};
  @autoreleasepool{ id<MTLCommandBuffer> cb=[q commandBuffer]; id<MTLComputeCommandEncoder> e=[cb computeCommandEncoder];
    [e setComputePipelineState:PRO];[e setBuffer:keys offset:0 atIndex:0];[e setBuffer:states offset:0 atIndex:1];
    [e setBytes:sb length:128 atIndex:2];[e setBytes:&p length:sizeof(p) atIndex:3];
    [e dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(TG,1,1)];[e endEncoding];[cb commit];[cb waitUntilCompleted];}
  id<MTLCommandBuffer> ring[8]; for(int i=0;i<8;i++) ring[i]=nil; int rem=2047, slot=0;
  while(rem>0){ @autoreleasepool{
      if(ring[slot]) [ring[slot] waitUntilCompleted];
      id<MTLCommandBuffer> cb=[q commandBuffer]; id<MTLComputeCommandEncoder> e=[cb computeCommandEncoder];
      [e setComputePipelineState:ITER];[e setBuffer:states offset:0 atIndex:0];[e setBuffer:seeds offset:0 atIndex:1];
      for(int k=0;k<cpb && rem>0;k++){ uint32_t r=(uint32_t)(rem<(int)R?rem:R); rem-=r;
        Params ip={count,r,(uint32_t)(rem==0),0};
        [e setBytes:&ip length:sizeof(ip) atIndex:2];
        [e dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(TG,1,1)];}
      [e endEncoding];[cb commit]; ring[slot]=cb; slot=(slot+1)%depth; } }
  for(int i=0;i<8;i++) if(ring[i]) { [ring[i] waitUntilCompleted]; if(ring[i].status!=MTLCommandBufferStatusCompleted) printf("  !! cb status=%ld err=%s\n",(long)ring[i].status,[[ring[i].error localizedDescription] UTF8String]); }
  return CFAbsoluteTimeGetCurrent()-t0;
}
int main(void){@autoreleasepool{
 dev=MTLCreateSystemDefaultDevice();q=[dev newCommandQueue];NSError*e=nil;
 NSString*src=[NSString stringWithContentsOfFile:@"pbkdf2_bip39.metal" encoding:NSUTF8StringEncoding error:&e];
 lib=[dev newLibraryWithSource:src options:[MTLCompileOptions new] error:&e];
 PRO=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pbkdf2_prologue"] error:&e];
 ITER=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pbkdf2_iterate"] error:&e];
 id<MTLBuffer> keys=[dev newBufferWithLength:8192*128 options:MTLResourceStorageModeShared];
 id<MTLBuffer> states=[dev newBufferWithLength:8192*256 options:MTLResourceStorageModeShared];
 id<MTLBuffer> seeds=[dev newBufferWithLength:8192*64 options:MTLResourceStorageModeShared];
 uint64_t sb[16]; pack_saltblock("mnemonic",sb);
 const char*VEC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
 for(uint32_t k=0;k<8192;k++) pack_keyblock(VEC,(uint64_t*)keys.contents+16*k);
 printf("== 5 repeats each, wave 8192, depth 3 ==\n%6s %7s | %s\n","R","disp/cb","seeds/s x5 (median)");
 struct{uint32_t R;int cpb;} C[]={{8,4},{8,8},{8,16},{16,4},{16,8},{4,16},{2,32}};
 for(int i=0;i<7;i++){
   double v[5]; run_wave(keys,states,seeds,sb,8192,C[i].R,C[i].cpb,3);
   for(int r=0;r<5;r++) v[r]=8192.0/run_wave(keys,states,seeds,sb,8192,C[i].R,C[i].cpb,3);
   for(int a=0;a<5;a++)for(int b=a+1;b<5;b++) if(v[b]<v[a]){double t=v[a];v[a]=v[b];v[b]=t;}
   int nd=(2047+C[i].R-1)/C[i].R;
   printf("%6u %7d | %6.0f %6.0f %6.0f %6.0f %6.0f  median %6.0f   %5.2f ms/kernel  %d cmdbufs/wave\n",
     C[i].R,C[i].cpb,v[0],v[1],v[2],v[3],v[4],v[2], 8192.0/v[2]*1e3/(nd+1), (nd+C[i].cpb-1)/C[i].cpb+1);
 }
 return 0;}}
