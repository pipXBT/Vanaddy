// Vanaddy GPU PBKDF2-HMAC-SHA512 (BIP-39 seed derivation).
// dkLen == 64 => exactly one output block, so T = U_1 ^ ... ^ U_c.
#include <metal_stdlib>
using namespace metal;

constant ulong K[80] = {
0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817};
constant ulong H0[8] = {
0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179};

inline ulong ror64(ulong x, uint n) { return rotate(x, (ulong)(64u - n)); }

// General SHA-512 compression over a caller-supplied 16-word block (destroys w).
inline void sha512_compress(thread ulong *st, thread ulong *w) {
    ulong a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
#pragma unroll(16)
    for (uint i = 0; i < 80; i++) {
        if (i >= 16) {
            ulong x=w[(i+1)&15], y=w[(i+14)&15];
            ulong s0 = ror64(x,1) ^ ror64(x,8) ^ (x >> 7);
            ulong s1 = ror64(y,19) ^ ror64(y,61) ^ (y >> 6);
            w[i&15] = w[i&15] + s0 + w[(i+9)&15] + s1;
        }
        ulong S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
        ulong t1 = h + S1 + ((e & f) ^ (~e & g)) + K[i] + w[i&15];
        ulong S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        ulong t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

// SHA-512 compression for the fixed PBKDF2 shape: one 128-byte key block already
// absorbed, message == 64-byte digest, so the padded block is
// msg[0..8] || 0x80.. || 0*6 || (128+64)*8. Schedule tail folded to constants.
inline void sha512_hash64(thread ulong *st, thread const ulong *msg) {
    ulong w[16];
#pragma unroll
    for (uint i=0;i<8;i++) w[i]=msg[i];
    w[8]=0x8000000000000000UL; w[9]=0;w[10]=0;w[11]=0;w[12]=0;w[13]=0;w[14]=0;
    w[15]=(128+64)*8;
    ulong a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
#pragma unroll(16)
    for (uint i=0;i<80;i++) {
        if (i>=16) {
            ulong x=w[(i+1)&15], y=w[(i+14)&15];
            ulong s0=ror64(x,1)^ror64(x,8)^(x>>7);
            ulong s1=ror64(y,19)^ror64(y,61)^(y>>6);
            w[i&15]=w[i&15]+s0+w[(i+9)&15]+s1;
        }
        ulong S1=ror64(e,14)^ror64(e,18)^ror64(e,41);
        ulong t1=h+S1+((e&f)^(~e&g))+K[i]+w[i&15];
        ulong S0=ror64(a,28)^ror64(a,34)^ror64(a,39);
        ulong t2=S0+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

// Per-candidate resumable PBKDF2 state. 32 ulongs = 256 B, 8-byte aligned.
struct Pbkdf2State {
    ulong inner[8];   // SHA-512 state after absorbing K0 ^ ipad
    ulong outer[8];   // SHA-512 state after absorbing K0 ^ opad
    ulong u[8];       // U_j
    ulong t[8];       // T = U_1 ^ .. ^ U_j
};

struct Params {
    uint count;      // live candidates in this wave
    uint iters;      // U-iterations to advance in THIS dispatch
    uint finalize;   // nonzero => write big-endian seed bytes
    uint _pad;
};

// 4 compressions per candidate: ipad, opad, U_1 inner, U_1 outer.
kernel void pbkdf2_prologue(device const ulong  *keyblocks [[buffer(0)]],
                            device Pbkdf2State  *states    [[buffer(1)]],
                            constant ulong      *saltblock [[buffer(2)]],
                            constant Params     &p         [[buffer(3)]],
                            uint tid [[thread_position_in_grid]])
{
    if (tid >= p.count) return;
    device const ulong *kb = keyblocks + 16 * (ulong)tid;
    ulong w[16], ist[8], ost[8], st[8], u[8];

#pragma unroll
    for (uint i=0;i<16;i++) w[i] = kb[i] ^ 0x3636363636363636UL;
#pragma unroll
    for (uint i=0;i<8;i++) ist[i]=H0[i];
    sha512_compress(ist, w);

#pragma unroll
    for (uint i=0;i<16;i++) w[i] = kb[i] ^ 0x5c5c5c5c5c5c5c5cUL;
#pragma unroll
    for (uint i=0;i<8;i++) ost[i]=H0[i];
    sha512_compress(ost, w);

#pragma unroll
    for (uint i=0;i<16;i++) w[i]=saltblock[i];
#pragma unroll
    for (uint i=0;i<8;i++) st[i]=ist[i];
    sha512_compress(st, w);              // inner hash of salt || INT(1)

#pragma unroll
    for (uint i=0;i<8;i++) u[i]=ost[i];
    sha512_hash64(u, st);                // U_1

    device Pbkdf2State *s = states + tid;
#pragma unroll
    for (uint i=0;i<8;i++) { s->inner[i]=ist[i]; s->outer[i]=ost[i]; s->u[i]=u[i]; s->t[i]=u[i]; }
}

// Advance p.iters U-iterations (2 compressions each). Resumable: all live state
// is in `states`, so a wave can be split across arbitrarily many dispatches.
kernel void pbkdf2_iterate(device Pbkdf2State *states [[buffer(0)]],
                           device uchar       *seeds  [[buffer(1)]],
                           constant Params    &p      [[buffer(2)]],
                           uint tid [[thread_position_in_grid]])
{
    if (tid >= p.count) return;
    device Pbkdf2State *s = states + tid;
    ulong ist[8], ost[8], u[8], t[8], st[8];
#pragma unroll
    for (uint i=0;i<8;i++) { ist[i]=s->inner[i]; ost[i]=s->outer[i]; u[i]=s->u[i]; t[i]=s->t[i]; }

    for (uint r=0; r<p.iters; r++) {
#pragma unroll
        for (uint i=0;i<8;i++) st[i]=ist[i];
        sha512_hash64(st, u);
#pragma unroll
        for (uint i=0;i<8;i++) u[i]=ost[i];
        sha512_hash64(u, st);
#pragma unroll
        for (uint i=0;i<8;i++) t[i]^=u[i];
    }

#pragma unroll
    for (uint i=0;i<8;i++) { s->u[i]=u[i]; s->t[i]=t[i]; }

    if (p.finalize) {
        device uchar *o = seeds + 64 * (ulong)tid;
#pragma unroll
        for (uint i=0;i<8;i++) {
            ulong v = t[i];
#pragma unroll
            for (uint b=0;b<8;b++) o[8*i+b] = (uchar)(v >> (56 - 8*b));
        }
    }
}

// Self-test 0: SHA-512("abc") -- isolates the general compression path.
kernel void sha512_abc(device ulong *out [[buffer(0)]], uint tid [[thread_position_in_grid]]) {
    ulong w[16]; for (uint i=0;i<16;i++) w[i]=0;
    w[0]=0x6162638000000000UL; w[15]=24;
    ulong st[8]; for (uint i=0;i<8;i++) st[i]=H0[i];
    sha512_compress(st, w);
    if (tid==0) for (uint i=0;i<8;i++) out[i]=st[i];
}

// A/B ONLY (not shipped): identical loop without the T accumulator, to isolate
// the register cost of carrying T in registers across the loop.
kernel void pbkdf2_iterate_noacc(device Pbkdf2State *states [[buffer(0)]],
                                 device uchar       *seeds  [[buffer(1)]],
                                 constant Params    &p      [[buffer(2)]],
                                 uint tid [[thread_position_in_grid]])
{
    if (tid >= p.count) return;
    device Pbkdf2State *s = states + tid;
    ulong ist[8], ost[8], u[8], st[8];
    for (uint i=0;i<8;i++) { ist[i]=s->inner[i]; ost[i]=s->outer[i]; u[i]=s->u[i]; }
    for (uint r=0; r<p.iters; r++) {
        for (uint i=0;i<8;i++) st[i]=ist[i];
        sha512_hash64(st, u);
        for (uint i=0;i<8;i++) u[i]=ost[i];
        sha512_hash64(u, st);
    }
    for (uint i=0;i<8;i++) s->u[i]=u[i];
    if (p.finalize) { device uchar *o = seeds + 64*(ulong)tid; for (uint i=0;i<8;i++){ulong v=u[i];for(uint b=0;b<8;b++)o[8*i+b]=(uchar)(v>>(56-8*b));} }
}
