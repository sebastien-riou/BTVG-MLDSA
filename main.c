#include <setjmp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hdrbg.h"
/*
// Three instances of mldsa-native for all security levels 
#define MLD_CONFIG_FILE "multilevel_config.h"

// Include level-independent code 
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED 1
// Keep level-independent headers at the end of monobuild file 
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.c"
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLD_CONFIG_PARAMETER_SET

// Exclude level-independent code 
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.c"
// `#undef` all headers at the and of the monobuild file 
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLD_CONFIG_PARAMETER_SET

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
*/


#define MLD_CONFIG_API_CONSTANTS_ONLY
#include <mldsa_native.h>

#define mldsa44_keypair_internal PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal
int PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
                                 uint8_t sk[MLDSA44_SECRETKEYBYTES],
                                 const uint8_t seed[MLDSA_SEEDBYTES]);

#define mldsa65_keypair_internal PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal
int PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
                                 uint8_t sk[MLDSA65_SECRETKEYBYTES],
                                 const uint8_t seed[MLDSA_SEEDBYTES]);

#define mldsa87_keypair_internal PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal
int PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
                                 uint8_t sk[MLDSA87_SECRETKEYBYTES],
                                 const uint8_t seed[MLDSA_SEEDBYTES]);

#define mldsa44_signature PQCP_MLDSA_NATIVE_MLDSA44_signature
int PQCP_MLDSA_NATIVE_MLDSA44_signature(uint8_t sig[MLDSA44_BYTES], size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *ctx,
                          size_t ctxlen,
                const uint8_t sk[MLDSA44_SECRETKEYBYTES]);

#define mldsa65_signature PQCP_MLDSA_NATIVE_MLDSA65_signature
int PQCP_MLDSA_NATIVE_MLDSA65_signature(uint8_t sig[MLDSA65_BYTES], size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *ctx,
                          size_t ctxlen,
                const uint8_t sk[MLDSA65_SECRETKEYBYTES]);

#define mldsa87_signature PQCP_MLDSA_NATIVE_MLDSA87_signature
int PQCP_MLDSA_NATIVE_MLDSA87_signature(uint8_t sig[MLDSA65_BYTES], size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *ctx,
                          size_t ctxlen,
                const uint8_t sk[MLDSA87_SECRETKEYBYTES]);

#define mldsa44_verify PQCP_MLDSA_NATIVE_MLDSA44_verify
int PQCP_MLDSA_NATIVE_MLDSA44_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t pk[MLDSA44_PUBLICKEYBYTES]);

#define mldsa65_verify PQCP_MLDSA_NATIVE_MLDSA65_verify
int PQCP_MLDSA_NATIVE_MLDSA65_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t pk[MLDSA65_PUBLICKEYBYTES]);

#define mldsa87_verify PQCP_MLDSA_NATIVE_MLDSA87_verify
int PQCP_MLDSA_NATIVE_MLDSA87_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t pk[MLDSA87_PUBLICKEYBYTES]);

extern uint32_t PQCP_MLDSA_NATIVE_MLDSA44_mldsa_native_repetitions;
extern uint32_t PQCP_MLDSA_NATIVE_MLDSA65_mldsa_native_repetitions;
extern uint32_t PQCP_MLDSA_NATIVE_MLDSA87_mldsa_native_repetitions;
extern uint32_t PQCP_MLDSA_NATIVE_MLDSA44_mldsa_native_repetitions_causes[4];
extern uint32_t PQCP_MLDSA_NATIVE_MLDSA65_mldsa_native_repetitions_causes[4];
extern uint32_t PQCP_MLDSA_NATIVE_MLDSA87_mldsa_native_repetitions_causes[4];


void randombytes(uint8_t *buf, size_t n){
  memset(buf,0,n);//we want deterministic mode, not hedged mode.
}

void dump_core(uintptr_t addr, uintptr_t size, uintptr_t display_addr){
  printf("@0x%08lx, %lu bytes:\n",display_addr, size);
  uint8_t*r = (uint8_t*)addr;
  while(size){
    printf("%02x ",*r++);
    size--;
  }
  printf("\n");
}

void dump(void*addr, uintptr_t size){
  dump_core((uintptr_t)addr,size,(uintptr_t)addr);
}

static jmp_buf main_exception_ctx;
static jmp_buf*exception_ctx = &main_exception_ctx;
jmp_buf*get_exception_ctx(){
  return exception_ctx;
}
jmp_buf*set_exception_ctx(jmp_buf*new_exception_ctx){
  jmp_buf*old = exception_ctx;
  exception_ctx = new_exception_ctx;
  return old;
}
void throw_exception(uint32_t err_code){
  longjmp(*exception_ctx,err_code);
}
#define MLDSA44 1
#define MLDSA65 2
#define MLDSA87 4
int main(int argc, const char*argv[]){
    uint64_t hdrbg_seed = 0;
    uint64_t offset = 0;
    size_t message_size = 69;
    unsigned int mldsa44 = 0;
    unsigned int mldsa65 = 0;
    unsigned int mldsa87 = 0;
    unsigned int log_aborts = 1;
    unsigned int verify = 0;
    uint64_t ntrials = 1000*1000;
    unsigned int min_repetitions = 1;
    unsigned int exact_repetitions = 0;
    unsigned int only1 = 0;
/*
    {
      uint8_t entropy[32] = {0};
      const uint8_t nonce[32] = {0};
      struct hdrbg_t *drbg = hdrbg_init2(0,entropy,sizeof entropy, nonce, sizeof nonce,0,0);
      if(NULL==drbg) throw_exception(__LINE__);
      struct hdrbg_t drbg1,drbg2,drbg3,drbg4;
      memcpy(&drbg1,drbg,sizeof(struct hdrbg_t));
      memcpy(&drbg2,drbg,sizeof(struct hdrbg_t));
      memcpy(&drbg3,drbg,sizeof(struct hdrbg_t));
      memcpy(&drbg4,drbg,sizeof(struct hdrbg_t));
      uint8_t tmp[4];
      uint8_t add_input=1;
      hdrbg_fill2(&drbg1,0,tmp,sizeof tmp,&add_input,1);
      dump(&tmp,sizeof tmp);
      add_input=2;
      hdrbg_fill2(&drbg2,0,tmp,sizeof tmp,&add_input,1);
      dump(&tmp,sizeof tmp);
      add_input=2;
      hdrbg_fill2(&drbg3,0,tmp,sizeof tmp,&add_input,1);
      dump(&tmp,sizeof tmp);
      add_input=1;
      hdrbg_fill2(&drbg4,0,tmp,sizeof tmp,&add_input,1);
      dump(&tmp,sizeof tmp);
    }
*/
    for(int i=1;i<argc;i++){
      const char*seed_str = "--hdrbg-seed=";
      if(0==memcmp(argv[i],seed_str,strlen(seed_str))){
        const char*seed_val_str = argv[i]+strlen(seed_str);
        hdrbg_seed = strtoul(seed_val_str,0,0);
        continue;
      }
      const char*offset_str = "--offset=";
      if(0==memcmp(argv[i],offset_str,strlen(offset_str))){
        const char*offset_val_str = argv[i]+strlen(offset_str);
        offset = strtoul(offset_val_str,0,0);
        continue;
      }
      const char*msgsize_str = "--msg-size=";
      if(0==memcmp(argv[i],msgsize_str,strlen(msgsize_str))){
        const char*msgsize_val_str = argv[i]+strlen(msgsize_str);
        char*end;
        message_size = strtoull(msgsize_val_str,&end,0);
        size_t factor=1;
        if(*end=='K' || *end=='k') factor = 1024;
        if(*end=='M' || *end=='m') factor = 1024*1024;
        if(*end=='G' || *end=='g') factor = 1024*1024*1024;
        message_size *= factor;
        continue;
      }
      const char*ntrials_str = "--n-trials=";
      if(0==memcmp(argv[i],ntrials_str,strlen(ntrials_str))){
        const char*ntrials_val_str = argv[i]+strlen(ntrials_str);
        char*end;
        ntrials = strtoull(ntrials_val_str,&end,0);
        size_t factor=1;
        if(*end=='K' || *end=='k') factor = 1024;
        if(*end=='M' || *end=='m') factor = 1024*1024;
        if(*end=='G' || *end=='g') factor = 1024*1024*1024;
        ntrials *= factor;
        continue;
      }
      const char*min_repetitions_str = "--min-repetitions=";
      if(0==memcmp(argv[i],min_repetitions_str,strlen(min_repetitions_str))){
        const char*min_repetitions_val_str = argv[i]+strlen(min_repetitions_str);
        min_repetitions = strtoull(min_repetitions_val_str,0,0);
        continue;
      }
      const char*exact_str = "--exact-repetitions";
      if(0==memcmp(argv[i],exact_str,strlen(exact_str))){
        exact_repetitions = 1;
        continue;
      }
      const char*only1_str = "--only1";
      if(0==memcmp(argv[i],only1_str,strlen(only1_str))){
        only1 = 1;
        continue;
      }
      const char*mldsa44_str = "mldsa44";
      if(0==memcmp(argv[i],mldsa44_str,strlen(mldsa44_str))){
        mldsa44 = 1;
        continue;
      }
      const char*mldsa65_str = "mldsa65";
      if(0==memcmp(argv[i],mldsa65_str,strlen(mldsa65_str))){
        mldsa65 = 1;
        continue;
      }
      const char*mldsa87_str = "mldsa87";
      if(0==memcmp(argv[i],mldsa87_str,strlen(mldsa87_str))){
        mldsa87 = 1;
        continue;
      }
      const char*verify_str = "--verify";
      if(0==memcmp(argv[i],verify_str,strlen(verify_str))){
        verify = 1;
        continue;
      }
      printf("ERROR unsupported command line argument: '%s'\n",argv[i]);
      abort();
    }
    const uint32_t pset = (mldsa87<<2)|(mldsa65<<1)|mldsa44;
    size_t sksize,pksize,sigsize;
    unsigned int mldsa_pset;
    switch(pset){
      case MLDSA44:
        mldsa_pset=44;
        sksize=MLDSA44_SECRETKEYBYTES;
        pksize=MLDSA44_PUBLICKEYBYTES;
        sigsize=MLDSA44_BYTES;
        break;
      case MLDSA65:
        mldsa_pset=65;
        sksize=MLDSA65_SECRETKEYBYTES;
        pksize=MLDSA65_PUBLICKEYBYTES;
        sigsize=MLDSA65_BYTES;
        break;
      case MLDSA87:
        mldsa_pset=87;
        sksize=MLDSA87_SECRETKEYBYTES;
        pksize=MLDSA87_PUBLICKEYBYTES;
        sigsize=MLDSA87_BYTES;
        break;
      default:
        if(0==pset) printf("ERROR unsupported command line: need exactly one mldsa* argument, none have been found.\n");
        else printf("ERROR unsupported command line: need exactly one mldsa* argument, several have been found.");
        abort();
    }

    uint32_t err_code=0;
    uint8_t*message=0;
    uint64_t sum_rep=0,total_sum_rep=0;
    uint64_t sum_z=0,total_sum_z=0;
    uint64_t sum_r=0, total_sum_r=0;
    uint64_t sum_t0=0,total_sum_t0=0;
    uint64_t sum_h=0, total_sum_h=0;
    uint64_t reported_cnt=0;
    uint64_t trials_cnt=0;
    uint32_t max_repetitions=0;
    if(0 == (err_code = setjmp(main_exception_ctx))){
      uint8_t entropy[32] = {0};
      const uint8_t nonce[32] = {0};
      dump(&hdrbg_seed,sizeof hdrbg_seed);
      memcpy(entropy,&hdrbg_seed,sizeof hdrbg_seed);
      struct hdrbg_t *drbg = hdrbg_init2(0,entropy,sizeof entropy, nonce, sizeof nonce,0,0);
      if(NULL==drbg) throw_exception(__LINE__);
      struct hdrbg_t drbg_msg;
      memcpy(&drbg_msg,drbg,sizeof(struct hdrbg_t));
      uint8_t seed[32];
      hdrbg_fill(drbg,0,seed,sizeof seed);
      dump(seed,sizeof seed);
      uint8_t pk[pksize];
      uint8_t sk[sksize];
      switch(mldsa_pset){
        case 44: if(mldsa44_keypair_internal(pk, sk, seed)){
            throw_exception(__LINE__);
          }
          break;
        case 65: if(mldsa65_keypair_internal(pk, sk, seed)){
            throw_exception(__LINE__);
          }
          break;
        case 87: if(mldsa87_keypair_internal(pk, sk, seed)){
            throw_exception(__LINE__);
          }
          break;
        default:
          throw_exception(__LINE__);
      }
      dump(&sk,sizeof(sk));
      dump(&pk,sizeof(pk));
      const unsigned int ctx_size = 0;
      printf("%u\n",mldsa_pset);
      printf("%u\n",ctx_size);
      printf("%lu\n",message_size);
      message = malloc(message_size);
      if(!message) throw_exception(__LINE__);
      //drbg_get_bytes(&ccore_deterministic_mode_ctx, message,message_size);
      //for(unsigned int i = 0; i < message_size; i++){message[i] = 1+(i%8);}
      memset(message,0,message_size);
      uint8_t sig[sigsize];
      for(uint64_t i=0;i<ntrials;i++){
        uint64_t idx = i+offset;
        struct hdrbg_t drbg_msg_tmp;
        memcpy(&drbg_msg_tmp,&drbg_msg,sizeof(struct hdrbg_t));//fork drbg_msg
        hdrbg_fill2(&drbg_msg_tmp,0,message,8,(uint8_t*)&idx,sizeof idx);//inject trial counter to get a unique message that we can jump to easily
        //dump(message,8);
        uint32_t mldsa_native_repetitions;
        uint32_t*causes=0;
        switch(mldsa_pset){
          case 44: if(mldsa44_signature(sig,&sigsize,message, message_size, 0, 0, sk)){
              throw_exception(__LINE__);
            }
            mldsa_native_repetitions=PQCP_MLDSA_NATIVE_MLDSA44_mldsa_native_repetitions;
            causes = PQCP_MLDSA_NATIVE_MLDSA44_mldsa_native_repetitions_causes;
            break;
          case 65: if(mldsa65_signature(sig,&sigsize,message, message_size, 0, 0, sk)){
              throw_exception(__LINE__);
            }
            mldsa_native_repetitions=PQCP_MLDSA_NATIVE_MLDSA65_mldsa_native_repetitions;
            causes = PQCP_MLDSA_NATIVE_MLDSA65_mldsa_native_repetitions_causes;
            break;
          case 87: if(mldsa87_signature(sig,&sigsize,message, message_size, 0, 0, sk)){
              throw_exception(__LINE__);
            }
            mldsa_native_repetitions=PQCP_MLDSA_NATIVE_MLDSA87_mldsa_native_repetitions;
            causes = PQCP_MLDSA_NATIVE_MLDSA87_mldsa_native_repetitions_causes;
            break;
          default:
            throw_exception(__LINE__);
        }
        //dump(&sig,sizeof(sig));
        //if(mldsa87_verify(sig,sigsize,message, message_size,0,0,pk)) throw_exception(__LINE__);
        if(verify){
          switch(mldsa_pset){
            case 44: if(mldsa44_verify(sig,sigsize,message, message_size, 0, 0, pk)){
                throw_exception(__LINE__);
              }
              break;
            case 65: if(mldsa65_verify(sig,sigsize,message, message_size, 0, 0, pk)){
                throw_exception(__LINE__);
              }
              break;
            case 87: if(mldsa87_verify(sig,sigsize,message, message_size, 0, 0, pk)){
                throw_exception(__LINE__);
              }
              break;
            default:
              throw_exception(__LINE__);
          }
        }
        trials_cnt++;
        total_sum_rep += mldsa_native_repetitions;
        if(max_repetitions<mldsa_native_repetitions) max_repetitions=mldsa_native_repetitions;
        total_sum_z += causes[0];
        total_sum_r += causes[1];
        total_sum_t0+= causes[2];
        total_sum_h += causes[3];
        //printf("repetitions = %u\n",mldsa_native_repetitions);
        if(mldsa_native_repetitions >= min_repetitions){
          if(exact_repetitions && (mldsa_native_repetitions != min_repetitions)) continue;
          reported_cnt++;
          uint32_t n_aborts_z=causes[0];
          uint32_t n_aborts_r=causes[1];
          uint32_t n_aborts_t0=causes[2];
          uint32_t n_aborts_h=causes[3];
          sum_rep += mldsa_native_repetitions;
          sum_z += n_aborts_z;
          sum_r += n_aborts_r;
          sum_t0 += n_aborts_t0;
          sum_h += n_aborts_h;
          if(log_aborts){
            //uint64_t msg64;
            //memcpy(&msg64,message,sizeof msg64);
            //printf("\r%10lu, %2u, %2u, %2u, %2u, %2u, %5lu, %5lu, 0x%016lx\n",idx,mldsa_native_repetitions,n_aborts_z,n_aborts_r, n_aborts_t0,n_aborts_h,sum_z,sum_r,msg64);
            printf("\r%10lu, %2u, %2u, %2u, %2u, %2u, %5lu, %5lu\n",idx,mldsa_native_repetitions,n_aborts_z,n_aborts_r, n_aborts_t0,n_aborts_h,sum_z,sum_r);
          }else{
            printf("\r%10lu,%2u\n",idx,mldsa_native_repetitions);
          }
          if(only1) break;
          //if(min_repetitions>1){
          //  min_repetitions = mldsa_native_repetitions + 1;
          //}
        }else{
          if(0==(i%(1024*1024))){
            printf("\r%10lu",i);
            fflush(stdout);
          }
        }
      }
    } else {
      //exception
      printf("EXCEPTION: %u (0x%x)\n",err_code,err_code);
    } 
    if(message){
      free(message);
    }
    printf("\n");
    printf("Stats over the %lu reported cases:\n", reported_cnt);
    printf("\tSums: repetitions=%lu, z=%lu, r=%lu, t0=%lu, h=%lu\n", sum_rep,sum_z, sum_r, sum_t0, sum_h);
    printf("\tAverages: repetitions=%f, z=%f, r=%f, t0=%f, h=%f\n",((double)sum_rep)/reported_cnt,((double)sum_z)/reported_cnt, ((double)sum_r)/reported_cnt, ((double)sum_t0)/reported_cnt, ((double)sum_h)/reported_cnt);
    printf("Stats over all %lu trials:\n", trials_cnt);
    printf("\tSums: repetitions=%lu, z=%lu, r=%lu, t0=%lu, h=%lu\n", total_sum_rep,total_sum_z, total_sum_r, total_sum_t0, total_sum_h);
    printf("\tAverages: repetitions=%f, z=%f, r=%f, t0=%f, h=%f\n",((double)total_sum_rep)/trials_cnt,((double)total_sum_z)/trials_cnt, ((double)total_sum_r)/trials_cnt, ((double)total_sum_t0)/trials_cnt, ((double)total_sum_h)/trials_cnt);
    printf("\tMaximum repetitions: %u\n",max_repetitions);
    printf("done.\n");
    return 0;
}