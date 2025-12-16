import hdrbg
import runpy
import os,sys
from pysatl import Utils
import hashlib
import argparse
import logging
import io
import copy

def size_str(size):
    for u in [['G',1024*1024*1024],['M',1024*1024],['K',1024]]:
        divider = u[1]
        if 0 == size % divider:
            return f'{size // divider}{u[0]}'
    return f'{size}'

# A functions to generate all inputs from the parameters
def gen_mldsa_inputs(params):
    if params['ctx_size'] > 0:
        raise RuntimeError('Not implemented')

    msg_size = params['msg_size']

    #seed DRBG
    drbg = hdrbg.DRBG_SHA2_256(entropy=params['hdrbg_seed']+bytes(24),nonce=bytes(32))
    drbg_msg = copy.deepcopy(drbg)
    #take zeta out
    zeta = bytearray()
    zeta += drbg.get_bytes(32)

    #generate initial message
    message = bytearray(msg_size)

    indexes = params['indexes']
    message_size = params['msg_size']
    messages = []
    for idx in indexes:
        drbg_msg_tmp = copy.deepcopy(drbg_msg)
        hbound = min(8,message_size)
        message[0:hbound] = drbg_msg_tmp.get_bytes(hbound,additional_input=idx.to_bytes(8,byteorder='little')) 
        messages.append(bytes(message))

    # Compute M' for Sign_Internal
    mprimes = []
    for i in range(0,len(messages)):
        m = bytearray()
        m += bytes(2) #assume ctx_size=0
        m += messages[i]
        mprimes.append(bytes(m))

    # Compute Mu
    mus = []
    tr = params['sk'][64:128]
    for i in range(0,len(messages)):
        m = bytearray(tr)
        m += mprimes[i]
        mus.append(hashlib.shake_256(m).digest(64))

    return messages, mprimes, mus

def format_as_c(params, *,expand_msg=False):
    out = io.StringIO()
    def p(s,end='\n'):
        print(s,end=end,file=out)

    # Generate the inputs
    messages, mprimes, mus = gen_mldsa_inputs(params)

    # Output them as C variables
    def print_c_byte_array(name,dat,end='\n'):
        if name:
            decl = f'.{name} = '
            comma = ','
        else:
            decl = ''
            comma = ''
        p(f"{decl} {{{Utils.hexstr(dat,head='0x',separator=', ')}}}{comma}",end=end)

    def print_param_as_c_byte_array(name):
        dat = params[name]
        print_c_byte_array(name,dat)

    def print_c_ui_array(name,dat,end='\n'):
        if name:
            decl = f'.{name} = '
            comma = ','
        else:
            decl = ''
            comma = ''
        p(f"{decl} {{",end="")
        sep=""
        for e in dat:
            p(f"{sep}{e}",end="")
            sep=", "
        p(f"}}{comma}",end=end)

    def print_param_as_c_ui_array(name):
        dat = params[name]
        print_c_ui_array(name,dat)

    base_type_name = f"mldsa{params['mldsa_pset']}_m{size_str(len(messages[0]))}_test_vectors"

    #struct declaration
    nmessages = len(messages)
    message_size = len(messages[0])
    m_size = min(8,message_size)
    p(f"typedef struct {base_type_name}_struct {{")
    p(f'\tunsigned int mldsa_pset;')
    p(f'\tuint8_t hdrbg_seed[8];')
    p(f'\tuint8_t mldsa_seed[32];')
    p(f"\tuint8_t sk[{len(params['sk'])}];")
    p(f"\tuint8_t pk[{len(params['pk'])}];")
    p(f'\tunsigned int nmessages;')
    p(f"\tunsigned int repetitions[{nmessages}];")
    p(f'\tunsigned int message_size;')
    p(f"\tuint8_t sign_messages[{nmessages}][{m_size}];")
    p(f'\tunsigned int internal_message_size;')
    p(f"\tuint8_t sign_internal_messages[{nmessages}][10];")
    p(f"\tuint8_t sign_external_mu[{nmessages}][64];")
    p(f'\tuint8_t sigs_sha256_digest[32];')
    p(f"}} {base_type_name}_t;")

    #value declaration
    p(f"const {base_type_name}_t {base_type_name} = {{")
    p(f".mldsa_pset = {params['mldsa_pset']},")
    print_param_as_c_byte_array('hdrbg_seed')
    print_param_as_c_byte_array('mldsa_seed')
    print_param_as_c_byte_array('sk')
    print_param_as_c_byte_array('pk')

    p(f".nmessages = {nmessages},")
    print_param_as_c_ui_array('repetitions')
    
    p(f'.message_size = {message_size},')
    mprime_size = message_size+2
    
    def decl_messages(name,data):
        p(f'.{name} = {{')
        for msg in data[:-1]:
            print_c_byte_array(None,msg,end=',\n')
        print_c_byte_array(None,data[-1],end='\n')
        p('},')

    if not expand_msg:
        for i in range(0,len(messages)):
            messages[i] = messages[i][0:8]
        for i in range(0,len(mprimes)):
            mprimes[i] = mprimes[i][0:10]

    # Input messages for ML-DSA.Sign
    decl_messages('sign_messages',messages)

    # Input messages for ML-DSA.Sign_Internal
    p(f'.internal_message_size = {mprime_size},')
    decl_messages('sign_internal_messages',mprimes)

    # Input messages for ML-DSA external Mu
    decl_messages('sign_external_mu',mus)

    print_param_as_c_byte_array('sigs_sha256_digest')
    p(f"}};")
    return out.getvalue()

def format_as_sv(params, *,expand_msg=False):
    out = io.StringIO()
    def p(s,end='\n'):
        print(s,end=end,file=out)
    # Generate the inputs
    messages, mprimes, mus = gen_mldsa_inputs(params)

    def int_as_sv_u64(name, v):
        if not isinstance(v,int):
            v = int.from_bytes(v,byteorder='little')
        if name:
            decl = f"logic [63:0] {name} = "
            comma = ';'
        else:
            decl = ""
            comma = ''
        return f"{decl}64'h{v:016x}{comma}"

    # Output them as SV variables
    def print_sv_array64(name,dat,end='\n'):
        nwords = (len(dat)+7)//8
        if name:
            p(f"localparam {name}_NWORDS = {nwords};")
            p(f'logic [{name}_NWORDS-1:0][63:0] {name} = ',end='')
            comma = ';'
        else:
            comma = ''
        p(f"'{{",end='')
        words = []
        for i in range(0,len(dat),8):
            words.insert(0,dat[i:i+8])
        sep = ''
        for w in words:
            p(f"{sep}{int_as_sv_u64(None,w)}",end='')
            sep=', '

        p(f"}}{comma}",end=end)

    def print_param_as_sv_u64(name):
        dat = params[name]
        p(int_as_sv_u64(name,dat))

    def print_param_as_sv_array64(name):
        dat = params[name]
        print_sv_array64(name,dat)

    p(f'localparam MLDSA_PSET = {params['mldsa_pset']};')
    print_param_as_sv_u64('hdrbg_seed')
    print_param_as_sv_array64('mldsa_seed')
    print_param_as_sv_array64('sk')
    print_param_as_sv_array64('pk')

    p(f'localparam N_MESSAGES = {len(messages)};')
    p(f'localparam MESSAGE_SIZE = {len(messages[0])};')
    mprime_size = len(messages[0])+2
    
    def decl_messages(name,data):
        nwords = (len(data[0])+7)//8
        p(f"logic [{nwords}-1:0][63:0] {name}[N_MESSAGES-1:0] = '{{")
        rdata = data[::-1] #create a copy of the list in reverse order
        for msg in rdata[:-1]:
            print_sv_array64(None,msg,end=',\n')
        print_sv_array64(None,rdata[-1],end='\n')
        p('};')

    if not expand_msg:
        for i in range(0,len(messages)):
            messages[i] = messages[i][0:8]
        for i in range(0,len(mprimes)):
            mprimes[i] = mprimes[i][0:10]

    # Input messages for ML-DSA.Sign
    decl_messages('sign_messages',messages)

    # Input messages for ML-DSA.Sign_Internal
    p(f'localparam INTERNAL_MESSAGE_SIZE = {mprime_size};')
    decl_messages('sign_internal_messages',mprimes)

    # Input messages for ML-DSA external Mu
    decl_messages('sign_external_mu',mus)

    print_param_as_sv_array64('sigs_sha256_digest')
    return out.getvalue()


if __name__ == '__main__':
    scriptname = os.path.basename(__file__)
    scriptpath = os.path.dirname(__file__)
    parser = argparse.ArgumentParser(scriptname)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='INFO', choices=levels)
    parser.add_argument('params', default=None, help='Path to input parameter file (.py)', type=str)
    formats = ('C', 'SV', 'ALL')
    parser.add_argument('format', default='C', choices=formats, help='output format')
    parser.add_argument('--expand-msg', help='Fully expand message input', action='store_true')
    parser.add_argument('--write', help='Write output to file(s)', action='store_true')

    args = parser.parse_args()
    logformat = '%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s'
    logdatefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(level=args.log_level, format=logformat, datefmt=logdatefmt)

    gen_c=False
    gen_sv=False
    match args.format:
        case 'C':
            gen_c = True
        case 'SV':
            gen_sv = True
        case 'ALL':
            gen_c = True
            gen_sv = True

    # Get the parameters
    params = runpy.run_path(args.params)
    
    out=[]
    if gen_c:
        out.append(['c',format_as_c(params,expand_msg=args.expand_msg)])
    if gen_sv:
        out.append(['sv',format_as_sv(params,expand_msg=args.expand_msg)])
    
    if args.write:
        base_name = f"mldsa{params['mldsa_pset']}-m{size_str(params['msg_size'])}-h{Utils.hexstr(params['sigs_sha256_digest'][:4],separator='')}"
        for o in out:
            with open(base_name+'.'+o[0],'w') as f:
                print(o[1],file=f)
    else:
        for o in out:
            print(f'output "{o[0]}":')
            print(o[1])