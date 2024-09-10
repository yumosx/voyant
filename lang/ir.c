#include <assert.h>

#include "ir.h"
#include "ut.h"
#include "insn.h"
#include "bpfsyscall.h"
#include "buffer.h"
#include <signal.h>

static prog_t* prog;
static bb_t* curbb;
static int nreg = 1;
int nlabel = 1;
static int regnum = 3;
int gregs[3] =  {BPF_REG_6, BPF_REG_7, BPF_REG_8}; 

const struct bpf_insn break_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN);
const struct bpf_insn continue_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN + 1);
const struct bpf_insn if_then_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN + 2);
const struct bpf_insn if_else_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN + 3);

static bb_t* new_bb() {
    bb_t* bb = calloc(1, sizeof(*bb));
    
    bb->label = nlabel++;
    bb->ir = vec_new();
    bb->succ = vec_new();
    bb->pred = vec_new();
    bb->def_regs = vec_new();
    bb->in_regs = vec_new();
    bb->out_regs = vec_new();

    vec_push(prog->bbs, bb);
    return bb;
}

static ir_t* new_ir(int op) {
    ir_t* ir = calloc(1, sizeof(*ir));
    ir->op = op;
    vec_push(curbb->ir, ir);
    return ir;
}

static reg_t* new_reg() {
    reg_t* reg = calloc(1, sizeof(*reg));
    reg->issp = false;
    reg->vn = nreg++;
    reg->rn = -1;
    return reg;
}

static ir_t* emit(int op, reg_t* r0, reg_t* r1, reg_t* r2) {
    ir_t* ir = new_ir(op);
    ir->r0 = r0;
    ir->r1 = r1;
    ir->r2 = r2;
    return ir;
}

static ir_t* if_then() {
    ir_t* ir = new_ir(IR_IF_THEN);
    return ir;
}

static ir_t* if_els() {
    ir_t* ir = new_ir(IR_IF_END);
    return ir;
}

static ir_t* els_then() {
    ir_t* ir = new_ir(IR_ELSE_THEN);
    return ir;
}

static ir_t* els_end() {
    ir_t* ir = new_ir(IR_ELSE_END);
    return ir;
}

static ir_t* br(reg_t* r, bb_t* then, bb_t* els) {
    ir_t* ir = new_ir(IR_BR);
    ir->r2 = r;
    ir->bb1 = then;
    ir->bb2 = els;

    return ir;
}

static ir_t* jmp(bb_t* bb) {
    ir_t* ir = new_ir(IR_JMP);    
    
    ir->bb1 = bb;
    return ir;
}

static reg_t* imm(int imm) {
    ir_t* ir = new_ir(IR_IMM);
    
    ir->r0 = new_reg();
    ir->imm = imm;

    return ir->r0;
}

static reg_t* str(node_t* str) {
    ir_t* ir = new_ir(IR_STR);

    ir->r0 = new_reg(); 
    ir->var = str;
    
    return ir->r0;
}

static ir_t* rec(node_t* rec) {
    ir_t* ir = new_ir(IR_REC);
    ir->var = rec;
    return ir;
}

reg_t* lval(node_t* var) {
    ir_t* ir;
    
    ir = new_ir(IR_BPREL);
    ir->r0 = new_reg();
    ir->var = var;

    return ir->r0;    
}

reg_t* load(node_t* var) {
    ir_t* ir;

    ir = new_ir(IR_LOAD);
    ir->r0 = new_reg();
    ir->var = var;

    return ir->r0;
}

ir_t* bind(node_t* var, reg_t* reg) {
    ir_t* ir;

    ir = new_ir(IR_PUSH);
    ir->r0 = reg;
    ir->var = var;

    return ir;    
}

static reg_t* binop(int op, node_t* node) {
    reg_t* r1 = new_reg();
    reg_t* r2 = emit_expr(node->infix_expr.left);
    reg_t* r3 = emit_expr(node->infix_expr.right); 
    
    emit(op, r1, r2, r3);

    return r1;
}

reg_t* emit_binop(node_t* n) {
    switch (n->infix_expr.opcode) {
    case OP_ADD:
        return binop(IR_ADD, n);
    case OP_DIV:
        return binop(IR_DIV, n);
    case JUMP_JGT:
        return binop(IR_GT, n);
    default:
        break;
    }
}

reg_t* emit_expr(node_t* n) {
    switch (n->type) {
    case NODE_INT:
        return imm(n->integer);
    case NODE_EXPR:
        return emit_binop(n);
    case NODE_STRING:
        return str(n); 
    case NODE_VAR:
        return load(n);
    case NODE_ASSIGN:
    case NODE_DEC: {
        if (n->dec.expr->type == NODE_STRING) {
            return str(n->dec.expr);
        }
        reg_t* r1 = emit_expr(n->dec.expr);
        reg_t* r2 = lval(n->dec.var); 
        ir_t* ir = emit(IR_STORE, NULL, r2, r1);        
        bind(ir->var, r2);
        return r1;
    }
    case NODE_REC: {
        break;
    }
    case NODE_CALL: {
        ir_t* ir;
        int i = 0;
        node_t* head;
        reg_t* args[6];

        rec(n->call.args->next);
        
        ir = new_ir(IR_CALL);
        ir->r0 = new_reg();
        ir->var = n;
        ir->nargs = i;
        
        memcpy(ir->args, args, sizeof(args));
        return ir->r0;
    }
    default:
        verror("unknown ast type");
        break;
    }
}

void emit_stmt(node_t* n) {
    switch (n->type) {
    case NODE_IF: {
        bb_t* then = new_bb();
        bb_t* els = new_bb();
        bb_t* last = new_bb();

        br(emit_expr(n->iff.cond), then, els);
        curbb = then;
        
        if_then();
        emit_stmt(n->iff.then);
        jmp(last);
        if_els();

        curbb = els;
        if (n->iff.els) {
            els_then();
            emit_stmt(n->iff.els);
            els_end();
        }
        
        jmp(last);
        
        curbb = last;
        break;    
    }
    default:
        emit_expr(n);
        break;
    }
}

int emit_ir(node_t* n) {
    node_t* head;

    curbb = new_bb();
    
    bb_t* bb = new_bb();
    jmp(bb);
    curbb = bb;

    _foreach(head, n->probe.stmts) {
        emit_stmt(head);
    }
    
    return 0; 
}

prog_t* prog_new(node_t* n) {
    prog_t* p = vmalloc(sizeof(*p));
    p->ast = n;
    p->vars = vec_new();
    p->bbs = vec_new();
    p->e = ebpf_new();
    
    evpipe_init(p->e->evp, 4<<10);
    return p; 
}

static void add_edges(bb_t* bb) {
    if (bb->succ->len > 0)
        return 0;
    assert(bb->ir->len);
    
    ir_t* ir = bb->ir->data[bb->ir->len-1];
    
    if (ir->bb1) {
        vec_push(bb->succ, ir->bb1);
        vec_push(ir->bb1->pred, bb);
        add_edges(ir->bb1);
    }

    if (ir->bb2) {
        vec_push(bb->succ, ir->bb2);
        vec_push(ir->bb2->pred, bb);
        add_edges(ir->bb2);
    }
}

static void init_def_regs(bb_t* bb) {
    int i;
    
    for (i = 0; i < bb->ir->len; i++) {
        ir_t* ir = bb->ir->data[i];
        if (ir->r0){
            vec_union(bb->def_regs, ir->r0);
        }
    }
}

static void cfg(bb_t* bb, reg_t* reg) {
    if (!reg || vec_contains(bb->def_regs, reg))
        return;
    
    if (!vec_union(bb->in_regs, reg))
        return;
    
    for (int i = 0; i < bb->pred->len; i++) {
        bb_t* pred = bb->pred->data[i];

        if (vec_union(pred->out_regs, reg)) {
            cfg(pred, reg);
        }
    }
}

static void init_it_regs(bb_t* bb, ir_t* ir) {
    int i;
    
    cfg(bb, ir->r1);
    cfg(bb, ir->r2);
    cfg(bb, ir->bbarg);

    if (ir->op == IR_CALL)
        for (i = 0; i < ir->nargs; i++)
            cfg(bb, ir->args[i]);

}

void liveness(prog_t* prog) {
    int i, j;
    bb_t* bb;
    ir_t* ir;

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];
        
        init_def_regs(bb);

        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            init_it_regs(bb, ir);
        }
    }
}

static void set_end(reg_t* reg, int ic) {
    if (reg && reg->end < ic) {
        reg->end = ic;
    }
}

static void trans(bb_t* bb) {
    vec_t* v = vec_new();
    int i;
    
    for (i = 0; i < bb->ir->len; i++) {
        ir_t* ir = bb->ir->data[i];
        
        if (!ir->r0 || !ir->r1) {
            vec_push(v, ir);
            continue;
        }
        
        assert(ir->r0 != ir->r1);
        
        ir_t* ir2 = calloc(1, sizeof(*ir2));
        ir2->op = IR_MOV;
        ir2->r0 = ir->r0;
        ir2->r2 = ir->r1;
        vec_push(v, ir2);

        ir->r1 = ir->r0;
        vec_push(v, ir);
    }

    bb->ir = v;
}

static vec_t* collect(prog_t* prog) {
    vec_t* v = vec_new();
    int ic = 1;
    int i, j, k;

    for (i = 0; i < prog->bbs->len; i++) {
        bb_t* bb = prog->bbs->data[i];
        
        for (j = 0; j < bb->ir->len; j++, ic++) {
            ir_t* ir = bb->ir->data[j]; 

            if (ir->r0 && !ir->r0->def) {
                ir->r0->def = ic;
                vec_push(v, ir->r0);
            }

            set_end(ir->r1, ic);
            set_end(ir->r2, ic);
            set_end(ir->bbarg, ic);
            
            if (ir->op == IR_CALL) {
                for (k = 0; k < ir->nargs; k++)
                    set_end(ir->args[k], ic);
            }
        }
        
        for (j = 0; j < bb->out_regs->len; j++) {
            reg_t* reg = bb->out_regs->data[j];
            set_end(reg, ic);
        }
    }

    return v;
}

static int spill(reg_t** used) {
    int i, k = 0;
    for (i = 1; i < regnum; i++) {
        if (used[k]->end < used[i]->end) {
            k = i;
        }
    }
    return k;
}

void scan(vec_t* regs) {
    int i, j, k;
    bool found;
    reg_t** used = calloc(regnum, sizeof(reg_t*));

    for (i = 0; i < regs->len; i++) {
        reg_t* reg = regs->data[i];
        found = false;
        
        for (j = 0; j < regnum - 1; j++) {
            if (used[j] && reg->def < used[j]->end) {
                continue;
            }
            reg->rn = j;
            used[j] = reg;
            found = true;
            break;
        } 
        
        if (found) 
            continue;
        
        used[regnum-1] = reg;
        
        k = spill(used);
        reg->rn = k;
        used[k]->rn = regnum - 1;
        used[k]->spill = true;
        used[k] = reg;
    }
}

void spill_store(vec_t* v, ir_t* ir) {
    reg_t* reg;

    reg = ir->r0;
    if (!reg || !reg->spill)
        return; 
    
    ir_t* ir2 = calloc(1, sizeof(*ir2));
    ir2->op = IR_STORE_SPILL;
    ir2->r1 = reg;
    ir2->var = reg->var;
    vec_push(v, ir2);
}

void spill_load(vec_t* vec, ir_t* ir, reg_t* reg) {
    if (!reg || !reg->spill) {
        return;
    }
    
    ir_t* ir2 = vcalloc(1, sizeof(*ir2));
    ir2->op = IR_LOAD_SPILL;
    ir2->r0 = reg;
    ir2->var = reg->var;
    vec_push(vec, ir2);
}

void emit_spill_code(bb_t* bb) {
    int i;
    ir_t* ir;
    vec_t* v = vec_new();

    for (i = 0; i < bb->ir->len; i++) {
        ir = bb->ir->data[i];
        spill_load(v, ir, ir->r1);
        spill_load(v, ir, ir->r2);
        spill_load(v, ir, ir->bbarg);
        vec_push(v, ir);
        spill_store(v, ir);
    }

    bb->ir = v;
}

void regs_alloc(prog_t* prog) {
    int i;
    bb_t* bb;
    vec_t* regs;
    node_t* var;
    
    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];
        trans(bb);
    }
    
    regs = collect(prog);
    scan(regs);
    
    for (i = 0; i < regs->len; i++) {
        reg_t* reg = regs->data[i];
        if (!reg->spill)
            continue;
        var = node_var_new("spill");
        reg->var = var;
        vec_push(prog->vars, var);
    }
    
    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];
        emit_spill_code(bb);
    }
}

void emit_code(ebpf_t* code, struct bpf_insn insn) {
    assert(code != NULL);
    *(code->ip)++ = insn;
}

void emit_at(ebpf_t* code, struct bpf_insn* at, struct bpf_insn insn) {
    *at = insn;
}


void store_str(ebpf_t* e, node_t* n) {
    ssize_t size, at, left;
    int32_t* str;

    at = n->annot.addr;
    size = n->annot.size;
    str = n->name;
    left = size / sizeof(*str);
    
    for (; left; left--, str++, at += sizeof(*str)) {
        emit_code(e, STW_IMM(BPF_REG_10, at, *str));
    }
}

void stack_init(node_t* n, ebpf_t* e) {
	size_t i;
	annot_t to = n->annot;
	size_t len = 8;
    
	emit_code(e, MOV_IMM(BPF_REG_0, 0));
	
	for (i = 0; i < len; i += sizeof(int64_t)) {
		emit_code(e, STXDW(BPF_REG_10, -8+i, BPF_REG_0));	
	}
}

void emit_ld_mapfd(ebpf_t* e, int reg, int fd) {
    emit_code(e, INSN(BPF_LD|BPF_DW|BPF_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    emit_code(e, INSN(0, 0, 0, 0, 0));
}

void emit_rec(node_t* n, ebpf_t* e) {
    ssize_t addr, size;
    node_t* arg;
    int id;

    id = e->evp->mapfd;
    addr = n->annot.addr;
    size = n->annot.size;

    printf("%d %d\n", addr, size);

    _foreach(arg, n->rec.args) {
        printf("%d\n", arg->annot.addr);
        emit_code(e, MOV_IMM(BPF_REG_1, arg->integer));
        emit_code(e, STXDW(BPF_REG_10, arg->annot.addr, BPF_REG_1));
    }

    emit_code(e, CALL(BPF_FUNC_get_smp_processor_id));
	emit_code(e, MOV(BPF_REG_3, BPF_REG_0));
    
    emit_code(e, MOV(BPF_REG_1, BPF_REG_9));
	emit_ld_mapfd(e, BPF_REG_2, id);

    emit_code(e, MOV(BPF_REG_4, BPF_REG_10));
	emit_code(e, ALU_IMM(OP_ADD, BPF_REG_4, addr));

    emit_code(e, MOV_IMM(BPF_REG_5, size));
	emit_code(e, CALL(BPF_FUNC_perf_event_output));
}

struct bpf_insn* at;
struct bpf_insn* end;

void compile_ir(ir_t* ir, ebpf_t* code) {
    int r0 = ir->r0 ? ir->r0->rn : 0;
    int r1 = ir->r1 ? ir->r1->rn : 0; 
    int r2 = ir->r2 ? ir->r2->rn : 0;

    switch (ir->op) {
    case IR_IMM:
        printf("mov %d, [%d]\n", ir->imm, gregs[r0]);
        emit_code(code, MOV_IMM(gregs[r0], ir->imm));
        break;
    case IR_STR:
        printf("push str %s\n", ir->var->name);
        printf("addr: %d\n", ir->var->annot.addr);
        store_str(code, ir->var);
        break;
    case IR_ADD:
        emit_code(code, ALU(BPF_ADD, gregs[r0], gregs[r2]));
        break;
    case IR_GT:
        printf("comp %d %d\n", gregs[r0], gregs[r2]);
        emit_code(code, JMP(JUMP_JGT, gregs[r0], gregs[r2], 2));
        emit_code(code, MOV_IMM(gregs[r0], 0));
        emit_code(code, JMP_IMM(BPF_JA, 0, 0, 1));
        emit_code(code, MOV_IMM(gregs[r0], 1));
        break;
    case IR_BPREL:
        printf("push [%d]\n", gregs[r0]);
        emit_code(code, STXDW(BPF_REG_10, ir->var->annot.addr, gregs[r0]));
        break;
    case IR_STORE:
        printf("store: [%d] [%d]\n", gregs[r1], gregs[r2]);
        emit_code(code, MOV(gregs[r1], gregs[r2]));
        break;
    case IR_BR:
        printf("br: %d\n", gregs[r2]);
        emit_code(code, MOV(BPF_REG_0, gregs[r2]));
        break;
    case IR_PUSH:
        printf("var push %d\n", gregs[r0]);
        break;
    case IR_IF_THEN:
        at = code->ip;
        emit_code(code, if_then_insn);
        break; 
    case IR_IF_END:
        printf("end if (%d)\n", code->ip-at-1);
        emit_at(code, at, JMP_IMM(BPF_JEQ, 0, 0, code->ip-at-1));
        break;
    case IR_REC:
        emit_rec(ir->var, code);
        break;
    case IR_CALL:
        break;
    default:
        break;
    }
}

void compile(prog_t* prog) {
    int i, j;
    bb_t* bb;
    ir_t* ir;
    ebpf_t* e;

    e = prog->e;

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];     
        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            compile_ir(ir, e);
        }
    }
}

static int term_sig = 0;
static void term(int sig) {
    term_sig = sig;
    return;
}

int main() {
    char* input; 
    lexer_t* l;
    parser_t* p;
    node_t* n;
    ebpf_t* e;

    input = "probe sys{ if (3 > 1) { out(\"%d\n\", 2);}";  
    l = lexer_init(input);
    p = parser_init(l);
    n = parse_program(p); 
    prog = prog_new(n); 

    visit(n, get_annot, loc_assign, prog->e);
    
    emit_code(prog->e, MOV(BPF_CTX_REG, BPF_REG_1));
    emit_ir(n);
    liveness(prog);
    regs_alloc(prog);
    compile(prog);

    emit_code(prog->e, MOV_IMM(BPF_REG_0, 0));
	emit_code(prog->e, EXIT);
    
    siginterrupt(SIGINT, 1);
    signal(SIGINT, term);
    bpf_probe_attach(prog->e, 721); 
    evpipe_loop(prog->e->evp, &term_sig, -1);
    return 0;
}