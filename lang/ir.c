#include <assert.h>

#include "ir.h"
#include "ut.h"
#include "insn.h"
#include "bpfsyscall.h"

static prog_t* prog;
static bb_t* out;
static int nreg = 1;
int nlabel = 1;
static int regnum = 3;
int gregs[3] =  {BPF_REG_6, BPF_REG_7, BPF_REG_8}; 
int argregs[5] = {BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5};

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
    vec_push(out->ir, ir);
    return ir;
}

static reg_t* new_reg() {
    reg_t* reg = calloc(1, sizeof(*reg));
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

reg_t* lval(node_t* var) {
    ir_t* ir;
    
    ir = new_ir(IR_BPREL);
    ir->r0 = new_reg();
    ir->var = var;
    
    return ir->r0;    
}

void load(node_t* node, reg_t* dst, reg_t* src) {
    ir_t* ir = emit(IR_LOAD, dst, NULL, src);
    ir->size = node->annot.size;
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
    case OP_MUL:
        return binop(IR_MUL, n);
    case OP_DIV:
        return binop(IR_DIV, n);
    default:
        break;
    }
}

reg_t* emit_expr(node_t* n) {
    switch (n->type) {
    case NODE_INT:
        return imm(n->integer);
    case NODE_INFIX_EXPR:
        return emit_binop(n);
    case NODE_VAR:{
        reg_t* r = new_reg();
        load(n, r, lval(n));
        return r;
    }
    case NODE_ASSIGN:
    case NODE_DEC: {
        reg_t* r1 = emit_expr(n->dec.expr);
        reg_t* r2 = lval(n->dec.var);
        ir_t* ir = emit(IR_STORE, NULL, r2, r1);        
        ir->size = 8;
        return r1;
    }
    case NODE_CALL: {
        ir_t* ir;
        ir = new_ir(IR_CALL);
        ir->r0 = new_reg();
        ir->name = n->name;
        return ir->r0;
    }
    default:
        verror("unknown ast type");
        break;
    }
}

int gen_ir(node_t* n) {
    node_t* head;

    out = new_bb();
    
    bb_t* bb = new_bb();
    jmp(bb);
    out = bb;

    _foreach(head, n->probe.stmts) {
        emit_expr(head);
    }
    
    return 0; 
}

prog_t* prog_new(node_t* n) {
    prog_t* p = vmalloc(sizeof(*p));
    p->ast = n;
    p->vars = vec_new();
    p->bbs = vec_new();
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

static void propagate(bb_t* bb, reg_t* reg) {
    if (!reg || vec_contains(bb->def_regs, reg))
        return;
    
    if (!vec_union(bb->in_regs, reg))
        return;
    
    for (int i = 0; i < bb->pred->len; i++) {
        bb_t* pred = bb->pred->data[i];

        if (vec_union(pred->out_regs, reg)) {
            propagate(pred, reg);
        }
    }
}

static void init_it_regs(bb_t* bb, ir_t* ir) {
    int i;
    
    propagate(bb, ir->r1);
    propagate(bb, ir->r2);
    propagate(bb, ir->bbarg);

    if (ir->op == IR_CALL)
        for (i = 0; i < ir->nargs; i++)
            propagate(bb, ir->args[i]);

}

void liveness(prog_t* prog) {
    int i, j;
    for (i = 0; i < prog->bbs->len; i++) {
        bb_t* bb = prog->bbs->data[i];
        
        init_def_regs(bb);

        for (j = 0; j < bb->ir->len; j++) {
            ir_t* ir = bb->ir->data[j];
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

void code_emit(ebpf_t* code, struct bpf_insn insn) {
    assert(code != NULL);
    *(code->ip)++ = insn;
}

void code_ld_mapfd(ebpf_t* e, int reg, int fd) {
    ebpf_emit(e, INSN(BPF_LD|BPF_DW|BPF_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    ebpf_emit(e, INSN(0, 0, 0, 0, 0));
}

void call_emit(ir_t* ir, ebpf_t* code) {
}


void compile_out(ir_t* ir, ebpf_t* code) {
    int i = 0; 
}

void compile_ir(ir_t* ir, ebpf_t* code) {
    int r0 = ir->r0 ? ir->r0->rn : 0;
    int r1 = ir->r1 ? ir->r1->rn : 0; 
    int r2 = ir->r2 ? ir->r2->rn : 0;

    switch (ir->op) {
    case IR_IMM:
        printf("mov: reg(%d) imm(%d)\n", gregs[r0], ir->imm);
        code_emit(code, MOV_IMM(gregs[r0], ir->imm));
        break;
    case IR_ADD:
        printf("add: reg(%d) reg(%d)\n", gregs[r0], gregs[r2]);
        code_emit(code, ALU(BPF_ADD, gregs[r0], gregs[r2]));
        break;
    case IR_BPREL:
        printf("store addr in %d\n", gregs[r0]);
        code_emit(code, MOV(gregs[r0], BPF_REG_10));
        code_emit(code, ALU_IMM(bpfregs[r0], BPF_REG_10, ir->var->annot.addr));
        break;
    case IR_STORE:
        printf("mov: reg(%d) reg(%d)\n", gregs[r1], gregs[r2]);
        code_emit(code, MOV(gregs[r1], gregs[r2]));
        break;
    case IR_CALL:
        printf("call: %s\n", ir->name);
        call_emit(ir, code);
        break;
    case IR_RETURN:
        printf("%s\n", "exit"); 
        break;
    default:
        break;
    }
}

ebpf_t* compile(prog_t* prog) {
    int i, j;
    bb_t* bb;
    ir_t* ir;
    ebpf_t* e;

    e = ebpf_new();

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];     

        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            compile_ir(ir, e);
        }
    }

    return e;
}

int main() {
    char* input; 
    lexer_t* l;
    parser_t* p;
    node_t* n;
    code_t* code;
    ebpf_t* e;

    /*
    out: addr-->reg1
    */
    input = "probe sys{ a := pid();}";  
    l = lexer_init(input);
    p = parser_init(l);
    n = parse_program(p); 
    prog = prog_new(n); 


    gen_ir(n);
    liveness(prog);
    regs_alloc(prog);
    code = compile(prog);

    code_emit(code, MOV_IMM(BPF_REG_0, 0));
	code_emit(code, EXIT);

    //bpf_probe_attach(code, 721); 
    return 0;
}