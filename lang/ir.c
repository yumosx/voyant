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
        reg_t* r2 = new_reg(); 
        ir_t* ir = emit(IR_STORE, NULL, r2, r1);        
        
        lval(n->dec.var);
        return r1;
    }
    case NODE_CALL: {
        ir_t* ir;
        int i = 0;
        node_t* head;
        reg_t* args[6];
        
        _foreach(head, n->call.args) {
            args[i] = emit_expr(head);
            i += 1;
        }
        
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
        out = then;
        emit_stmt(n->iff.then);
        jmp(last);
        
        out = els;
        if (n->iff.els)
            emit_stmt(n->iff.els);
        jmp(last);
        
        out = last;
        
        return;
    }
    default:
        emit_expr(n);
        break;
    }
}

int emit_ir(node_t* n) {
    node_t* head;

    out = new_bb();
    
    bb_t* bb = new_bb();
    jmp(bb);
    out = bb;

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

void emit_call(ebpf_t* e, ir_t* ir) {
    int i;
    int reg;
    size_t size;

    size = strlen("%d")+1;

    emit_code(e, MOV(BPF_REG_1, BPF_REG_10));
    emit_code(e, ALU_IMM(BPF_ADD, BPF_REG_1, -16));
   
    emit_code(e, LDXB(3, -8, 10));

    emit_code(e, MOV_IMM(BPF_REG_2, size));
    emit_code(e, CALL(BPF_FUNC_trace_printk));
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

void compile_ir(ir_t* ir, ebpf_t* code) {
    int r0 = ir->r0 ? ir->r0->rn : 0;
    int r1 = ir->r1 ? ir->r1->rn : 0; 
    int r2 = ir->r2 ? ir->r2->rn : 0;

    switch (ir->op) {
    case IR_IMM:
        emit_code(code, MOV_IMM(gregs[r0], ir->imm));
        break;
    case IR_STR:
        store_str(code, ir->var);
        break;
    case IR_ADD:
        emit_code(code, ALU(BPF_ADD, gregs[r0], gregs[r2]));
        break;
    case IR_GT:
        emit_code(code, JMP(JUMP_JGT, gregs[r0], gregs[r2], 2));
        emit_code(code, MOV_IMM(gregs[r0], 0));
        emit_code(code, JMP_IMM(BPF_JA, 0, 0, 1));
        emit_code(code, MOV_IMM(gregs[r0], 1));
        break;
    case IR_BPREL:
        emit_code(code, STXDW(BPF_REG_10, ir->var->annot.addr, gregs[r0]));
        break;
    case IR_STORE:
        emit_code(code, MOV(gregs[r1], gregs[r2]));
        break;
    case IR_BR:
        break;
    case IR_CALL:
        emit_call(code, ir);
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

    printf("block: %d\n", prog->bbs->len);


    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];     

        printf("%d\n", bb->ir->len);

        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            compile_ir(ir, e);
        }
    }

}

int main() {
    char* input; 
    lexer_t* l;
    parser_t* p;
    node_t* n;
    ebpf_t* e;

    input = "probe sys{ if(2 > 1){ trace(\"%d\n\", a);};}";  
    l = lexer_init(input);
    p = parser_init(l);
    n = parse_program(p); 
    prog = prog_new(n); 

    visit(n, get_annot, loc_assign, prog->e);

    emit_ir(n);
    liveness(prog);
    regs_alloc(prog);
    compile(prog);

    emit_code(prog->e, MOV_IMM(BPF_REG_0, 0));
	emit_code(prog->e, EXIT);

    //bpf_probe_attach(prog->e, 721); 
    
    return 0;
}