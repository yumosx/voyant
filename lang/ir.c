#include <assert.h>

#include "ir.h"
#include "ut.h"
#include "insn.h"
#include "bpfsyscall.h"
#include "buffer.h"

static prog_t* prog;
static bb_t* curbb;
static int nreg = 1;
static int nlabel = 1;
static int regnum = 3;

static bb_t* bb_new() {
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

static ir_t* ir_new(int op) {
    ir_t* ir = calloc(1, sizeof(*ir));
    ir->op = op;
    vec_push(curbb->ir, ir);
    return ir;
}

static reg_t* reg_new() {
    reg_t* reg = calloc(1, sizeof(*reg));
    reg->vn = nreg++;
    reg->rn = -1;
    return reg;
}

static ir_t* emit(int op, reg_t* r0, reg_t* r1, reg_t* r2) {
    ir_t* ir = ir_new(op);
    ir->r0 = r0;
    ir->r1 = r1;
    ir->r2 = r2;
    return ir;
}

static ir_t* if_then() {
    ir_t* ir = ir_new(IR_IF_THEN);
    return ir;
}

static ir_t* if_els() {
    ir_t* ir = ir_new(IR_IF_END);
    return ir;
}

static ir_t* els_then() {
    ir_t* ir = ir_new(IR_ELSE_THEN);
    return ir;
}

static ir_t* els_end() {
    ir_t* ir = ir_new(IR_ELSE_END);
    return ir;
}

static ir_t* map_update(node_t* map) {
    ir_t* ir = ir_new(IR_MAP_UPDATE);
    ir->value = map;
    return ir;
}

static ir_t* br(reg_t* r, bb_t* then, bb_t* els) {
    ir_t* ir = ir_new(IR_BR);
    ir->r2 = r;
    ir->bb1 = then;
    ir->bb2 = els;

    return ir;
}

static ir_t* jmp(bb_t* bb) {
    ir_t* ir = ir_new(IR_JMP);    
    
    ir->bb1 = bb;
    return ir;
}

static reg_t* imm(node_t* n) {
    ir_t* ir = ir_new(IR_IMM);
    
    ir->r0 = reg_new();
    ir->imm = n->integer;

    return ir->r0;
}

ir_t* lval(node_t* var) {
    ir_t* ir;
    
    ir = ir_new(IR_INIT);
    ir->value = var;

    return ir;
}

void push(node_t* value) {
    vec_push(prog->data, value);
}

ir_t* store(node_t* dst, reg_t* src) {
    ir_t* ir;

    ir = ir_new(IR_STORE);
    ir->r0 = src;
    ir->value = dst;

    return ir;    
}
 
static reg_t* binop(int op, node_t* node) {
    reg_t* r1, *r2, *r3;

    r1 = reg_new();
    r2 = gen_expr(node->expr.left);
    r3 = gen_expr(node->expr.right); 
    
    emit(op, r1, r2, r3);

    return r1;
}

reg_t* gen_binop(node_t* n) {
    switch (n->expr.opcode) {
    case OP_ADD:
        return binop(IR_ADD, n);
    case OP_DIV:
        return binop(IR_DIV, n);
    case OP_MUL:
        return binop(IR_MUL, n);
    case OP_GT:
        return binop(IR_GT, n);
    case OP_GE:
        return binop(IR_GE, n);
    default:
        break;
    }
}

reg_t* gen_call(node_t* call) {
    node_t* arg;
    ir_t* ir;

    if (vstreq("out", call->name)) {
        node_t* h, *rec;
        rec = call->call.args->next;

        _foreach(h, rec->rec.args) {
            gen_node_store(h, h);
        }

        ir = ir_new(IR_CALL);
        ir->r0 = reg_new();
        ir->value = rec;
        return ir->r0;
    }

    _foreach(arg, call->call.args) {
        gen_node_store(arg, arg);
    }

    ir = ir_new(IR_CALL);
    ir->r0 = reg_new();
    ir->value = call;

    return ir->r0;
}

reg_t* gen_expr(node_t* n) {
    switch (n->type){
    case NODE_INT:
        return imm(n);
    case NODE_EXPR:
        return gen_binop(n);
    case NODE_CALL:
        return gen_call(n);
    default:
        break;
    }
}

void gen_node_store(node_t* dst, node_t* src) {
    reg_t* r1, *r2;
    ir_t* ir;
    
    switch (src->annot.type) {
    case TYPE_RINT:
    case TYPE_EXPR:
    case TYPE_INT:
        r1 = gen_expr(src);
        lval(dst);
        store(dst, r1);
        break;
    case TYPE_STR:
    case TYPE_RSTR:
        push(src);
        break;
    case TYPE_REC:
        printf("%d\n", 12);
        break;
    default:
        verror("not found the store pos");
    }
}

void gen_dec(node_t* dec) {
    node_t* var, *expr;
    ssize_t addr;

    var = dec->dec.var;
    expr = dec->dec.expr;

    switch (var->type) {
    case NODE_MAP:
        gen_node_store(var->map.args, var->map.args);
        gen_node_store(var, expr);
        map_update(var);
        break;
    case NODE_VAR:
        gen_node_store(var, expr);
        break;
    default:
        break;
    }
}

void gen_iff(node_t* n) {
    bb_t* then = bb_new();
    bb_t* els = bb_new();
    bb_t* last = bb_new();
    
    br(gen_binop(n->iff.cond), then, els);
    
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
}

void emit_stmt(node_t* n) {
    switch (n->type) {
    case NODE_IF:
        gen_iff(n);
        break;
    case NODE_DEC:
        gen_dec(n);
        break;
    case NODE_CALL:
        gen_call(n);
        break;
    }
}

int gen_ir(node_t* n) {
    node_t* head;

    curbb = bb_new();
    
    bb_t* bb = bb_new();
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
    p->data = vec_new();
    p->bbs = vec_new();
    return p; 
}

static void ir_add_edges(bb_t* bb) {
    if (bb->succ->len > 0)
        return 0;
    assert(bb->ir->len);
    
    ir_t* ir = bb->ir->data[bb->ir->len-1];
    
    if (ir->bb1) {
        vec_push(bb->succ, ir->bb1);
        vec_push(ir->bb1->pred, bb);
        ir_add_edges(ir->bb1);
    }

    if (ir->bb2) {
        vec_push(bb->succ, ir->bb2);
        vec_push(ir->bb2->pred, bb);
        ir_add_edges(ir->bb2);
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

static void ir_cfg(bb_t* bb, reg_t* reg) {
    if (!reg || vec_contains(bb->def_regs, reg))
        return;
    
    if (!vec_union(bb->in_regs, reg))
        return;
    
    for (int i = 0; i < bb->pred->len; i++) {
        bb_t* pred = bb->pred->data[i];

        if (vec_union(pred->out_regs, reg)) {
            ir_cfg(pred, reg);
        }
    }
}

static void ir_init_it_regs(bb_t* bb, ir_t* ir) {
    int i;
    
    ir_cfg(bb, ir->r1);
    ir_cfg(bb, ir->r2);
    ir_cfg(bb, ir->bbarg);

    if (ir->op == IR_CALL) {
        for (i = 0; i < ir->nargs; i++){
            ir_cfg(bb, ir->args[i]);
        }
    }
}

void ir_liveness(prog_t* prog) {
    int i, j;
    bb_t* bb;
    ir_t* ir;

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];
        
        init_def_regs(bb);

        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            ir_init_it_regs(bb, ir);
        }
    }
}

static void ir_set_end(reg_t* reg, int ic) {
    if (reg && reg->end < ic) {
        reg->end = ic;
    }
}

static void ir_trans(bb_t* bb) {
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

            ir_set_end(ir->r1, ic);
            ir_set_end(ir->r2, ic);
            ir_set_end(ir->bbarg, ic);
            
            if (ir->op == IR_CALL) {
                for (k = 0; k < ir->nargs; k++)
                    ir_set_end(ir->args[k], ic);
            }
        }
        
        for (j = 0; j < bb->out_regs->len; j++) {
            reg_t* reg = bb->out_regs->data[j];
            ir_set_end(reg, ic);
        }
    }

    return v;
}

static int ir_spill(reg_t** used) {
    int i, k = 0;
    for (i = 1; i < regnum; i++) {
        if (used[k]->end < used[i]->end) {
            k = i;
        }
    }
    return k;
}

void ir_scan(vec_t* regs) {
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
 
        k = ir_spill(used);
        reg->rn = k;
        used[k]->rn = regnum - 1;
        used[k]->spill = true;
        used[k] = reg;
    }
}

void ir_regs_alloc(prog_t* prog) {
    int i;
    bb_t* bb;
    vec_t* regs;
    node_t* var;
    
    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];
        ir_trans(bb);
    }
    
    regs = collect(prog);
    ir_scan(regs);
}

prog_t* gen_prog(node_t* n) {
    prog = prog_new(n);
    
    gen_ir(n);
    ir_liveness(prog);
    ir_regs_alloc(prog);

    return prog;
}