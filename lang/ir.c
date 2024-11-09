#include <assert.h>

#include "ir.h"
#include "ut.h"
#include "insn.h"
#include "probe.h"
#include "buffer.h"

static prog_t *prog;
static bb_t *curbb;
static int nreg = 1;
static int nlabel = 1;
static int regnum = 3;

static bb_t *bb_new() {
    bb_t *bb = calloc(1, sizeof(*bb));

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

static ir_t *ir_new(int op) {
    ir_t *ir = calloc(1, sizeof(*ir));
    ir->op = op;
    vec_push(curbb->ir, ir);
    return ir;
}

static reg_t *reg_new() {
    reg_t *reg = calloc(1, sizeof(*reg));
    reg->vn = nreg++;
    reg->rn = -1;
    return reg;
}

static ir_t *emit(int op, reg_t *r0, reg_t *r1, reg_t *r2) {
    ir_t *ir = ir_new(op);
    ir->r0 = r0;
    ir->r1 = r1;
    ir->r2 = r2;
    return ir;
}

static ir_t* ir_exit() {
    ir_t* ir = ir_new(IR_RETURN);
    return ir;
}

static ir_t* if_then() {
    ir_t *ir = ir_new(IR_IF_THEN);
    return ir;
}

static ir_t* then_end() {
    ir_t *ir = ir_new(IR_IF_END);
    return ir;
}

static ir_t* else_then() {
    ir_t *ir = ir_new(IR_ELSE_THEN);
    return ir;
}

static ir_t* else_end() {
    ir_t *ir = ir_new(IR_ELSE_END);
    return ir;
}

static ir_t* map_update(node_t *map) {
    ir_t *ir = ir_new(IR_MAP_UPDATE);
    ir->value = map;
    return ir;
}

static ir_t* map_look(node_t* map) {
    ir_t* ir = ir_new(IR_MAP_LOOK);
    ir->value = map;
    return ir;
}

static ir_t* map_count(node_t* map) {
    ir_t* ir = ir_new(IR_MAP_METHOD);
    ir->value = map;
    return ir;
}

static ir_t *br(reg_t *r, bb_t *then, bb_t *els) {
    ir_t *ir = ir_new(IR_BR);
    ir->r2 = r;
    ir->bb1 = then;
    ir->bb2 = els;

    return ir;
}

static ir_t *jmp(bb_t *bb) {
    ir_t *ir = ir_new(IR_JMP);

    ir->bb1 = bb;
    return ir;
}

static reg_t *imm(node_t *n) {
    ir_t *ir = ir_new(IR_IMM);

    ir->r0 = reg_new();
    ir->imm = n->integer;

    return ir->r0;
}


static void push(node_t *value) {
    vec_push(prog->data, value);
}

static ir_t *init(node_t *var) {
    ir_t *ir;

    ir = ir_new(IR_INIT);
    ir->value = var;

    return ir;
}

static reg_t* var_copy(node_t* var) {
    ir_t* ir = ir_new(IR_COPY);
    ir->r0 = reg_new();
    ir->value = var;

    return ir->r0;
}

static reg_t* map_copy(node_t* map) {
    ir_t* ir = ir_new(IR_MAP_LOOK);
    ir->r0 = reg_new();
    ir->value = map;

    return ir->r0;
}

static reg_t* arg_read(node_t* expr) {
    ir_t* ir = ir_new(IR_READ);
    ir->r0 = reg_new();
    ir->value = expr;

    return ir->r0;
}

static ir_t* ir_struct(node_t* expr, node_t* dst) {
    ir_t* ir = ir_new(IR_CAST);
    ir->value = expr;
    return ir;
}

ir_t *store(node_t *dst, reg_t *src) {
    ir_t *ir;

    ir = ir_new(IR_STORE);
    
    ir->value = dst;
    ir->r0 = src;

    return ir;
}

ir_t* arg_reg_to_stack(node_t* arg, reg_t* reg) {
    ir_t *ir;

    ir = ir_new(IR_ARG);
    
    ir->value = arg;
    ir->r0 = reg;
    ir->addr = arg->annot.addr;
    ir->size = arg->annot.size;

    return ir;
}

reg_t* ret(node_t* call) {
    ir_t* ir;

    ir = ir_new(IR_RCALL);
    ir->r0 = reg_new();
    ir->value = call;

    return ir->r0;
}

static void gen_noret_call(node_t* call) {
    ir_t* ir;
    node_t* rec;
    node_t* arg;

    if (call->call.args) {
        rec = call->call.args->next;
        _foreach(arg, rec->rec.args) {
            dyn_args(arg);
        }
    }

    ir = ir_new(IR_CALL);
    ir->value = rec;
}


static reg_t *binop(int op, node_t *node) {
    reg_t *r1, *r2, *r3;

    r1 = reg_new();
    r2 = gen_expr(node->expr.left);
    r3 = gen_expr(node->expr.right);

    emit(op, r1, r2, r3);

    return r1;
}

reg_t* gen_binop(node_t *n) {
    switch (n->expr.opcode) {
    case OP_ADD: 
        return binop(IR_ADD, n);
    case OP_SUB:
        return binop(IR_SUB, n);
    case OP_DIV:
        return binop(IR_DIV, n);
    case OP_MUL:
        return binop(IR_MUL, n);
    case OP_GT:
        return binop(IR_GT, n);
    case OP_GE:
        return binop(IR_GE, n);
    case OP_LT:
        return binop(IR_LT, n);
    case OP_LE:
        return binop(IR_LE, n);
    case OP_EQ:
        return binop(IR_EQ, n);
    case OP_ACCESS:
        return arg_read(n);
    default:
        break;
    }
}

reg_t* gen_expr(node_t *expr) {
    switch (expr->type) {
    case NODE_INT:
        return imm(expr);
    case NODE_EXPR:
        return gen_binop(expr);
    case NODE_CALL:
        return ret(expr);
    case NODE_VAR:
        return var_copy(expr);
    case NODE_MAP:
        dyn_args(expr->map.args);
        return map_copy(expr);
    default:
        break;
    }
}

void reg_to_stack(node_t* dst, node_t* src) {
    reg_t* r1;

    r1 = gen_expr(src);
    init(dst);
    store(dst, r1);
}

void direct_to_stack(node_t* dst, node_t* src) {
    switch (src->type) {
    case NODE_CALL:
        push(src);
        break;
    case NODE_STR:
        push(src);
        break;
    case NODE_VAR:
        var_copy(dst);
        break;
    case NODE_MAP:
        dyn_args(dst->map.args);
        map_copy(dst);
        break;
    case NODE_EXPR:
        arg_read(src);
        break;
    default:
        break;
    }
}

void dyn_assign(node_t* dst, node_t* src) {
    switch (dst->annot.type) {
    case TYPE_INT:
        reg_to_stack(dst, src);
        break;
    case TYPE_STR:
        direct_to_stack(dst, src);
        break; 
    case TYPE_CAST:
        ir_struct(dst, src);
        break;
    default:
        break;
    }
}


void dyn_int_store(node_t* dst) {
    reg_t* reg;

    switch (dst->type) {
    case NODE_INT:
        reg = gen_expr(dst);
        break;
    case NODE_CALL:
        reg = gen_expr(dst);
        break;
    case NODE_VAR:
        reg = gen_expr(dst);
        break;
    case NODE_EXPR:
        reg = gen_expr(dst);
        break;
    case NODE_MAP:
        reg = gen_expr(dst);
        break;
    default:
        break;
    }

    arg_reg_to_stack(dst, reg);
}

void dyn_str_store(node_t* dst) {
    switch (dst->type) {
    case NODE_STR:
        push(dst);
        break;
    case NODE_CALL:
        push(dst);
        break;
    case NODE_VAR:
        var_copy(dst);
        break;
    case NODE_MAP:
        dyn_args(dst->map.args);
        map_copy(dst);
        break;
    case NODE_EXPR:
        arg_read(dst);
        break;
    default:
        break;
    }
}

void dyn_args(node_t* dst) {
    switch (dst->annot.type) {
    case TYPE_INT:
        dyn_int_store(dst);
        break;
    case TYPE_STR:
        dyn_str_store(dst);
        break;
    default:
        break;
    }
}

void gen_map_method(node_t* expr) {
    node_t* map;

    map = expr->expr.left;

    dyn_args(map->map.args);
    map_count(map);
}

void gen_dec(node_t *dec) {
    node_t *var, *expr;
    ssize_t addr;

    var = dec->dec.var;
    expr = dec->dec.expr;

    switch (var->type) {
    case NODE_MAP:
        dyn_args(var->map.args);
        dyn_assign(var, expr);
        map_update(var);
        break;
    case NODE_VAR:
        dyn_assign(var, expr);
        break;
    default:
        break;
    }
}

void gen_iff(node_t *n) {
    node_t* stmt;
    bb_t *then = bb_new();
    bb_t *els = bb_new();
    bb_t *last = bb_new();

    br(gen_binop(n->iff.cond), then, els);

    curbb = then;

    if_then();
    gen_stmt(n->iff.then);
    jmp(last);
    
    
    then_end();

    curbb = els;

    if (n->iff.els){
        else_then();
        gen_stmt(n->iff.els);
        else_end();
    }

    jmp(last);

    curbb = last;
}

void gen_stmt(node_t *n) {
    switch (n->type) {
    case NODE_IF:
        gen_iff(n);
        break;
    case NODE_DEC:
        gen_dec(n);
        break;
    case NODE_CALL:
        gen_noret_call(n);
        break;
    case NODE_EXPR:
        gen_map_method(n);
        break;
    default:
        verror("not match stmts type");
        break;
    }
}

int gen_ir(node_t *n) {
    node_t *head;

    curbb = bb_new();
    bb_t *bb = bb_new();
    jmp(bb);
    curbb = bb;
    
    _foreach(head, n->probe.stmts) {
        gen_stmt(head);
    }

    ir_exit();
    return 0;
}

prog_t *prog_new(node_t *n) {
    prog_t *p = vmalloc(sizeof(*p));
    p->ast = n;
    p->data = vec_new();
    p->bbs = vec_new();
    return p;
}

static void init_def_regs(bb_t *bb) {
    ir_t* ir;
    int i;

    for (i = 0; i < bb->ir->len; i++) {
        ir = bb->ir->data[i];
        if (ir->r0) {
            vec_union(bb->def_regs, ir->r0);
        }
    }
}

static void ir_cfg(bb_t *bb, reg_t *reg) {
    if (!reg || vec_contains(bb->def_regs, reg))
        return;

    if (!vec_union(bb->in_regs, reg))
        return;

    for (int i = 0; i < bb->pred->len; i++) {
        bb_t *pred = bb->pred->data[i];

        if (vec_union(pred->out_regs, reg)) {
            ir_cfg(pred, reg);
        }
    }
}

static void ir_init_it_regs(bb_t *bb, ir_t *ir) {
    int i;

    ir_cfg(bb, ir->r1);
    ir_cfg(bb, ir->r2);
    ir_cfg(bb, ir->bbarg);

    if (ir->op == IR_CALL) {
        for (i = 0; i < ir->nargs; i++) {
            ir_cfg(bb, ir->args[i]);
        }
    }
}

void ir_liveness(prog_t *prog) {
    int i, j;
    bb_t *bb;
    ir_t *ir;

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];

        init_def_regs(bb);

        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            ir_init_it_regs(bb, ir);
        }
    }
}

static void ir_set_end(reg_t *reg, int ic) {
    if (reg && reg->end < ic) {
        reg->end = ic;
    }
}

static void ir_trans(bb_t *bb) {
    vec_t *v = vec_new();
    ir_t *ir, *ir2;
    int i;

    for (i = 0; i < bb->ir->len; i++) {
        ir = bb->ir->data[i];

        if (!ir->r0 || !ir->r1) {
            vec_push(v, ir);
            continue;
        }

        assert(ir->r0 != ir->r1);

        ir2 = calloc(1, sizeof(*ir2));
        ir2->op = IR_MOV;
        ir2->r0 = ir->r0;
        ir2->r2 = ir->r1;
        vec_push(v, ir2);

        ir->r1 = ir->r0;
        vec_push(v, ir);
    }

    bb->ir = v;
}

static vec_t *ir_collect(prog_t *prog) {
    vec_t *vec = vec_new();
    int ic = 1;
    int i, j, k;
    bb_t* bb;
    ir_t* ir;

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];

        for (j = 0; j < bb->ir->len; j++, ic++) {
            ir = bb->ir->data[j];

            if (ir->r0 && !ir->r0->def) {
                ir->r0->def = ic;
                vec_push(vec, ir->r0);
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
            reg_t *reg = bb->out_regs->data[j];
            ir_set_end(reg, ic);
        }
    }

    return vec;
}

static int ir_spill(reg_t **used) {
    int i, k = 0;
    for (i = 1; i < regnum; i++) {
        if (used[k]->end < used[i]->end) {
            k = i;
        }
    }
    return k;
}

void ir_scan(vec_t *regs) {
    int i, j, k;
    bool found;
    reg_t **used = calloc(regnum, sizeof(reg_t *));

    for (i = 0; i < regs->len; i++) {
        reg_t *reg = regs->data[i];
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

        used[regnum - 1] = reg;

        k = ir_spill(used);
        reg->rn = k;
        used[k]->rn = regnum - 1;
        used[k]->spill = true;
        used[k] = reg;
    }
}

void ir_regs_alloc(prog_t *prog) {
    int i;
    bb_t *bb;
    vec_t *regs;
    node_t *var;

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];
        ir_trans(bb);
    }

    regs = ir_collect(prog);
    ir_scan(regs);
}

prog_t *gen_prog(node_t *n) {
    prog = prog_new(n);

    gen_ir(n);
    ir_liveness(prog);
    ir_regs_alloc(prog);

    return prog;
}
