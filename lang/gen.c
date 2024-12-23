#include "func.h"
#include "ir.h"

static struct bpf_insn* at;

const struct bpf_insn break_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN);
const struct bpf_insn continue_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN + 1);
const struct bpf_insn if_then_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN + 2);
const struct bpf_insn if_else_insn =
	JMP_IMM(BPF_JA, 0xf, INT32_MIN, INT16_MIN + 3);

int gregs[3] =  {BPF_REG_6, BPF_REG_7, BPF_REG_8}; 

#define LOG2_CMP(_bit)\
	ebpf_emit(code, JMP_IMM(BPF_JSGE, src, (1<<(_bit)), 1));\
	ebpf_emit(code, JMP_IMM(BPF_JA, 0, 0, 2));\
	ebpf_emit(code, ALU_IMM(BPF_ADD, dst, _bit));\
	ebpf_emit(code, ALU_IMM(BPF_RSH, src, _bit));\

int emit_log2(ebpf_t* code, int dst, int src) {
	int cmp = BPF_REG_5;

	ebpf_emit(code, MOV_IMM(dst, 0));

	ebpf_emit(code, JMP_IMM(BPF_JSGE, src, 0, 2));
	ebpf_emit(code, ALU_IMM(BPF_SUB, dst, 1));
	ebpf_emit(code, JMP_IMM(BPF_JA, 0, 0, 8+5*4));

	ebpf_emit(code, JMP_IMM(BPF_JEQ, src, 0, 7+5*4));
	
	ebpf_emit(code, ALU_IMM(BPF_ADD, dst, 1));

	ebpf_emit(code, MOV_IMM(cmp, 1));
	ebpf_emit(code, ALU_IMM(BPF_LSH, cmp, 32));
	
	ebpf_emit(code, JMP(BPF_JSGE, src, cmp, 1));
	ebpf_emit(code, JMP_IMM(BPF_JA, 0, 0, 2));
	ebpf_emit(code, ALU_IMM(BPF_ADD, dst, 32));
	ebpf_emit(code, ALU_IMM(BPF_RSH, src, 32));

	LOG2_CMP(16);
	LOG2_CMP(8);
	LOG2_CMP(4);
	LOG2_CMP(2);
	LOG2_CMP(1);
	return 0;
}

void compile_map_update(ebpf_t* code, node_t* var) {
    ssize_t kaddr, vaddr, size;
    int fd;

    vaddr = var->annot.addr;
    kaddr = var->map.args->annot.addr;
    size = var->annot.ksize;
    fd = var->annot.mapid;

    ebpf_emit_map_update(code, fd, kaddr, vaddr);
}

void compile_map_look(ebpf_t* code, node_t* map, ir_t* ir) {
    int fd;
    ssize_t kaddr, vaddr, vsize;

    fd = map->annot.mapid;
    kaddr = map->map.args->annot.addr;
    vsize = map->annot.size;
    vaddr = map->annot.addr;
    
    ebpf_emit_map_look(code, fd, kaddr);
    
    ebpf_emit_read(code, vaddr, BPF_REG_0, vsize);

    if (map->annot.type == TYPE_INT) {
        ebpf_emit(code, LDXDW(gregs[ir->r0->rn], vaddr, BPF_REG_10));
    }

}

void map_count(node_t* map, ebpf_t* code) {
    int fd;
    ssize_t kaddr, vaddr, vsize;

    fd = map->annot.mapid;
    kaddr = map->map.args->annot.addr;
    vsize = map->annot.size;
    vaddr = map->annot.addr;

    ebpf_stack_zero(map, code, 0);

    ebpf_emit_map_look(code, fd, kaddr);
    ebpf_emit(code, JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8));
    ebpf_emit_read(code, vaddr, BPF_REG_0, vsize);

    ebpf_emit_count(code, vaddr);
    ebpf_emit_map_update(code, fd, kaddr, vaddr);
}

void compile_comm(node_t* n, ebpf_t* e) {
	size_t i;
	
	for (i = 0; i < n->annot.size; i += 4) {
		ebpf_emit(e, STW_IMM(BPF_REG_10, n->annot.addr+i, 0));
	}

	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, n->annot.addr));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, n->annot.size));
	ebpf_emit(e, CALL(BPF_FUNC_get_current_comm));
}

void compile_rec(node_t* n, ebpf_t* code) {
    ssize_t addr, size;
    node_t* arg;
    int id;

    id = code->evp->mapfd;
    addr = n->annot.addr;
    size = n->annot.size;
    
    ebpf_emit(code, MOV(BPF_REG_1, BPF_REG_9));
	ebpf_emit_mapld(code, BPF_REG_2, id);

	ebpf_emit(code, MOV32_IMM(BPF_REG_3, BPF_F_CURRENT_CPU));
    ebpf_emit(code, MOV(BPF_REG_4, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(BPF_ADD, BPF_REG_4, addr));

    ebpf_emit(code, MOV_IMM(BPF_REG_5, size));
	ebpf_emit(code, CALL(BPF_FUNC_perf_event_output));
}

void compile_call(node_t* n, ebpf_t* e) {
    if (n->annot.type == TYPE_REC) {
        compile_rec(n, e);
        return;
    }
}

void to_stack(node_t* obj, ebpf_t* code) {
    switch (obj->type) {
    case NODE_STR:
        ebpf_str_to_stack(code, obj);
        break;
    case NODE_CALL:
        compile_comm(obj, code);
        break;
    default:
        break;
    }
}

void store_data(vec_t* vec, ebpf_t* e) {
    int i, len;
    node_t* obj;

    len = vec->len;    

    for (i = 0; i < len; i++) {
        obj = (node_t*)vec->data[i];
        to_stack(obj, e);
    }
}

void copy_data(ebpf_t* ebpf, ir_t* ir) {
    ssize_t to, from;
    size_t size;
    sym_t* sym;
    node_t* n = ir->value;

    sym = symtable_get(ebpf->st, n->name);
    to = n->annot.addr;
    from = sym->vannot.addr;
    size = n->annot.size;

    if (n->annot.type == TYPE_INT) {
        ebpf_emit(ebpf, LDXDW(gregs[ir->r0->rn], from, BPF_REG_10));
        return;
    }

    ebpf_value_copy(ebpf, to, from, size);
}

void read_trace_args(ir_t* ir, ebpf_t* code) {
    node_t* right, *expr;
    ssize_t addr;
    size_t size, offs;

    expr = ir->value;
    right = expr->expr.right;

    addr = expr->annot.addr;
    size = expr->annot.size;
    offs = right->annot.offs;

    switch (right->annot.type) {
    case TYPE_INT:
        ebpf_emit(code, LDXDW(BPF_REG_0, offs, BPF_REG_9));
        ebpf_emit(code, MOV(gregs[ir->r0->rn], BPF_REG_0));
        break;
    case TYPE_STR:
        ebpf_emit(code, MOV(BPF_REG_1, BPF_REG_10));
        ebpf_emit(code, ALU_IMM(BPF_ADD, BPF_REG_1, addr));
        ebpf_emit(code, MOV_IMM(BPF_REG_2, size));
        ebpf_emit(code, LDXDW(BPF_REG_3, offs, BPF_REG_9));
        ebpf_emit(code, CALL(BPF_FUNC_probe_read_user_str));
        break;
    default:
        break;
    }
}

void read_kprobe_args(ir_t* ir, ebpf_t* ctx) {
    ssize_t o, size, addr, offs;
    sym_t* sym;
    node_t* node;
    char* name;

    node = ir->value;
    name = node->expr.left->name;
    size = node->annot.size;
    addr = node->annot.addr;
    offs = node->annot.offs;
    
    sym = symtable_get(ctx->st, name);

    switch (sym->vannot.offs) {
    case 0:
        o = btf_get_field_off("pt_regs", "di");
        break;
    case 1:
        o = btf_get_field_off("pt_regs", "si");
        break;
    case 2:
        o = btf_get_field_off("pt_regs", "dx");
    default:
        break;
    }

    ebpf_emit(ctx, LDXDW(BPF_REG_3, o, BPF_REG_9));
    ebpf_emit(ctx, MOV(BPF_REG_1, BPF_REG_10));
    ebpf_emit(ctx, ALU_IMM(BPF_ADD, BPF_REG_1, addr));
    ebpf_emit(ctx, MOV_IMM(BPF_REG_2, size));
    ebpf_emit(ctx, ALU_IMM(BPF_ADD, BPF_REG_3, offs));
    ebpf_emit(ctx, CALL(BPF_FUNC_probe_read_kernel));

    ebpf_emit(ctx, LDXDW(gregs[ir->r0->rn], addr, BPF_REG_10));
}

//todo refactor
void read_args(ir_t* ir, ebpf_t* code) {
    if (code->name == NULL) {
        read_kprobe_args(ir, code);
    } else {
        read_trace_args(ir, code);
    }
}


void compile_ir(ir_t* ir, ebpf_t* code) {
    ssize_t addr;
    int r0 = ir->r0 ? ir->r0->rn : 0;
    int r1 = ir->r1 ? ir->r1->rn : 0; 
    int r2 = ir->r2 ? ir->r2->rn : 0;

    switch (ir->op) {
    case IR_IMM:
        ebpf_emit(code, MOV_IMM(gregs[r0], ir->imm));
        break;
    case IR_SUB:
        ebpf_emit(code, ALU(BPF_SUB, gregs[r0], gregs[r2]));
        break;
    case IR_ADD:
        ebpf_emit(code, ALU(BPF_ADD, gregs[r0], gregs[r2]));
        break;
    case IR_EQ:
        ebpf_emit_bool(code, BPF_JEQ, r0, r2);
        break;
    case IR_MUL:
        ebpf_emit(code, ALU(BPF_MUL, gregs[r0], gregs[r2]));
        break;
    case IR_DIV:
        ebpf_emit(code, ALU(BPF_DIV, gregs[r0], gregs[r2]));
        break;
    case IR_GT:
        ebpf_emit_bool(code, BPF_JGT, r0, r2);
        break;
    case IR_GE:
        ebpf_emit_bool(code, BPF_JGE, r0, r2);
        break;
    case IR_LT:
        ebpf_emit_bool(code, BPF_JGT, r2, r0);
        break;
    case IR_LE:
        ebpf_emit_bool(code, BPF_JGE, r2, r0);
        break;
    case IR_COPY:
        copy_data(code, ir);
        break;
    case IR_INIT:
        ebpf_stack_zero(ir->value, code, BPF_REG_0);
        break;
    case IR_STORE:
        addr = ir->value->annot.addr;
        ebpf_emit(code, STXDW(BPF_REG_10, addr, gregs[r2]));
        break;
    case IR_ARG:
        ebpf_emit(code, STXDW(BPF_REG_10, ir->addr, gregs[r0]));
        break;
    case IR_MAP_UPDATE:
        compile_map_update(code, ir->value);
        break;
    case IR_MAP_LOOK:
        compile_map_look(code, ir->value, ir);
        break;
    case IR_RCALL:
        global_compile(ir->value, code, 0);
        ebpf_emit(code, MOV(gregs[r0], BPF_REG_0));
        break; 
    case IR_CALL:
        compile_call(ir->value, code); 
        break;
    case IR_BR:
        ebpf_emit(code, MOV(BPF_REG_0, gregs[r2]));
        break;
    case IR_IF_THEN:
        at = code->ip;
        ebpf_emit(code, if_then_insn);
        break;
    case IR_IF_END:
        ebpf_emit_at(at, JMP_IMM(BPF_JEQ, 0, 0, code->ip-at-1));
        break;
    case IR_MAP_METHOD:
        map_count(ir->value, code);
        break;
    case IR_READ:
        read_args(ir, code);
        break;
    case IR_RETURN:
        ebpf_emit(code, MOV_IMM(BPF_REG_0, 0));
	    ebpf_emit(code, EXIT);
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

    e = prog->ctx;

    ebpf_emit(e, MOV(BPF_CTX_REG, BPF_REG_1));
    store_data(prog->data, e);

    for (i = 0; i < prog->bbs->len; i++) {
        bb = prog->bbs->data[i];     
        for (j = 0; j < bb->ir->len; j++) {
            ir = bb->ir->data[j];
            compile_ir(ir, e);
        }
    }
}
