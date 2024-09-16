
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

void compile_bool(ebpf_t* code, int op, int r0, int r2) {
    ebpf_emit(code, JMP(op, gregs[r0], gregs[r2], 2));
    ebpf_emit(code, MOV_IMM(gregs[r0], 0));
    ebpf_emit(code, JMP_IMM(BPF_JA, 0, 0, 1));
    ebpf_emit(code, MOV_IMM(gregs[r0], 1)); 
}

void compile_map_update(ebpf_t* code, node_t* var) {
    ssize_t kaddr, vaddr, size;

    vaddr = var->annot.addr;
    kaddr = var->map.args->annot.addr;
    size = var->annot.ksize;

    ebpf_emit_mapld(code, BPF_REG_1, var->annot.mapid);
	
    ebpf_emit(code, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(OP_ADD, BPF_REG_2, kaddr));
   
	ebpf_emit(code, MOV(BPF_REG_3, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(OP_ADD, BPF_REG_3, vaddr));

	ebpf_emit(code, MOV_IMM(BPF_REG_4, 0));
	ebpf_emit(code, CALL(BPF_FUNC_map_update_elem));
}

void emit_read(ebpf_t* e, ssize_t to, int from, size_t size) {
	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_1, to));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, size));
	ebpf_emit(e, MOV(BPF_REG_3, from));
	ebpf_emit(e, CALL(BPF_FUNC_probe_read));
}

void emit_look(ebpf_t* code, int fd, ssize_t kaddr) {
    ebpf_emit_mapld(code, BPF_REG_1, fd);
    ebpf_emit(code, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(BPF_ADD, BPF_REG_2, kaddr));
	ebpf_emit(code, CALL(BPF_FUNC_map_lookup_elem));
}

void emit_update(ebpf_t* code, int fd, ssize_t kaddr, ssize_t vaddr) {
    ebpf_emit_mapld(code, BPF_REG_1, fd);
	
    ebpf_emit(code, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(OP_ADD, BPF_REG_2, kaddr));
   
	ebpf_emit(code, MOV(BPF_REG_3, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(OP_ADD, BPF_REG_3, vaddr));

	ebpf_emit(code, MOV_IMM(BPF_REG_4, 0));
	ebpf_emit(code, CALL(BPF_FUNC_map_update_elem));
}


void emit_count(ssize_t addr, ebpf_t* code) {
	ebpf_emit(code, LDXB(BPF_REG_0, addr, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(BPF_ADD, BPF_REG_0, 1));
	ebpf_emit(code, STXDW(BPF_REG_10, addr, BPF_REG_0));
}

void compile_map_look(ebpf_t* code, node_t* map) {
    int fd;
    ssize_t kaddr, vaddr, vsize;

    fd = map->annot.mapid;
    kaddr = map->map.args->annot.addr;
    vsize = map->annot.size;
    vaddr = map->annot.addr;

    ebpf_emit_mapld(code, BPF_REG_1, fd);
    ebpf_emit(code, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(BPF_ADD, BPF_REG_2, kaddr));
	ebpf_emit(code, CALL(BPF_FUNC_map_lookup_elem));
    emit_read(code, vaddr, BPF_REG_0, vsize);
}

void map_count(node_t* map, ebpf_t* code) {
    int fd;
    ssize_t kaddr, vaddr, vsize;

    fd = map->annot.mapid;
    kaddr = map->map.args->annot.addr;
    vsize = map->annot.size;
    vaddr = map->annot.addr;

   //_d("%d %d %d\n", kaddr, vsize, vaddr);

    ebpf_stack_zero(map, code, 0);

    emit_look(code, fd, kaddr);
    ebpf_emit(code, JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8));
    emit_read(code, vaddr, BPF_REG_0, vsize);

    emit_count(vaddr, code);
    emit_update(code, fd, kaddr, vaddr);
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

void compile_rec(node_t* n, ebpf_t* e) {
    ssize_t addr, size;
    node_t* arg;
    int id;

    id = e->evp->mapfd;
    addr = n->annot.addr;
    size = n->annot.size;


    ebpf_emit(e, CALL(BPF_FUNC_get_smp_processor_id));
	ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_0));
    
    ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_9));
	ebpf_emit_mapld(e, BPF_REG_2, id);

    ebpf_emit(e, MOV(BPF_REG_4, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_4, addr));

    ebpf_emit(e, MOV_IMM(BPF_REG_5, size));
	ebpf_emit(e, CALL(BPF_FUNC_perf_event_output));
}

void compile_call(node_t* n, ebpf_t* e) {
    if (n->annot.type == TYPE_REC) {
        compile_rec(n, e);
        return;
    }
}

void to_stack(node_t* obj, ebpf_t* code) {
    switch (obj->annot.type) {
    case TYPE_STR:
        ebpf_str_to_stack(code, obj);
        break;
    case TYPE_RSTR:
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

void copy_data(ebpf_t* e, node_t* n) {
    ssize_t to, from;
    size_t size;
    sym_t* sym;
    
    sym = symtable_get(e->st, n->name);
    to = n->annot.addr;
    from = sym->vannot.addr;
    size = n->annot.size;

    //_d("copy value from the %d to %d", from, to);
    ebpf_value_copy(e, to, from, size);
}

void load_value(ebpf_t* code, node_t* n, int reg) {
    sym_t* sym;
    ssize_t from; 

    sym = symtable_get(code->st, n->name);
    from = n->annot.addr;
    
    //_d("load value from addr: %d to reg %d", from, reg);
    ebpf_emit(code, LDXDW(reg, from, BPF_REG_10));
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
    case IR_ADD:
        ebpf_emit(code, ALU(BPF_ADD, gregs[r0], gregs[r2]));
        break;
    case IR_MUL:
        ebpf_emit(code, ALU(BPF_MUL, gregs[r0], gregs[r2]));
        break;
    case IR_GT:
        compile_bool(code, BPF_JGT, r0, r2);
        break;
    case IR_LOAD:
        load_value(code, ir->value, gregs[r0]);
        break;
    case IR_COPY:
        copy_data(code, ir->value);
        break;
    case IR_INIT:
        ebpf_stack_zero(ir->value, code, BPF_REG_0);
        break;
    case IR_STORE:
        addr = ir->value->annot.addr;
        ebpf_emit(code, STXDW(BPF_REG_10, addr, gregs[r2]));
        break;
    case IR_MAP_UPDATE:
        compile_map_update(code, ir->value);
        break;
    case IR_MAP_LOOK:
        compile_map_look(code, ir->value);
        break;
    case IR_RCALL:
        global_compile(ir->value, code);
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

    e = prog->e;

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
