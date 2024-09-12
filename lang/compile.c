
void emit_rec(node_t* n, ebpf_t* e) {
    ssize_t addr, size;
    node_t* arg;
    int id;

    id = e->evp->mapfd;
    addr = n->annot.addr;
    size = n->annot.size;

    ebpf_value_to_stack(e, n);

    ebpf_emit(e, CALL(BPF_FUNC_get_smp_processor_id));
	ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_0));
    
    ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_9));
	ebpf_emit_mapld(e, BPF_REG_2, id);

    ebpf_emit(e, MOV(BPF_REG_4, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_4, addr));

    ebpf_emit(e, MOV_IMM(BPF_REG_5, size));
	ebpf_emit(e, CALL(BPF_FUNC_perf_event_output));
}

void compile_bool(ebpf_t* code, int op, int r0, int r2) {
    ebpf_emit(code, JMP(op, gregs[r0], gregs[r2], 2));
    ebpf_emit(code, MOV_IMM(gregs[r0], 0));
    ebpf_emit(code, JMP_IMM(BPF_JA, 0, 0, 1));
    ebpf_emit(code, MOV_IMM(gregs[r0], 1)); 
}

void compile_dec(ebpf_t* code, node_t* var) {
    node_t* args;
    
    switch (var->type) {
    case NODE_MAP:
        ebpf_stack_zero(var->map.args, code);
        ebpf_stack_zero(var, code);
        ebpf_value_to_stack(code, var->map.args);
        break;
    case NODE_VAR:
        ebpf_stack_zero(var, code);
        break;
    default:
        break;
    }
}

void compile_map_update(ebpf_t* code, node_t* var) {
    ssize_t kaddr, vaddr;

    vaddr = var->annot.addr;
    kaddr = var->map.args->annot.addr;

    ebpf_emit_mapld(code, BPF_REG_1, var->annot.mapid);
	ebpf_emit(code, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(OP_ADD, BPF_REG_2, kaddr));
   
	ebpf_emit(code, MOV(BPF_REG_3, BPF_REG_10));
	ebpf_emit(code, ALU_IMM(OP_ADD, BPF_REG_3, vaddr));

	ebpf_emit(code, MOV_IMM(BPF_REG_4, 0));
	ebpf_emit(code, CALL(BPF_FUNC_map_update_elem));
}

void compile_ir(ir_t* ir, ebpf_t* code) {
    int r0 = ir->r0 ? ir->r0->rn : 0;
    int r1 = ir->r1 ? ir->r1->rn : 0; 
    int r2 = ir->r2 ? ir->r2->rn : 0;

    switch (ir->op) {
    case IR_IMM:
        ebpf_emit(code, MOV_IMM(gregs[r0], ir->imm));
        break;
    case IR_STR:
        ebpf_value_to_stack(code, ir->value);
        break;
    case IR_ADD:
        ebpf_emit(code, ALU(BPF_ADD, gregs[r0], gregs[r2]));
        break;
    case IR_GT:
        compile_bool(code, BPF_JGT, r0, r2);
        break;
    case IR_DEC:
        compile_dec(code, ir->value);
        break;
    case IR_STORE:
        ebpf_emit(code, MOV(gregs[r1], gregs[r2]));
        break;
    case IR_PUSH:
        ebpf_emit(code, STXDW(BPF_REG_10, ir->value->annot.addr, gregs[r0]));
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
    case IR_REC:
        emit_rec(ir->value, code);
        break;
    case IR_MAP_UPDATE:
        compile_map_update(code, ir->value);
        break;
    case IR_CALL:
        break;
    case IR_RETURN:
        break;
    default:
        break;
    }
}

reg_t* gen_expr(node_t* n) {
    switch (n->type) {
    case NODE_INT:
        return imm(n->integer);
    case NODE_STR:  
        return push(n);
    case NODE_EXPR:
        return gen_binop(n);
    case NODE_VAR:
        return load(n);
    case NODE_ASSIGN:
        return NULL;
    case NODE_CALL: {
        
        return ir->r0;
    }
    default:
        verror("unknown ast type");
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