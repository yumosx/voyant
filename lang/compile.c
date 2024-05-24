
void compile_var_assign(node_t* a, ebpf_t* e) {
    reg_t* dst = ebpf_reg_get(e);
    ebpf_reg_load(e, dst, expr);
    ebpf_reg_bind(e, dst, a->assign.lval);
}

void compile_map_assign(node_t* n, ebpf_t* e) {
   emit_ld_mapfd(e, BPF_REG_1, n->assign.lval->annot.mapid);
   
   //we get the value
   if (n->assign.expr->annot.type == NODE_INT) {
       ebpf_emit(e, ALU_IMM(n->assign.op, BPF_REG_0, n->assign.expr->integer));       
       ebpf_emit(e, STXDW(BPF_REG_10, n->assign.lval->annot.addr, BPF_REG_0));   
   }
    
   emit_ld_mapfd(e, BPF_REG_1, n->assign.lval->annot.mapid);
   ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
   ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, n->assign.lval->annot.addr + n->assign.lval->annot.size));
   
   ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_10));
   ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_3, n->assign.lval->annot.addr));

   ebpf_emit(e, MOV_IMM(BPF_REG_4, 0));
   ebpf_emit(e, CALL(BPF_FUNC_map_update_elem));
}


void node_assign_walk(node_t* a, ebpf_t* e) {
    get_annot(a, e);
    
    node_t* expr = a->assign.expr;
    node_walk(expr, e);
    
    if (a->assign.lval->type == NODE_MAP) {
        compile_map_assign(a, e); 
    } else if(a->assign.lval->type == NODE_VAR) {    
        compile_var_assign(a, e); 
    }
}

