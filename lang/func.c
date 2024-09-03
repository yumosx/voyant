#include <stdint.h>
#include <stdio.h>

#include "func.h"
#include "buffer.h"
#include "ut.h"

static int annot_rint(node_t* n) {
    n->annot.type = ANNOT_RINT;
    n->annot.size = 8;
}

static int annot_rstr(node_t* n) {
    n->annot.type = ANNOT_RSTR;
	n->annot.size = _ALIGNED(16);
}

static int annot_probe_str(node_t* n) {
	node_t* arg;

	n->annot.type = ANNOT_RSTR;
	n->annot.size = 16;
}

static void printf_spec(const char* spec, const char* term, void* data, node_t* arg) {
	int64_t num;
	size_t fmt_len;
	char* fmt;

	memcpy(&num, data, sizeof(num));
	fmt_len = term - spec + 1;
	fmt = strndup(spec, fmt_len);
	
	switch(*term) {
	case 's':
		printf(fmt, (char*)data);
		break;
	case 'd':
		printf(fmt, (int)num);
		break;
	}

	free(fmt);
}

static int event_output(event_t* ev, void* _call) {
	node_t* arg, *call = _call;
	char* fmt, *spec, *name, *str;
	void* data = ev->data;

	name = call->call.args->name;

	arg = call->call.args->next->rec.args->next; 
	str = call->call.args->name;	

	str_escape(str);	
	
	for (fmt = str; *fmt; fmt++) {
		if (*fmt == '%' && arg) {
			spec = fmt;
			fmt = strpbrk(spec, "scd");
			if (!fmt) 
				break;
			printf_spec(spec, fmt, data, arg);
			
			data += arg->annot.size;
			arg = arg->next;
		} else {
			fputc(*fmt, stdout);
		}
	}
	return 0;
}

static int annot_out(node_t* call) {
    evhandler_t* evh;
	node_t* meta, *head, *varg, *rec;
	size_t size; 
	ssize_t addr;

	varg = call->call.args;
	if (!varg) {
		_errmsg("should has a string fromat");
		return -1;
	}
    
	evh = vcalloc(1, sizeof(*evh));
    evh->priv = call;
	evh->handle = event_output;
	
	evhandler_register(evh);	
	
	meta = node_int_new(evh->type);
	meta->annot.type = ANNOT_INT;
	meta->annot.size = 8;
	meta->next = varg->next;
	
	rec = node_rec_new(meta);
	varg->next = rec;
}

int compile_rint_func(enum bpf_func_id func, extract_op_t op, ebpf_t* e, node_t* n) {
	ebpf_emit(e, CALL(func));
    
    switch(op) {
        case EXTRACT_OP_MASK:
            ebpf_emit(e, ALU_IMM(OP_AND, BPF_REG_0, 0xffffffff));
            break;
        case EXTRACT_OP_SHIFT:
            ebpf_emit(e, ALU_IMM(OP_RSH, BPF_REG_0, 32));
            break;
		case EXTRACT_OP_DIV_1G:
			ebpf_emit(e, ALU_IMM(OP_DIV, BPF_REG_0, 1000000000));
        default:
            break;
    }
	
	ebpf_emit(e, STXDW(BPF_REG_10, n->annot.addr, BPF_REG_0));
	return 0; 
}

int compile_pid(node_t* n, ebpf_t* e) {
    return compile_rint_func(BPF_FUNC_get_current_pid_tgid, EXTRACT_OP_MASK, e, n);
}

int compile_ns(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_ktime_get_ns, EXTRACT_OP_DIV_1G, e, n);
}

int compile_cpu(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_get_smp_processor_id, EXTRACT_OP_NONE, e, n);
}

void compile_comm(node_t* n, ebpf_t* e) {
	size_t i;
	
	for (i = 0; i < n->annot.size; i += 4) {
		ebpf_emit(e, STW_IMM(BPF_REG_10, n->annot.addr+i, BPF_REG_0));
	}

	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, n->annot.addr));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, n->annot.size));
	ebpf_emit(e, CALL(BPF_FUNC_get_current_comm));
}

int compile_probe_str(node_t* n, ebpf_t* e) {
	ssize_t addr, size, from;
	node_t* arg;

	addr = n->annot.addr;
	size = n->annot.size;
	
	stack_init(n, e);
	
	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_1, addr));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, size));

	ebpf_emit(e, LDXDW(BPF_REG_3, 16, BPF_REG_9));
	ebpf_emit(e, CALL(BPF_FUNC_probe_read_user_str));
}

static builtin_t global_builtins[] = {
	builtin("pid", annot_rint, compile_pid),
	builtin("cpu", annot_rint, compile_cpu),
	builtin("ns", annot_rint,  compile_ns),
	builtin("comm", annot_rstr, compile_comm),
	builtin("arg", annot_probe_str, compile_probe_str),	
	builtin("out", annot_out, NULL),
	builtin("close", NULL, NULL),
};

int global_annot(node_t* n) {
    builtin_t* bi;

    for (bi = global_builtins; bi->name; bi++) {
        if (vstreq(bi->name, n->name))
            return bi->annotate(n);
    }

    return -1;
}

int global_compile(node_t* n, ebpf_t* e) {
	builtin_t* bi;

	for (bi = global_builtins; bi->name; bi++) {
		if (vstreq(bi->name, n->name))
			return bi->compile(n, e);
	}

	return -1;
}