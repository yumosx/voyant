#include <stdint.h>
#include <stdio.h>

#include "func.h"
#include "buffer.h"
#include "ut.h"

static int annot_rint(node_t* n) {
    n->annot.type = TYPE_INT;
    n->annot.size = 8;
}

static int annot_rstr(node_t* n) {
    n->annot.type = TYPE_STR;
	n->annot.size = _ALIGNED(16);
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
		verror("should has a string fromat");
		return -1;
	}
    
	evh = vcalloc(1, sizeof(*evh));
    evh->priv = call;
	evh->handle = event_output;
	
	evhandler_register(evh);	
	
	meta = node_int_new(evh->type);
	meta->annot.type = TYPE_INT;
	meta->annot.size = 8;
	meta->next = varg->next;
	
	rec = node_rec_new(meta);
	varg->next = rec;
}

static int annot_strcmp(node_t* call) {
	node_t* arg = call->call.args;
	
	if (!arg || arg->type != NODE_STR) {
		verror("strcmp requires string arguments");
	}

	arg = arg->next;

	if (!arg || arg->type != NODE_STR) {
		verror("strcmp requires string arguments");
	}

	call->annot.type = TYPE_INT;
    call->annot.size = 8;
}


static int compile_rint_func(enum bpf_func_id func, extract_op_t op, ebpf_t* e, node_t* n) {
	ebpf_emit(e, CALL(func));
    
    switch(op) {
        case EXTRACT_OP_MASK:
			ebpf_emit(e, ALU_IMM(BPF_AND, BPF_REG_0, 0x7fffffff));
            break;
        case EXTRACT_OP_SHIFT:
            ebpf_emit(e, ALU_IMM(BPF_RSH, BPF_REG_0, 32));
            break;
		case EXTRACT_OP_DIV_1G:
			ebpf_emit(e, ALU_IMM(BPF_DIV, BPF_REG_0, 1000000000));
        default:
            break;
    }
	
	return 0; 
}

int compile_gid(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_get_current_uid_gid, EXTRACT_OP_SHIFT, e, n);
}

int compile_uid(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_get_current_uid_gid, EXTRACT_OP_MASK, e, n);
}

int compile_pid(node_t* n, ebpf_t* e) {
    return compile_rint_func(BPF_FUNC_get_current_pid_tgid, EXTRACT_OP_SHIFT, e, n);
}

int compile_tid(node_t* n, ebpf_t* e) {
    return compile_rint_func(BPF_FUNC_get_current_pid_tgid, EXTRACT_OP_MASK, e, n);
}

int compile_ns(node_t* n, ebpf_t* e) {
	 return compile_rint_func(BPF_FUNC_ktime_get_ns, EXTRACT_OP_NONE, e, n);
}

int compile_sens(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_ktime_get_ns, EXTRACT_OP_DIV_1G, e, n);
}

int compile_bns(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_ktime_get_boot_ns, EXTRACT_OP_NONE, e, n);
}

int compile_cpu(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_get_smp_processor_id, EXTRACT_OP_NONE, e, n);
}

int compile_stack(node_t* call, ebpf_t* code) {
	ebpf_emit(code, MOV(BPF_REG_1, BPF_REG_9));
	ebpf_emit_mapld(code, BPF_REG_2, call->annot.mapid);
	ebpf_emit(code, MOV_IMM(BPF_REG_3, 0));
	ebpf_emit(code, CALL(BPF_FUNC_get_stackid));
}

static builtin_t global_builtins[] = {
	builtin("tid", annot_rint, compile_tid),
	builtin("gid", annot_rint, compile_gid),
	builtin("pid", annot_rint, compile_pid),
	builtin("uid", annot_rint, compile_uid),
	builtin("cpu", annot_rint, compile_cpu),
	builtin("ns", annot_rint, compile_ns),
	builtin("secs", annot_rint,  compile_sens),
	builtin("bns", annot_rint, compile_bns),
	builtin("log", annot_rint, NULL),
	builtin("comm", annot_rstr, NULL),
	builtin("out", annot_out, NULL),
	builtin("strcmp", annot_strcmp, NULL),
};


int global_annot(node_t* n) {
    builtin_t* bi;

    for (bi = global_builtins; bi->name; bi++) {
		if (vstreq(bi->name, n->name))
            return bi->annotate(n);
    }

    return -1;
}

int global_compile(node_t* n, ebpf_t* e, type_t type) {
	builtin_t* bi;

	for (bi = global_builtins; bi->name; bi++) {
		if (vstreq(bi->name, n->name))
			return bi->compile(n, e);
	}

	return -1;
}
