#kprobe;

probe dev_queue_xmit {
	sk := (sk_buff*) arg0;
	out("comm: %s len: %d\n", comm(), sk->len);
}