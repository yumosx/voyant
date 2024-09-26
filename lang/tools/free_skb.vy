#skb;

probe kfree_skb {
    skb[comm()] |> count();
}