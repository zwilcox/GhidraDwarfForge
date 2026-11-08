extern __thread int effect_tls;
int effect_read_tls(void) {
    return effect_tls;
}
