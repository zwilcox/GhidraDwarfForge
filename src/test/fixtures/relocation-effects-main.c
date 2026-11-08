extern unsigned char effect_copy[37];
extern int effect_read_tls(void);
int main(void) {
    for (int index = 0; index < 37; index++) {
        if (effect_copy[index] != index + 1) return index + 1;
    }
    return effect_read_tls() == 41 ? 0 : 42;
}
