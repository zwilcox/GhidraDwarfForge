namespace left {
int item = 17;
int unique_value = 41;
}
namespace right {
int item = 29;
}
int item = 53;
extern "C" __attribute__((noinline)) int marker() {
    return left::item + right::item + left::unique_value + item;
}
int main() { return marker() != 140; }
