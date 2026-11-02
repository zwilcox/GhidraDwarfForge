/* Load the real aggregate DSO through the target's normal dynamic loader. */
extern int aggregate_fixture_main(void);
extern int aggregate_fixture_before(void);

int main(void)
{
    if (aggregate_fixture_before() != 17) {
        return 1;
    }
    return aggregate_fixture_main();
}
