#include <stdio.h>
#include "sqlite3.h"

volatile unsigned int observed_count;
volatile unsigned int observed_sum;

__attribute__((noinline)) unsigned int benchmark_checkpoint(void)
{
    return observed_count + observed_sum;
}

int main(void)
{
    sqlite3 *database = 0;
    sqlite3_stmt *statement = 0;
    if (sqlite3_open(":memory:", &database) != SQLITE_OK) {
        return 1;
    }
    if (sqlite3_exec(database,
            "CREATE TABLE sample(value INTEGER PRIMARY KEY);"
            "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL "
            "SELECT n+1 FROM numbers WHERE n<100) "
            "INSERT INTO sample SELECT n FROM numbers;",
            0, 0, 0) != SQLITE_OK) {
        sqlite3_close(database);
        return 2;
    }
    if (sqlite3_prepare_v2(database, "SELECT count(*), sum(value) FROM sample;",
            -1, &statement, 0) != SQLITE_OK) {
        sqlite3_close(database);
        return 3;
    }
    int result = sqlite3_step(statement);
    if (result == SQLITE_ROW) {
        observed_count = (unsigned int) sqlite3_column_int(statement, 0);
        observed_sum = (unsigned int) sqlite3_column_int(statement, 1);
    }
    sqlite3_finalize(statement);
    sqlite3_close(database);
    if (result != SQLITE_ROW || observed_count != 100 || observed_sum != 5050 ||
            benchmark_checkpoint() != 5150) {
        return 4;
    }
    printf("sqlite-workload=PASS count=%u sum=%u\n", observed_count, observed_sum);
    return 0;
}
