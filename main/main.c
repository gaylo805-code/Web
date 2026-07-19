#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "dns_sniffer.h"

void app_main(void) {
    printf("ESP32 DNS Sniffer Started!\n");
    init_dns_sniffer();
    while (1) {
        printf("Running...\n");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
