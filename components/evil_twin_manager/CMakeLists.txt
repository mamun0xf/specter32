idf_component_register(SRCS "evil_twin_manager.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_wifi esp_event nvs_flash lwip packet_handler wifi_manager filesystem_manager attack_manager)
