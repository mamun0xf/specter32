idf_component_register(SRCS "attack_manager.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "esp_wifi" "packet_handler" "filesystem_manager" "wifi_manager" "web_server")
