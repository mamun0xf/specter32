idf_component_register(SRCS "web_server.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "esp_http_server" "wifi_manager" "attack_manager" "evil_twin_manager" "filesystem_manager" "json"
                    EMBED_FILES "web/index.html" "web/style.css" "web/script.js" "web/captive_portal.html" )
