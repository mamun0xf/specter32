idf_component_register(SRCS "packet_handler.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_wifi esp_event)

# Add linker flag to allow multiple definitions (for ieee80211_raw_frame_sanity_check override)
target_link_libraries(${COMPONENT_LIB} "-Wl,-z,muldefs")
