idf_component_register(SRCS "app_main.c"
                    INCLUDE_DIRS ".")

# Increase main task stack size
target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192)

# Critical linker flag to allow multiple definitions for ieee80211_raw_frame_sanity_check bypass
target_link_libraries(${COMPONENT_LIB} "-Wl,-z,muldefs")
