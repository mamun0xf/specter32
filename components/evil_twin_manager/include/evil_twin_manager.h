#ifndef EVIL_TWIN_MANAGER_H
#define EVIL_TWIN_MANAGER_H

#include <stdbool.h>
#include "esp_err.h"

typedef enum {
    VERIFY_STATE_IDLE,
    VERIFY_STATE_IN_PROGRESS,
    VERIFY_STATE_SUCCESS,
    VERIFY_STATE_FAIL
} evil_twin_verify_state_t;

esp_err_t evil_twin_manager_init(void);
esp_err_t evil_twin_manager_start(void);
esp_err_t evil_twin_manager_stop(void);
bool evil_twin_manager_is_running(void);
void evil_twin_manager_handle_password_submission(const char *password);
evil_twin_verify_state_t evil_twin_manager_get_verification_status(void);

#endif
