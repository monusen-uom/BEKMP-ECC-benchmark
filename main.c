#include "micro-ecc/uECC.h"
#include "BEKMP.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "sha.h"
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <math.h>

double total_time_spent = 0.0;
pthread_mutex_t time_mutex = PTHREAD_MUTEX_INITIALIZER;
long total_memory_consumed = 0;  // Accumulate memory consumed by all threads
int total_threads_measured = 0;  // Number of threads for which memory has been measured
pthread_mutex_t memory_lock = PTHREAD_MUTEX_INITIALIZER;

long get_memory_usage() {
    long rss = 0L;
    FILE *fp = NULL;
    if ((fp = fopen("/proc/self/status", "r")) == NULL) return (size_t)0L;
    char line[128];
    while (fgets(line, 128, fp) != NULL) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            rss = strtol(&line[6], NULL, 0);
            break;
        }
    }
    fclose(fp);
    return rss;
}


struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) return 0;  /* out of memory! */

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int getCertificate(uint8_t *assetId, uint8_t **certificate) {
  int isFound = 0;
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;

  chunk.memory = malloc(1);  
  chunk.size = 0;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:3000/GetCertificate/%s", assetId);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
      struct json_object *parsed_json, *found, *data, *certificateObj;
      parsed_json = json_tokener_parse(chunk.memory);
     
      json_object_object_get_ex(parsed_json, "found", &found);
      isFound = json_object_get_boolean(found);

      if (isFound) {
        json_object_object_get_ex(parsed_json, "data", &data);
        json_object_object_get_ex(data, "certificate", &certificateObj);
        *certificate = (uint8_t *)strdup(json_object_get_string(certificateObj));
      }
    }
    curl_easy_cleanup(curl);
    free(chunk.memory);
  }
  curl_global_cleanup();
  return isFound;
}

int getDevice(uint8_t *deviceId, bool *status) {
  int isFound = 0;
  CURL *curl; CURLcode res; struct MemoryStruct chunk;
  chunk.memory = malloc(1);  chunk.size = 0;
  curl_global_init(CURL_GLOBAL_ALL); curl = curl_easy_init();
  if(curl) {
    char url[256]; snprintf(url, sizeof(url), "http://localhost:3000/getDevice/%s", deviceId);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
      struct json_object *parsed_json, *found, *data, *statusObj;
      parsed_json = json_tokener_parse(chunk.memory);
      json_object_object_get_ex(parsed_json, "found", &found);
      isFound = json_object_get_boolean(found);
      if (isFound) {
        json_object_object_get_ex(parsed_json, "data", &data);
        json_object_object_get_ex(data, "status", &statusObj);
        *status = strcmp(json_object_get_string(statusObj), "true") == 0;
      }
    }
    curl_easy_cleanup(curl); free(chunk.memory);
  }
  curl_global_cleanup();
  return isFound;
}

void storeCertificate(uint8_t *id, uint8_t *color) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char data[256];
    snprintf(data, sizeof(data), "{\"id\":\"%s\", \"color\":\"%s\"}", (char *)id, (char *)color);

    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/storeCertificate");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
}

void storeKey(uint8_t *device, uint8_t *cluster, uint8_t *color) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char data[256];
    snprintf(data, sizeof(data), "{\"device\":\"%s\", \"cluster\":\"%s\", \"color\":\"%s\"}", (char *)device, (char *)cluster, (char *)color);

    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/storeKey");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
}

int getKey(uint8_t *device, uint8_t *cluster, uint8_t **key) {
  CURL *curl;
  CURLcode res;
  struct MemoryStruct chunk;

  chunk.memory = malloc(1);
  chunk.size = 0;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:3000/getKey/%s/%s", (char *)device, (char *)cluster);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      return 0;
    } else {
      // Parse JSON and populate key
      struct json_object *parsed_json, *found, *data, *keyObj;
      parsed_json = json_tokener_parse(chunk.memory);
     
      json_object_object_get_ex(parsed_json, "found", &found);
      int isFound = json_object_get_boolean(found);

      if (isFound) {
        json_object_object_get_ex(parsed_json, "data", &data);
        json_object_object_get_ex(data, "key", &keyObj);
       
        *key = (uint8_t *)strdup(json_object_get_string(keyObj));
        return 1;
      } else {
        return 0;
      }
    }

    curl_easy_cleanup(curl);
    free(chunk.memory);
  }
  curl_global_cleanup();
  return 0;
}


int open_port(const char* port) {
    return open(port, O_RDWR | O_NOCTTY);
}

int configure_port(int fd, struct termios* tty) {
    if (tcgetattr(fd, tty) != 0) return -1;

    cfsetospeed(tty, B9600);
    cfsetispeed(tty, B9600);

    tty->c_cflag &= ~PARENB;
    tty->c_cflag &= ~CSTOPB;
    tty->c_cflag &= ~CSIZE;
    tty->c_cflag |= CS8;

    return tcsetattr(fd, TCSANOW, tty);
}

int send_message(int fd, const char* message) {
    return write(fd, message, strlen(message));
}

int read_message(int fd, int *length, char *message) {
    char c, length_str[3];
    int read_status = read(fd, &c, 1);
   
    if (read_status != 1 || c != '#') return 0;
    read_status = read(fd, &c, 1);
    printf("Debug: First read status: %d, First character: %c\n", read_status, c);

    if (read_status != 1 || c != 'U') return 0;
    if (read(fd, length_str, 2) != 2) return 0;
    length_str[2] = '\0';
    sscanf(length_str, "%d", length);
    if (*length < 2 || *length > 64) return 0;
    if (read(fd, message, *length) != *length) return 0;
    message[*length] = '\0';
    return 1;
}

const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint8_t* base64_encode(const uint8_t *input, int length, int *outLength) {
    *outLength = 4 * ((length + 2) / 3);
    uint8_t *output = (uint8_t*) malloc(*outLength);
    int i = 0, j = 0;
    uint8_t char_array_3[3], char_array_4[4];

    while (length--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                output[j++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (int k = i; k < 3; k++) char_array_3[k] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int k = 0; k < i + 1; k++) output[j++] = base64_chars[char_array_4[k]];
        while (i++ < 3) output[j++] = '=';
    }

    return output;
}

uint8_t* base64_decode(const uint8_t *input, int length, int *outLength) {
    *outLength = length / 4 * 3;
    if (input[length - 1] == '=') (*outLength)--;
    if (input[length - 2] == '=') (*outLength)--;

    uint8_t *output = (uint8_t*) malloc(*outLength);
    int i = 0, j = 0, in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];

    while (length--) {
        char_array_4[i++] = input[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = strchr(base64_chars, char_array_4[i]) - base64_chars;

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) output[j++] = char_array_3[i];
            i = 0;
        }
    }
    return output;
}

char* assemble_message(uint8_t* encoded_data, int encoded_length, const char* destination) {
    char data_size_str[3];
    snprintf(data_size_str, 3, "%02d", encoded_length);
    int total_size_for_msg = 2 + strlen(destination) + 2 + encoded_length; // $U + destination + size_of_data + data
    int total_size_for_alloc = total_size_for_msg + 1; // +1 for null_terminator
    char* msg = malloc(total_size_for_alloc);

    if (msg != NULL) {
        snprintf(msg, total_size_for_alloc, "$U%s%s", destination, data_size_str);
        strncat(msg, (char*)encoded_data, encoded_length);
    }
    return msg;
}

void xor_encrypt_decrypt(uint8_t *input, uint8_t *key, uint8_t *output, size_t len) {
  for (size_t i = 0; i < len; i++) {
    output[i] = input[i] ^ key[i % 32];
  }
}

int read_message_from_cli(char *message, int *length, char *cli_input) {
  // Your message handling logic here

  *length = strlen(cli_input);
  strncpy(message, cli_input, *length);
  message[*length] = '\0';
  return 1; // Assume success
}

int storeMeasurement(uint8_t *nodeId, double measurement, double energyLevel, char *timestamp) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    char data[512];
    snprintf(data, sizeof(data), "{\"nodeId\":\"%s\", \"measurement\":%f, \"energyLevel\":%f, \"timestamp\":\"%s\"}", nodeId, measurement, energyLevel, timestamp);
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/storeMeasurement");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      return 0;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
  return 1;
}

// Update Energy Trust
int updateEnergyTrust(char *nodeId, double threshold) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    char data[256];
    snprintf(data, sizeof(data), "{\"nodeId\":\"%s\", \"threshold\":%f}", nodeId, threshold);
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/updateEnergyTrust");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      return 0;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
  return 1;
}

// Update Communication Trust
int updateCommunicationTrust(char *nodeId, bool isSuccess) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    char data[256];
    snprintf(data, sizeof(data), "{\"nodeId\":\"%s\", \"isSuccess\":%s}", nodeId, isSuccess ? "true" : "false");
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/updateCommunicationTrust");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      return 0;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
  return 1;
}

// Update Packet Trust
int updatePacketTrust(char *nodeId, double packetValue) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    char data[256];
    snprintf(data, sizeof(data), "{\"nodeId\":\"%s\", \"packetValue\":%f}", nodeId, packetValue);
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/updatePacketTrust");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      return 0;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
  return 1;
}

int revokeNodeIfBelowThreshold(char *nodeId, double w1, double w2, double w3, double compositeThreshold) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    char data[512];
    snprintf(data, sizeof(data), "{\"nodeId\":\"%s\", \"w1\":%.2f, \"w2\":%.2f, \"w3\":%.2f, \"compositeThreshold\":%.2f}",
             nodeId, w1, w2, w3, compositeThreshold);
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/revokeNodeIfBelowThreshold");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      return 0;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
  curl_global_cleanup();
  return 1;
}

void *generate_csr(void *arg) {
    if (arg == NULL) {
        fprintf(stderr, "arg is NULL.\n");
        return NULL;
    }
    void **args = (void **)arg;
    if (args[0] == NULL || args[1] == NULL || args[2] == NULL) {
        fprintf(stderr, "One or more argument pointers are NULL.\n");
        return NULL;
    }
    int *request_number = (int *)args[0];
    uint8_t *arg1 = (uint8_t *)args[1];
    uint8_t *arg2 = (uint8_t *)args[2];
    uint8_t public_ca[] = {0xB1, 0x42, 0x64, 0x44, 0xD4, 0xFE, 0xAE, 0x33, 0x91, 0x3A, 0xEB, 0x4F, 0x8C, 0xC6, 0xBF, 0x3D, 0x68, 0xB1, 0xBC, 0xC2, 0xAD, 0x39, 0xA7, 0x5C, 0x80, 0x14, 0xAD, 0xD7, 0x83, 0x17, 0x57, 0x4E, 0x1F, 0x40, 0x2A, 0x1A, 0x45, 0x41, 0x9D, 0xE8, 0x26, 0x8D, 0x1A, 0x9E, 0x7E, 0xA3, 0xC3, 0x4B};
    uint8_t private_ca[] = {0xBB, 0xB7, 0x84, 0x0E, 0x10, 0x96, 0xFC, 0xEB, 0x9F, 0x4F, 0x9F, 0xB2, 0x6D, 0xFF, 0x77, 0x73, 0xC0, 0x7A, 0x9D, 0x36, 0x17, 0x7B, 0xF9, 0xBF};

    // Declare csr variable
    struct csr_t csr;

    // Your curve and id
    uECC_Curve curve = uECC_secp192r1();
    const uint8_t id[ID_SIZE] = "200";

    // Your code block
    uint8_t private_csr[PRIVATE_SIZE] = {0};
    csr_request(&csr, private_csr, id, curve);
    
    size_t total_size = MESSAGE_TYPE + ID_SIZE + ID_SIZE + PT_COMPRESSED_SIZE;
    uint8_t *buffer = malloc(total_size);
    if (buffer == NULL) {
        fprintf(stderr, "Failed to allocate memory for buffer.\n");
        return NULL;
    }
    buffer[0] = 'c'; buffer[1] = '2'; buffer[2] = '0'; buffer[3] = '0';
    memcpy(buffer + MESSAGE_TYPE + ID_SIZE, csr.id, ID_SIZE);
    memcpy(buffer + MESSAGE_TYPE + ID_SIZE + ID_SIZE, csr.point, PT_COMPRESSED_SIZE);
    size_t encoded_length;
    uint8_t *encoded_data = base64_encode(buffer, total_size, &encoded_length);
    
    args[4] = malloc(sizeof(size_t));
    if (args[4] == NULL) {
        fprintf(stderr, "Failed to allocate memory for args[4].\n");
        free(buffer);
        return NULL;
    }
    *((size_t *) args[4]) = encoded_length;
    free(buffer);

    // Save encoded_data for the next stage (create_certificate)
    args[3] = encoded_data;

    return NULL;
}

void *create_certificate(void *arg) {
  uint8_t local_key[32] = { 0x9A, 0x3D, 0x2F, 0x46, 0x78, 0x9A, 0xE2, 0x23, 0x1C, 0x03, 0x3D, 0x16, 0x0A, 0x6C, 0x4A, 0x7F, 0x8D, 0x06, 0x1E, 0x9E, 0x0F, 0xEA, 0xB6, 0x48, 0x9C, 0x23, 0x13, 0xD8, 0xEA, 0xB6, 0x1C, 0x8D };
    void **args = (void **)arg;
    int *request_number = (int *)args[0];
    uint8_t *arg1 = (uint8_t *)args[1];
    uint8_t *encoded_data = (uint8_t *)args[3];
    size_t encoded_length = *((size_t *) args[4]);  // Add this line
    uint8_t shared_key1[32] = {0};
    uint8_t id_cluster[ID_SIZE + 1] = "201";
    uint8_t public_ca[] = {0xB1, 0x42, 0x64, 0x44, 0xD4, 0xFE, 0xAE, 0x33, 0x91, 0x3A, 0xEB, 0x4F, 0x8C, 0xC6, 0xBF, 0x3D, 0x68, 0xB1, 0xBC, 0xC2, 0xAD, 0x39, 0xA7, 0x5C, 0x80, 0x14, 0xAD, 0xD7, 0x83, 0x17, 0x57, 0x4E, 0x1F, 0x40, 0x2A, 0x1A, 0x45, 0x41, 0x9D, 0xE8, 0x26, 0x8D, 0x1A, 0x9E, 0x7E, 0xA3, 0xC3, 0x4B};
    uint8_t private_ca[] = {0xBB, 0xB7, 0x84, 0x0E, 0x10, 0x96, 0xFC, 0xEB, 0x9F, 0x4F, 0x9F, 0xB2, 0x6D, 0xFF, 0x77, 0x73, 0xC0, 0x7A, 0x9D, 0x36, 0x17, 0x7B, 0xF9, 0xBF};
    clock_t start_time, end_time;

    uint8_t crt[CRT_SIZE] = {0xBB, 0xB7, 0x84, 0x0E, 0x10, 0x96, 0xFC, 0xEB, 0x9F, 0x4F, 0x9F, 0xB2, 0x6D, 0xFF, 0x77, 0x73, 0xC0, 0x7A, 0x9D, 0x36, 0x17, 0x7B, 0xF9, 0xBF, 0x17, 0x7B, 0xF9, 0xBF};
    uint8_t r[PRIVATE_SIZE];
    uECC_Curve curve = uECC_secp192r1();
    // Base64 decode the received message
    int decodedLength;
    uint8_t *decodedMessage = base64_decode((uint8_t*)encoded_data, encoded_length, &decodedLength);
    uint8_t message_type[MESSAGE_TYPE];

    memcpy(message_type, decodedMessage, MESSAGE_TYPE);
    if(message_type[0] == 'y') {
        printf("csr received\n");
        start_time = clock();
        struct csr_t received_csr;

        uint8_t sender[ID_SIZE + 1];
        memcpy(sender, decodedMessage + MESSAGE_TYPE, ID_SIZE);
        sender[ID_SIZE] = '\0';
        bool status = true;
        getCertificate(sender, crt);
        end_time = clock(); 
        double duration = ((double) (end_time - start_time)) / CLOCKS_PER_SEC * 1000;
        printf("Elapsed time: %.2f ms\n", duration);  
        pthread_mutex_lock(&time_mutex);
        total_time_spent += duration;
        pthread_mutex_unlock(&time_mutex); 
        if(status) {
          memcpy(received_csr.id, decodedMessage + MESSAGE_TYPE + ID_SIZE, ID_SIZE);
          memcpy(received_csr.point, decodedMessage + MESSAGE_TYPE + ID_SIZE + ID_SIZE, PT_COMPRESSED_SIZE);
          
          int encodedLength;
          uint8_t *decodedData = base64_encode(received_csr.point, PT_COMPRESSED_SIZE, &encodedLength);
          for(int j=0; j<encodedLength;j++) {
              putchar(decodedData[j]);
          }
          printf("\n");
          // // Free the decoded message
          free(decodedData);
          crt_generation(r, crt, &received_csr, private_ca, public_ca, curve);

          int encodedCrtLength;
          uint8_t *encodedCRT = base64_encode(crt, CRT_SIZE, &encodedCrtLength);

          // Allocate a new buffer to hold null-terminated data
          uint8_t *nullTerminatedEncodedCRT = malloc(encodedCrtLength + 1);

          // Copy the original data
          memcpy(nullTerminatedEncodedCRT, encodedCRT, encodedCrtLength);

          // Add the null terminator
          nullTerminatedEncodedCRT[encodedCrtLength] = '\0';
          storeCertificate(sender, nullTerminatedEncodedCRT);           
        }  
        else {
          printf("Device not recognized\n");
        }        
    }
    else if(message_type[0] == 'c') {
        printf("y request received\n");
        
        uint8_t source[ID_SIZE + 1];
        uint8_t extracted2[PUBLIC_SIZE] = {0};
        uint8_t Y[PUBLIC_SIZE] = {0};

        memcpy(source, decodedMessage + MESSAGE_TYPE, ID_SIZE);
        source[ID_SIZE] = '\0';

        homqv_generate_key(shared_key1, Y, extracted2, crt, private_ca, public_ca, id_cluster, 0, curve);  

        uint8_t encrypted[32];
        xor_encrypt_decrypt(shared_key1, local_key, encrypted, 32);
        int encodedEncryptedKeyLength;
        uint8_t *encodedEncryptedKey = base64_encode(encrypted, 32, &encodedEncryptedKeyLength);
        // Allocate a new buffer to hold null-terminated data
        uint8_t *nullTerminatedEncodedKey = malloc(encodedEncryptedKeyLength + 1);

        // Copy the original data
        memcpy(nullTerminatedEncodedKey, encodedEncryptedKey, encodedEncryptedKeyLength);

        // Add the null terminator
        nullTerminatedEncodedKey[encodedEncryptedKeyLength] = '\0';  
        storeKey(source, id_cluster, nullTerminatedEncodedKey);
        free(encodedEncryptedKey);  

        uint8_t *retrieved_key = NULL;
        
        int isFound = getKey(source, id_cluster, &retrieved_key);

        isFound = 1;

        if (isFound) {
            // Base64 decode the retrieved key
            int decodedLength;
            uint8_t *decoded = base64_decode(retrieved_key, encodedEncryptedKeyLength, &decodedLength);

            // Decrypt the decoded key
            uint8_t decrypted[32];
            usleep(20000);
            xor_encrypt_decrypt(decoded, local_key, decrypted, 32);
            char destinacija[10]; // Make sure the buffer is large enough for the string representation
            int random_number;

            // Seed the random number generator
            srand(time(NULL));

            // Generate a random integer
            random_number = rand() % 1000;  // Random integer between 0 and 999

            // Convert integer to string
            snprintf(destinacija, sizeof(destinacija), "%d", random_number);
            char *destination = "200";
            double measurement = 25.5;
            double energyLevel = 75.0;
            double threshold = 10.0; // Energy threshold
            bool isSuccess = true; // Communication success flag
            double packetValue = 32.5; // Packet value for trust calculation

            // Generate current timestamp
            start_time = clock();
            time_t rawtime;
            struct tm *timeinfo;
            char timestamp[30];
            double w1 = 0.3; // Weight for energy trust
            double w2 = 0.3; // Weight for communication trust
            double w3 = 0.4; // Weight for packet trust
            double compositeThreshold = 0.5; // Composite trust threshold
            int successRevoke = revokeNodeIfBelowThreshold(destination, w1, w2, w3, compositeThreshold);      
            free(decoded);
            end_time = clock(); 
            double duration = ((double) (end_time - start_time)) / CLOCKS_PER_SEC * 1000;
            printf("Elapsed time: %.2f ms\n", duration);  
            pthread_mutex_lock(&time_mutex);
            total_time_spent += duration;
            pthread_mutex_unlock(&time_mutex); 
        } else {
            //printf("Key not found.\n");
        } 
        printf("\n");              
    }
    free(decodedMessage);
}

double poisson_interval(double lambda) {
    return -log(1.0 - (double) rand() / (RAND_MAX)) / lambda;
}



int main(int argc, char *argv[]) {

    uint8_t local_key[32] = { 0x9A, 0x3D, 0x2F, 0x46, 0x78, 0x9A, 0xE2, 0x23, 0x1C, 0x03, 0x3D, 0x16, 0x0A, 0x6C, 0x4A, 0x7F, 0x8D, 0x06, 0x1E, 0x9E, 0x0F, 0xEA, 0xB6, 0x48, 0x9C, 0x23, 0x13, 0xD8, 0xEA, 0xB6, 0x1C, 0x8D };

    char *destination = "200";
    int fd;
    struct termios tty;
    int length;
    char message[51];
    uECC_Curve curve;
    uint8_t shared_key1[32] = {0};
    uint8_t public_ca[] = {0xB1, 0x42, 0x64, 0x44, 0xD4, 0xFE, 0xAE, 0x33, 0x91, 0x3A, 0xEB, 0x4F, 0x8C, 0xC6, 0xBF, 0x3D, 0x68, 0xB1, 0xBC, 0xC2, 0xAD, 0x39, 0xA7, 0x5C, 0x80, 0x14, 0xAD, 0xD7, 0x83, 0x17, 0x57, 0x4E, 0x1F, 0x40, 0x2A, 0x1A, 0x45, 0x41, 0x9D, 0xE8, 0x26, 0x8D, 0x1A, 0x9E, 0x7E, 0xA3, 0xC3, 0x4B};
    uint8_t private_ca[] = {0xBB, 0xB7, 0x84, 0x0E, 0x10, 0x96, 0xFC, 0xEB, 0x9F, 0x4F, 0x9F, 0xB2, 0x6D, 0xFF, 0x77, 0x73, 0xC0, 0x7A, 0x9D, 0x36, 0x17, 0x7B, 0xF9, 0xBF};
    uint8_t id_cluster[ID_SIZE + 1] = "201";
    id_cluster[ID_SIZE] = '\0';
    const uint8_t id[ID_SIZE] = "200";
    struct csr_t csr;
    clock_t start_time, end_time;

    uint8_t crt[CRT_SIZE];
    uint8_t r[PRIVATE_SIZE];

    curve = uECC_secp192r1();

    char *cli_input = argv[1];

    srand(time(0));  // Initialize random seed
    int observation_period = 4;  // In seconds
    double elapsed_time = 0.0;
    double total_waiting_time = 0.0;
    // 1/10 5/10 10/20 15/30 20/40 25/50 30/60
    double lambda = 1.0;  // Average rate parameter
    int MAX_THREADS = 10; // Maximum number of threads
    pthread_t thread_ids[MAX_THREADS]; // Pre-allocated array of threads
    for (int i = 0; i < MAX_THREADS; ++i) {
        thread_ids[i] = 0;
    }
    int i = 0; // Index to keep track of next empty slot in thread_ids
    int active_threads = 0; // Counter for active threads
    //pthread_mutex_t lock; 
    while (elapsed_time < observation_period) {
        // Wait for an available thread slot if we're at the max
        double start_wait_time, end_wait_time;
        while (active_threads == MAX_THREADS) {
            start_wait_time = (double)clock() / CLOCKS_PER_SEC;
            //printf("Max thread count reached, waiting...\n");
            //pthread_mutex_lock(&lock);  // Lock mutex
            for (int j = 0; j < MAX_THREADS; ++j) {
                if (thread_ids[j] == 0) continue;  // Skip invalid thread IDs
                
                int ret = pthread_tryjoin_np(thread_ids[j], NULL);
                if (ret == 0) {
                    printf("Joined thread %lu\n", thread_ids[j]);
                    thread_ids[j] = 0;  // Reset the ID to an invalid state
                    active_threads--;  // Decrement the counter as this thread is done
                } else if (ret == EBUSY) {
                    // Thread is still running; do nothing
                } else {
                    printf("Failed to join thread %lu, error: %s\n", thread_ids[j], strerror(errno));
                }
            }
            //pthread_mutex_unlock(&lock);  // Unlock mutex
            usleep(1000);  // Wait a short time before checking again
            end_wait_time = (double)clock() / CLOCKS_PER_SEC;  // Capture the time at the end of the wait
            total_waiting_time += (end_wait_time - start_wait_time);
        }



        double wait_time = poisson_interval(lambda);
        usleep((unsigned int)(wait_time * 1000000));
        elapsed_time += wait_time;
        printf("Current elapsed_time: %.2f seconds\n", elapsed_time);
        if (elapsed_time < observation_period) {
            int *request_number = malloc(sizeof(int));
            uint8_t *arg1 = malloc(sizeof(uint8_t));
            uint8_t *arg2 = malloc(sizeof(uint8_t));

            *request_number = i + 1;
            *arg1 = i + 200;
            *arg2 = i + 3;

            void **args = malloc(4 * sizeof(void *));
            args[0] = request_number;
            args[1] = arg1;
            args[2] = arg2;

            clock_t start_time, end_time;
            start_time = clock();
            generate_csr(args);
            end_time = clock();

            double duration = ((double) (end_time - start_time)) / CLOCKS_PER_SEC * 1000;
            total_time_spent += duration;

            if (pthread_create(&thread_ids[active_threads], NULL, create_certificate, args) != 0) {
                printf("Failed to create thread for request: %d\n", *request_number);
                free(args);
            } else {
                printf("ACTIVE THREADS: %d \n", active_threads);
                active_threads++; // Increment the active thread count
                i++; // Increment for the next available request_number
            }
        }
    }

    // Wait for remaining threads to finish
    for (int j = 0; j < active_threads; j++) {
      if (thread_ids[j] == 0) continue;  // Skip invalid thread IDs
      pthread_join(thread_ids[j], NULL);  // Assuming it succeeds
    }

    printf("All certificates created.\n");
    double mean_time = (total_time_spent + total_waiting_time) / i;
    printf("Mean elapsed time: %.2f ms\n", mean_time);
    printf("Total time: %.2f ms\n", total_time_spent);
    printf("Wait time: %.2f ms\n", total_waiting_time);
    printf("Total rounds: %d\n", i);

    close(fd);
    return 0;
}
