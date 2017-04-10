/*
MIT License

Copyright (c) 2017 MH Lim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mqtt_version_s
{
	mqtt_version_3_1 = 0,
	mqtt_version_3_1_1 = 1
} mqtt_version_s;

typedef enum tls_version_s
{
	tls_version_1_0 = 0,
	tls_version_1_1 = 1,
	tls_version_1_2 = 2
} tls_version_s;

typedef struct mqtt_client_info_s
{
	char *server;
	char *client_id;
	char *username;
	char *password;
	char *will_topic;
	char *will_message;
	char *ca_cert;
	char *cert;
	char *private_key;
	mqtt_version_s version;
	tls_version_s tls_version;
	unsigned short port;
	unsigned short keep_alive;
	unsigned short will_qos;
	bool clean_session;
	bool will_retain;
	bool verify_server;
} mqtt_client_info_s;

void mqtt_client_info_init(mqtt_client_info_s *info);
char *mqtt_client_strdup(const char *src);
void mqtt_client_free(void *mem);
void mqtt_client_info_delete(mqtt_client_info_s *info);
void mqtt_client_info_init(mqtt_client_info_s *info);
void mqtt_client_info_delete(mqtt_client_info_s *info);
int mqtt_client_parse_command_line(int argc, char *argv[], mqtt_client_info_s *info);
void mqtt_client_print_usage(const char *program_name);

#ifdef __cplusplus
}
#endif

#endif
