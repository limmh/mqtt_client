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

#include "client.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined _WIN32 || defined _WIN64
#define strcasecmp stricmp
#else
#include <strings.h>
#endif

char *mqtt_client_strdup(const char *src)
{
	size_t length = strlen(src);
	size_t size = length + 1;
	char *str = (char*) malloc(size);
	if (str) {
		strncpy(str, src, length);
		str[length] = '\0';
	}
	return str;
}

void mqtt_client_free(void *mem)
{
	free(mem);
}

void mqtt_client_info_init(mqtt_client_info_s *info)
{
	info->server = NULL;
	info->client_id = NULL;
	info->username = NULL;
	info->password = NULL;
	info->will_topic = NULL;
	info->will_message = NULL;
	info->ca_cert = NULL;
	info->cert = NULL;
	info->private_key = NULL;
	info->version = mqtt_version_3_1_1;
	info->tls_version = tls_version_1_2;
	info->port = 1883;
	info->keep_alive = 0;
	info->will_qos = 1;
	info->clean_session = true;
	info->will_retain = false;
	info->verify_server = false;
}

void mqtt_client_info_delete(mqtt_client_info_s *info)
{
	mqtt_client_free(info->server);
	mqtt_client_free(info->client_id);
	mqtt_client_free(info->username);
	mqtt_client_free(info->password);
	mqtt_client_free(info->will_topic);
	mqtt_client_free(info->will_message);
	mqtt_client_info_init(info);
}

enum param_error_s
{
	param_error_success = 0,
	param_error_invalid_param,
	param_error_duplicated_param,
	param_error_missing_value,
	param_error_invalid_value,
	param_error_open_failed
};

static void print_invalid_param_warning(const char *param)
{
	printf("\"%s\" is not a valid parameter.\n", param);
}

static void print_duplicated_param_warning(const char *param)
{
	printf("The parameter \"%s\" is duplicated.\n", param);
}

static void print_missing_value_warning(const char *param)
{
	printf("The value for the parameter \"%s\" is missing or empty.\n", param);
}

static void print_invalid_value_warning(const char *param, const char *value)
{
	printf("\"%s\" is not a valid value for the parameter \"%s\".\n", value, param);
}

static int file_can_be_opened(const char *file)
{
	FILE *fp = fopen(file, "rb");
	int ret = (NULL != fp) ? 0 : errno;
	if (fp) fclose(fp);
	return ret;
}

int mqtt_client_parse_command_line(int argc, char *argv[], mqtt_client_info_s *info)
{
	int i = 0, last_error = 0;
	enum param_error_s param_error = param_error_success;
	int np = 0, nka = 0, ncs = 0, nwq = 0, nr = 0, nvs = 0, nver = 0, ntls = 0;
	mqtt_client_info_delete(info);
	char *param = NULL, *value = NULL;

	while (i < argc) {
		param = argv[i];
		value = ((i + 1) >= argc) ? NULL : argv[i + 1];

		if (!strcasecmp(param, "-server")) {
			if (info->server) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value) {
				param_error = param_error_missing_value;
				break;
			}
			info->server = mqtt_client_strdup(value);
		} else if (!strcasecmp(param, "-port")) {
			if (np > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_invalid_value;
				break;
			} else {
				char *endptr = NULL;
				long port = strtol(value, &endptr, 10);
				if (!endptr || '\0' != *endptr || port < 1 || port > 65535) {
					param_error = param_error_invalid_value;
					break;
				}
				info->port = port;
				np++;
			}
		} else if (!strcasecmp(param, "-keepalive")) {
			if (nka > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else {
				char *endptr = NULL;
				long keepalive = strtol(value, &endptr, 10);
				if (!endptr || '\0' != *endptr || keepalive < 0 || keepalive > 65535) {
					param_error = param_error_invalid_value;
					break;
				}
				info->keep_alive = keepalive;
				nka++;
			}
		} else if (!strcasecmp(param, "-cleansession")) {
			if (ncs > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else if (strcasecmp(value, "true") == 0) {
				info->clean_session = true;
				ncs++;
			} else if (strcasecmp(value, "false") == 0) {
				info->clean_session = false;
				ncs++;
			} else {
				param_error = param_error_invalid_value;
				break;
			}
		} else if (!strcasecmp(param, "-clientid")) {
			if (info->client_id) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			}
			info->client_id = mqtt_client_strdup(value);
		} else if (!strcasecmp(param, "-username")) {
			if (info->username) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value) {
				param_error = param_error_missing_value;
				break;
			}
			info->username = mqtt_client_strdup(value);
		} else if (!strcasecmp(param, "-password")) {
			if (info->password) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value) {
				param_error = param_error_missing_value;
				break;
			}
			info->password = mqtt_client_strdup(value);
		} else if (!strcasecmp(param, "-willtopic")) {
			if (info->will_topic) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			}
			info->will_topic = mqtt_client_strdup(value);
		} else if (!strcasecmp(param, "-willmessage")) {
			if (info->will_message) {
				param_error = param_error_duplicated_param;
				break;
			}
			info->will_message = (NULL != value) ? mqtt_client_strdup(value) : NULL;
		} else if (!strcasecmp(param, "-willqos")) {
			if (nwq > 0 ) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else {
				char *endptr = NULL;
				long qos = strtol(value, &endptr, 10);
				if (!endptr || '\0' != *endptr || qos < 0 || qos > 2) {
					param_error = param_error_invalid_value;
					break;
				}
				info->will_qos = qos;
				nwq++;
			}
		} else if (!strcasecmp(param, "-willretain")) {
			if (nr > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value) {
				param_error = param_error_missing_value;
				break;
			} else if (strcasecmp(value, "true") == 0) {
				info->will_retain = true;
				nr++;
			} else if (strcasecmp(value, "false") == 0) {
				info->will_retain = false;
				nr++;
			} else {
				param_error = param_error_invalid_value;
				break;
			}
		} else if (!strcasecmp(param, "-cacert")) {
			if (info->ca_cert) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else {
				last_error = file_can_be_opened(value);
				if (last_error) {
					param_error = param_error_open_failed;
					break;
				}
				info->ca_cert = mqtt_client_strdup(value);
			}
		} else if (!strcasecmp(param, "-cert")) {
			if (info->cert) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else {
				last_error = file_can_be_opened(value);
				if (last_error) {
					param_error = param_error_open_failed;
					break;
				}
				info->cert = mqtt_client_strdup(value);
			}
		} else if (!strcasecmp(param, "-privatekey")) {
			if (info->private_key) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else {
				last_error = file_can_be_opened(value);
				if (last_error) {
					param_error = param_error_open_failed;
					break;
				}
				info->private_key = mqtt_client_strdup(value);
			}
			info->private_key = mqtt_client_strdup(value);
		} else if (!strcasecmp(param, "-verifyserver")) {
			if (nvs > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else if (!strcasecmp(value, "-true")) {
				info->verify_server = true;
				nvs++;
			} else if (!strcasecmp(value, "false")) {
				info->verify_server = false;
				nvs++;
			} else {
				param_error = param_error_invalid_value;
				break;
			}
		} else if (!strcasecmp(param, "-mqtt")) {
			if (nver > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else if (!strcmp(value, "3.1")) {
				info->version = mqtt_version_3_1;
				nver++;
			} else if (!strcmp(value, "3.1.1")) {
				info->version = mqtt_version_3_1_1;
				nver++;
			} else {
				param_error = param_error_invalid_value;
				break;
			}
		} else if (!strcasecmp(param, "-tls")) {
			if (ntls > 0) {
				param_error = param_error_duplicated_param;
				break;
			} else if (NULL == value || '\0' == value[0]) {
				param_error = param_error_missing_value;
				break;
			} else if (!strcmp(value, "1.0") || !strcmp(value, "1")) {
				info->tls_version = tls_version_1_0;
				ntls++;
			} else if (!strcmp(value, "1.1")) {
				info->tls_version = tls_version_1_1;
				ntls++;
			} else if (!strcmp(value, "1.2")) {
				info->tls_version = tls_version_1_2;
				ntls++;
			} else {
				param_error = param_error_invalid_value;
				break;
			}
		} else {
			param_error = param_error_invalid_param;
			break;
		}

		i += 2;
	}

	if (param_error_success != param_error) {
		switch (param_error) {
		case param_error_invalid_param:
			print_invalid_param_warning(param);
			break;
		case param_error_duplicated_param:
			print_duplicated_param_warning(param);
			break;
		case param_error_missing_value:
			print_missing_value_warning(param);
			break;
		case param_error_invalid_value:
			print_invalid_value_warning(param, value);
			break;
		case param_error_open_failed:
			printf("%s: %s\n", value, strerror(last_error));
			break;
		default:
			break;
		}
		mqtt_client_info_delete(info);
		return 0;
	}

	return 1;
}

void mqtt_client_print_usage(const char *program_name)
{
	printf("%s ", program_name);
	printf("-server <server name or address> [-port <port_number>]\n");
	printf("[-mqtt <MQTT version>]\n");
	printf("[-cleansession <true or false>] ");
	printf("[-keepalive <between 0 and 65535 inclusive>]\n");
	printf("[-clientid <ID>] ");
	printf("[-username <user name>] [-password <password>]\n");
	printf("[-willtopic <topic>] [-willmessage <message>] [-willqos <QoS>] [-willretain <true or false>]\n");
	printf("[-tls <TLS version>] [-cacert <CA certificate file path>] [-cert <client certificate file path>] [-privatekey <client private key file path>]\n");
	printf("[-verifyserver <true or false>]\n");
	printf("\n");
	printf("Parameters:\n");
	printf("-server: server name or address\n");
	printf("-port: server port number (default: 1883)\n");
	printf("-mqtt: MQTT version (3.1 or 3.1.1, default: 3.1.1)\n");
	printf("-cleansession: enables or disables clean session (default: true)\n");
	printf("-keepalive: keep alive value (0 to 65535, default: 0)\n");
	printf("-clientid: client ID (default: auto-generated)\n");
	printf("-username: username (optional)\n");
	printf("-password: password (optional)\n");
	printf("-willtopic: will topic (optional)\n");
	printf("-willmessage: will message (optional)\n");
	printf("-willqos: will QoS (0 to 2, optional, default: 1)\n");
	printf("-willretain: will retain (optional, default: false)\n");
	printf("-tls: TLS version (optional, default: 1.2)\n");
	printf("-cacert: Certificate Authority certificate file that is used to sign the client certificate (in PEM format)\n");
	printf("-cert: client certificate file (in PEM format)\n");
	printf("-privatekey: client private key file (in PEM format)\n");
	printf("-verifyserver: enable or disable server verification (default: false)\n");
}
