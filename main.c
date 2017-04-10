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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "client.h"
#include "queue.h"
#include "utils.h"

#include <mosquitto.h>
#include <pthread.h>

#if defined _WIN32 || defined _WIN64
#include <Windows.h>
#define strcasecmp stricmp
#define sleep(n) Sleep(n * 1000)
#else
#include <unistd.h>
#include <strings.h>
#endif

typedef struct client_s
{
	struct mosquitto *mqtt;
	mqtt_client_info_s info;
	queue_s *received;
	pthread_mutex_t mutex;
	bool run;
	bool conn_lost;
} client_s;

static void generate_client_id(char *buffer, size_t buffer_size)
{
	static const char pattern[] = "0123456789ABCDEFGHIJKLMNOPQSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	static const size_t pattern_size = (sizeof pattern)/(sizeof pattern[0]) - 1;
	utils_generate_random_sequence(pattern, pattern_size, buffer, buffer_size);
}

static void init_username_password(mqtt_client_info_s *info)
{
	if (info->username && !info->password) {
		char *pwd = NULL;
		printf("Enter a password: ");
		utils_gets_quiet(&pwd);
		info->password = mqtt_client_strdup(pwd);
		utils_delete(pwd);
	}
}

static const char *get_error_message(int error)
{
#if defined _WIN32 || defined _WIN64
	static char buffer[512];
	const size_t buffer_size = (sizeof buffer) / (sizeof buffer[0]);
	DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	FormatMessageA(flags, NULL, error, lang, buffer, buffer_size, NULL);
	buffer[buffer_size - 1] = '\0';
	return buffer;
#else
	return strerror(error);
#endif
}

static void on_connect(struct mosquitto *m, void *obj, int rc)
{
	client_s *c = (client_s*) obj;
	printf("%s\n", mosquitto_connack_string(rc));
	if (0 == rc)
		printf("Successfully connected to %s (port %d).\n", c->info.server, c->info.port);
	else
		printf("Failed to connect to %s (port %d).\n", c->info.server, c->info.port);
}

static void on_disconnect(struct mosquitto *m, void *obj, int rc)
{
	client_s *c = (client_s*) obj;
	printf("Disconnection code: %d\n", rc);
	if (0 == rc) {
		c->conn_lost = false;
		printf("Successfully disconnected from %s (port %d).\n", c->info.server, c->info.port);
	} else {
		c->conn_lost = true;
		printf("Disconnected from %s (port %d).\n", c->info.server, c->info.port);
	}
}

static void on_subscribe(struct mosquitto *m, void *obj, int mid, int qos_count, const int *granted_qos)
{
	printf("Packet ID %d: The topic has been subscribed.\n", mid);
}

static void on_publish(struct mosquitto *m, void *obj, int mid)
{
	printf("Packet ID %d: The message has been published.\n", mid);
}

static void client_received_data_delete(void *data)
{
	struct mosquitto_message *msg = (struct mosquitto_message*) data;
	free(msg->payload);
	utils_delete(msg->topic);
	memset(msg, 0, sizeof *msg);
}

static void on_message(struct mosquitto *m, void *obj, const struct mosquitto_message *msg)
{
	client_s *c = (client_s*) obj;
	struct mosquitto_message message;

	message.payload = malloc(msg->payloadlen);
	if (NULL == message.payload) {
		printf("Message received: Out of memory error.\n");
		return;
	}

	memcpy(message.payload, msg->payload, (size_t) msg->payloadlen);
	message.topic = utils_strdup(msg->topic);
	if (NULL == message.topic) {
		free(message.payload);
		printf("Message received: Out of memory.\n");
		return;
	}

	message.payloadlen = msg->payloadlen;
	message.mid = msg->mid;
	message.qos = msg->qos;
	message.retain = msg->retain;
	queue_push_back(c->received, &message, sizeof message, client_received_data_delete);
}

static void on_unsubscribe(struct mosquitto *m, void *obj, int mid)
{
	printf("\nPacket ID %d: The topic has been unsubscribed.\n>> ", mid);
}

static void get_topic(char **input)
{
	do {
		printf("Topic: ");
		utils_get_stdin(input);
	} while (NULL == *input || '\0' == (*input)[0]);
}

static void get_message(char **input)
{
	do {
		printf("Message: ");
		utils_get_stdin(input);
	} while (NULL == *input);
}

static int get_qos(void)
{
	long qos;
	do {
		char *input = NULL, *endptr = NULL;
		qos = -1;
		printf("QoS: ");
		utils_get_stdin(&input);
		if (input && '\0' != input[0]) {
			qos = (int) strtol(input, &endptr, 10);
			if (!endptr || '\0' != *endptr)
				qos = -1;
		}
		utils_delete(input);
	} while (qos < 0 || qos > 2);
	return (int) qos;
}

static unsigned long get_count(void)
{
	unsigned long count = 0;
	do {
		char *input = NULL;
		printf("Count (default: 1): ");
		utils_get_stdin(&input);
		if (input)
			count = ('\0' == input[0]) ? 1 : strtoul(input, NULL, 10);
		utils_delete(input);
	} while (count < 1);
	return count;
}

static bool get_retain(void)
{
	bool retain;
	char *input = NULL;
	for (;;) {
		printf("Retain (Y/N): ");
		utils_get_stdin(&input);
		if (input) {
			if (!strcasecmp(input, "y")) {
				retain = true;
				break;	
			} else if (!strcasecmp(input, "n")) {
				retain = false;
				break;
			}
		}
	} 
	return retain;
}

static void get_binary_data(char **data)
{
	for (;;) {
		printf("Binary data (hexadecimal sequence without any space): ");
		utils_get_stdin(data);
		if (data && utils_hex_sequence_is_valid(*data))
			break;
		else
			printf("Invalid hexadecimal sequence. Please try again.\n");
	}
}

static void get_file_path(char **path)
{
	for (;;) {
		printf("File path: ");
		utils_get_stdin(path);
		if (path) {
			FILE *fp = fopen(*path, "rb");
			if (!fp) {
				printf("%s\n", strerror(errno));
				continue;
			}
			fclose(fp);
			return;
		}
	}
}

static void client_cleanup(client_s *c)
{
	mosquitto_destroy(c->mqtt);
	mqtt_client_info_delete(&c->info);
	pthread_mutex_destroy(&c->mutex);
	queue_destroy(c->received);
	memset(c, 0, sizeof *c);
}

static int client_init(int argc, char *argv[], client_s *c)
{
	memset(c, 0, sizeof *c);
	c->received = queue_create();
	if (NULL == c->received) {
		printf("Out of memory.\n");
		return -1;
	}

	if (0 != pthread_mutex_init(&c->mutex, NULL)) {
		queue_destroy(c->received);
		printf("Failed to initialize mutex.\n");
		return -2;
	}

	mqtt_client_info_init(&c->info);
	mqtt_client_parse_command_line(argc, argv, &c->info);
	if (NULL == c->info.client_id || '\0' == c->info.client_id[0]) {
		char buffer[24];
		if (c->info.client_id)
			mqtt_client_free(c->info.client_id);
		generate_client_id(buffer, (sizeof buffer) / (sizeof buffer[0]));
		c->info.client_id = mqtt_client_strdup(buffer);
	}

	c->mqtt = mosquitto_new(c->info.client_id, c->info.clean_session, c);
	if (NULL == c->mqtt) {
		int error = errno;
		pthread_mutex_destroy(&c->mutex);
		queue_destroy(c->received);
		printf("Error %d: %s\n", error, mosquitto_strerror(error));
		return -3;
	}

	int mqtt_version;
	switch (c->info.version) {
	case mqtt_version_3_1:
		mqtt_version = MQTT_PROTOCOL_V31;
		break;
	case mqtt_version_3_1_1:
	default:
		mqtt_version = MQTT_PROTOCOL_V311;
		break;
	}
	mosquitto_opts_set(c->mqtt, MOSQ_OPT_PROTOCOL_VERSION, &mqtt_version);

	int rc;
	init_username_password(&c->info);
	if (c->info.username && '\0' != c->info.username[0]) {
		rc = mosquitto_username_pw_set(c->mqtt, c->info.username, c->info.password);
		if (MOSQ_ERR_SUCCESS != rc)
			printf("Error setting username and password. %s\n", mosquitto_strerror(rc));
	}

	if (c->info.will_topic) {
		rc = mosquitto_will_set(c->mqtt, c->info.will_topic, strlen(c->info.will_message), c->info.will_message, c->info.will_qos, c->info.will_retain);
		if (MOSQ_ERR_SUCCESS != rc)
			printf("Error in will topic configuration. %s\n", mosquitto_strerror(rc));
	}

	bool valid_tls = (c->info.ca_cert && c->info.cert && c->info.private_key);
	bool valid_normal = (NULL == c->info.ca_cert && NULL == c->info.cert && NULL == c->info.private_key);
	if (!(valid_tls || valid_normal)) {
		if (NULL == c->info.ca_cert)
			printf("The CA certificate file is not specified.\n");
		if (NULL == c->info.cert)
			printf("The client certificate file is not specified.\n");
		if (NULL == c->info.private_key)
			printf("The client private key file is not specified.\n");
		return -4;
	}

	if (valid_tls) {
		rc = mosquitto_tls_set(c->mqtt, c->info.ca_cert, NULL, c->info.cert, c->info.private_key, NULL);
		if (MOSQ_ERR_SUCCESS != rc) {
			printf("Error in TLS configuration. %s\n", mosquitto_strerror(rc));
			return -5;
		}
		int verify_server = c->info.verify_server ? 1 : 0;
		const char *tls_version;
		switch (c->info.tls_version) {
		case tls_version_1_0:
			tls_version = "tlsv1";
			break;
		case tls_version_1_1:
			tls_version = "tlsv1.1";
			break;
		case tls_version_1_2:
		default:
			tls_version = "tlsv1.2";
			break;
		}
		rc = mosquitto_tls_opts_set(c->mqtt, verify_server, tls_version, NULL);
		if (MOSQ_ERR_SUCCESS != rc) {
			printf("Error in setting TLS options. %s\n", mosquitto_strerror(rc));
			return -6;
		}
	}

	mosquitto_connect_callback_set(c->mqtt, on_connect);
	mosquitto_disconnect_callback_set(c->mqtt, on_disconnect);
	mosquitto_subscribe_callback_set(c->mqtt, on_subscribe);
	mosquitto_message_callback_set(c->mqtt, on_message);
	mosquitto_publish_callback_set(c->mqtt, on_publish);
	mosquitto_unsubscribe_callback_set(c->mqtt, on_unsubscribe);
	mosquitto_threaded_set(c->mqtt, true);

	c->run = false;
	c->conn_lost = false;
	return 0;
}

static bool client_is_running(client_s *c)
{
	pthread_mutex_lock(&c->mutex);
	bool run = c->run;
	pthread_mutex_unlock(&c->mutex);
	return run;
}

static void client_set_running_status(client_s *c, bool status)
{
	pthread_mutex_lock(&c->mutex);
	c->run = status;
	pthread_mutex_unlock(&c->mutex);
}

static int client_connect(client_s *c)
{
	if (NULL == c->info.server) {
		printf("The server is not specified.\n");
		return -1;		
	}

	printf("Connecting to %s (port %d) ...\n", c->info.server, c->info.port);
	int rc = mosquitto_connect(c->mqtt, c->info.server, c->info.port, c->info.keep_alive);
	if (MOSQ_ERR_SUCCESS == rc) {
		printf("Connected to %s (port %d). Waiting for MQTT connection to establish.\n", c->info.server, c->info.port);
	} else {
		if (MOSQ_ERR_ERRNO == rc) {
			rc = errno;
			printf("Error %d: %s\n", rc, get_error_message(rc));
		} else {
			printf("Cannot connect to %s (port %d). Error %d: %s\n", c->info.server, c->info.port, rc, mosquitto_strerror(rc));
		}
	}
	return rc;
}

static void client_disconnect(client_s *c)
{
	mosquitto_disconnect(c->mqtt);
}

static void client_publish(client_s *c, const char *topic, const void *message, int message_size, int qos, bool retain)
{
	int mid;
	int rc = mosquitto_publish(c->mqtt, &mid, topic, message_size, message, qos, retain);
	if (MOSQ_ERR_SUCCESS == rc)
		printf("Packet ID %d: The message for the topic \"%s\" is being published.\n", mid, topic);
	else
		printf("Failed to publish the message for \"%s\". Error %d: %s\n", topic, rc, mosquitto_strerror(rc));
}

static void client_subscribe(client_s *c)
{
	char *topic = NULL;
	get_topic(&topic);
	if (topic) {
		int qos = get_qos();
		int mid;
		int rc = mosquitto_subscribe(c->mqtt, &mid, topic, qos);
		if (MOSQ_ERR_SUCCESS == rc)
			printf("Packet ID %d: The topic \"%s\" is being subscribed.\n", mid, topic);
		else
			printf("Failed to subscribe to %s. Error %d: %s\n", topic, rc, mosquitto_strerror(rc));
		utils_delete(topic);
	}
}

static void client_publish_message(client_s *c)
{
	char *topic = NULL;
	get_topic(&topic);
	if (topic) {
		int qos = get_qos();
		bool retain = get_retain();
		char *message = NULL;
		get_message(&message);
		if (message) {
			unsigned long count = get_count();
			for (unsigned long i = 0; i < count; ++i)
				client_publish(c, topic, message, (int) strlen(message), qos, retain);
			utils_delete(message);
		}
		utils_delete(topic);
	}
}

static void client_publish_binary_data(client_s *c)
{
	char *topic = NULL;
	get_topic(&topic);
	if (topic) {
		int qos = get_qos();
		bool retain = get_retain();
		char *hex_seq = NULL;
		get_binary_data(&hex_seq);
		if (hex_seq) {
			void *data = NULL;
			size_t size = utils_hex_sequence_to_binary_data(hex_seq, &data);
			if (data) {
				unsigned long count = get_count();
				for (unsigned long i = 0; i < count; ++i)
					client_publish(c, topic, data, (int) size, qos, retain);
				utils_delete(data);
			}
			utils_delete(hex_seq);
		}
		utils_delete(topic);
	}
}

static void client_publish_file(client_s *c)
{
	char *topic = NULL;
	get_topic(&topic);
	if (topic) {
		int qos = get_qos();
		bool retain = get_retain();
		char *file_path = NULL;
		get_file_path(&file_path);
		if (file_path) {
			void *message = NULL;
			size_t size = utils_read_file(file_path, &message);
			if (message) {
				client_publish(c, topic, message, (int) size, qos, retain);
				utils_delete(message);
			}
			utils_delete(file_path);
		}
	}
}

static void client_unsubscribe(client_s *c)
{
	char *topic = NULL;
	get_topic(&topic);
	if (topic) {
		int mid;
		int rc = mosquitto_unsubscribe(c->mqtt, &mid, topic);
		if (MOSQ_ERR_SUCCESS == rc)
			printf("Packet ID %d: Topic \"%s\" is being unsubscribed.\n", mid, topic);
		else 
			printf("Failed to unsubscribe the topic \"%s\". Error %d: %s\n", topic, rc, mosquitto_strerror(rc));
	}
}

static void client_print_help(void)
{
	printf("Commands\n");
	printf("help - show this help message\n");
	printf("publish - publish messages for a topic\n");
	printf("subscribe - subscribe to a topic\n");
	printf("unsubscribe - unsubscribe from a topic\n");
	printf("binary - publish binary data for a topic\n");
	printf("file - publish file contents for a topic\n");
	printf("exit - disconnect and exit\n");
	printf("quit - the same as exit\n");
}

static void client_run(client_s *c)
{
	int run = 1;
	while (run) {
		char *input = NULL;
		utils_get_stdin(&input);
		if (!input)
			continue;
		if (strcasecmp(input, "subscribe") == 0) {
			client_subscribe(c);
		} else if (!strcasecmp(input, "publish")) {
			client_publish_message(c);
		} else if (!strcasecmp(input, "binary")) {
			client_publish_binary_data(c);
		} else if (!strcasecmp(input, "file")) {
			client_publish_file(c);
		} else if (!strcasecmp(input, "unsubscribe")) {
			client_unsubscribe(c);			
		} else if (!strcasecmp(input, "exit") || !strcasecmp(input, "quit")) {
			run = 0;
		} else if ('\0' == input[0] || !strcasecmp(input, "help")) {
			client_print_help();
		} else {
			printf("Unknown command: %s\n", input);
		}
		utils_delete(input);
	}
}

static void *mqtt_thread(void *arg)
{
	client_s *c = (client_s*) arg;
	client_set_running_status(c, true);
	bool running = true;

	while (running) {
		int rc = mosquitto_loop(c->mqtt, 1000, 1);
		if (MOSQ_ERR_NO_CONN == rc || MOSQ_ERR_CONN_LOST == rc) {
			if (c->conn_lost)
				mosquitto_reconnect(c->mqtt);
		}
		running = client_is_running(c);
	}

	return arg;
}

static void write_message_to_file(FILE *fp, struct mosquitto_message *msg)
{
	char buffer[512];
	snprintf(buffer, (sizeof buffer) / (sizeof buffer[0]), "%s, Q%d, %d byte%s%s\n", msg->topic, msg->qos, msg->payloadlen, (msg->payloadlen > 1) ? "s" : "", (msg->retain) ? ", retain" : "");
	buffer[(sizeof buffer) / (sizeof buffer[0]) - 1] = '\0';
	fwrite(buffer, 1, strlen(buffer), fp);
	fwrite(msg->payload, 1, msg->payloadlen, fp);
	fwrite("\n\n", 1, 2, fp);
}

static void *output_thread(void *arg)
{
	client_s *c = (client_s*) arg;
	struct mosquitto_message *msg;
	FILE *fp = fopen(c->info.client_id, "ab");
	if (!fp) {
		printf("Failed to to create or open %s. %s\n", c->info.client_id, strerror(errno));
		printf("The messages will be output to the terminal.\n");
	}

	bool output_to_file = fp ? true : false;
	fclose(fp);

	bool running;
	do {
		running = client_is_running(c);
		sleep(1);
	} while (!running);

	if (output_to_file) {
		while (running) {
			fp = fopen(c->info.client_id, "ab");
			if (fp) {
				queue_pop_front(c->received, (void**) &msg);
				while (msg) {
					write_message_to_file(fp, msg);
					client_received_data_delete(msg);
					queue_delete_data(msg);
					queue_pop_front(c->received, (void**) &msg);
				}
			}
			fclose(fp);
			sleep(1);
			running = client_is_running(c);
		}
	} else {
		while (running) {
			queue_pop_front(c->received, (void**) &msg);
			while (msg) {
				write_message_to_file(stdout, msg);
				client_received_data_delete(msg);
				queue_delete_data(msg);
				queue_pop_front(c->received, (void**) &msg);
			}
			sleep(1);
			running = client_is_running(c);
		}
	}

	return arg;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		mqtt_client_print_usage(argv[0]);
		return 0;
	}

	srand(time(NULL));
	mosquitto_lib_init();

	client_s client = {0};
	int rc = client_init(argc - 1, &argv[1], &client);
	if (0 != rc) {
		mosquitto_lib_cleanup();
		return -1;
	}

	printf("The client ID is %s.\n", client.info.client_id);
	rc = client_connect(&client);
	if (0 != rc) {
		mosquitto_lib_cleanup();
		return -2;
	}

	pthread_t thread_mqtt, thread_output;
	if (0 != pthread_create(&thread_mqtt, NULL, mqtt_thread, &client)) {
		printf("Failed to create the MQTT thread.\n");
		client_cleanup(&client);
		mosquitto_lib_cleanup();
		return -3;
	}

	if (0 != pthread_create(&thread_output, NULL, output_thread, &client)) {
		printf("Failed to create the output thread.\n");
		client_set_running_status(&client, false);
		pthread_join(thread_mqtt, NULL);
		client_disconnect(&client);
		client_cleanup(&client);
		mosquitto_lib_cleanup();
		return -4;
	}

	client_run(&client);
	client_disconnect(&client);
	client_set_running_status(&client, false);
	pthread_join(thread_mqtt, NULL);
	pthread_join(thread_output, NULL);
	sleep(1);
	client_cleanup(&client);
	mosquitto_lib_cleanup();

	printf("The client has been terminated.\n");
	return 0;
}
