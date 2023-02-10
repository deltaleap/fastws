#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iconv.h>
#include <locale.h>

#if 1
#define PRINTERR() fprintf(stderr, "%s:L%i: error\n", __FILE__, __LINE__)
void print_hex_and_ascii(const unsigned char *data, size_t len) {
    int i;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            int j;
            for (j = i - 15; j < i; j++) {
                if (j < 0) {
                    printf("   ");
                } else if (data[j] >= 32 && data[j] <= 126) {
                    printf("%c", data[j]);
                } else {
                    printf(".");
                }
            }
            for (; j <= i; j++) {
                printf(" ");
            }
        }
    }
    printf("\n");
}

void hex_dump(const char *title, const unsigned char *buf, size_t len)
{
    printf("%s:\n", title);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
};

void create_masking_key(uint8_t *masking_key) {
	uint8_t mask_bit;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec);
	mask_bit = rand();
	memcpy(masking_key, &mask_bit, 4);
}


char *bin_to_utf8(const char *bin, size_t bin_len) {
  iconv_t cd = iconv_open("UTF-8", "");
  if (cd == (iconv_t) -1) {
    perror("iconv_open");
    return NULL;
  }

  size_t utf8_len = bin_len * 4 + 1;
  char *utf8 = malloc(utf8_len);
  if (!utf8) {
    perror("malloc");
    return NULL;
  }

  char *in = (char *) bin;
  char *out = utf8;
  size_t in_left = bin_len;
  size_t out_left = utf8_len;
  if (iconv(cd, &in, &in_left, &out, &out_left) == (size_t) -1) {
    perror("iconv");
    return NULL;
  }

  iconv_close(cd);

  *out = '\0';
  return utf8;
}

struct client {
    SSL_CTX *ssl_context;
    SSL *ssl;
    const char *host;
    const char *path;
    int port;
    int sockfd;
};

void init_ws(struct client *c, const char *host, const char *path, int port) {
    c->host = host;
    c->path = path;
    c->port = 443;
}

int connect_to_server(struct client *c) {
    struct sockaddr_in server_addr;
    struct hostent *server;

    // Create socket
    c->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->sockfd < 0) {
        PRINTERR();
        return -1;
    }

    // Configure server address
    server = gethostbyname(c->host);
    if (server == NULL) {
        PRINTERR();
        return -1;
    }

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&server_addr.sin_addr.s_addr,
          server->h_length);
    server_addr.sin_port = htons(c->port);
    if (connect(c->sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        PRINTERR();
        return -1;
    }

    // Initialize SSL context
    SSL_library_init();
    SSL_load_error_strings();
    c->ssl_context = SSL_CTX_new(TLS_client_method());
    if (!c->ssl_context) {
        PRINTERR();
        return -1;
    }

    SSL_CTX_set_verify(c->ssl_context, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(c->ssl_context, "/etc/ssl/certs/ca-certificates.crt", NULL) != 1) {
        PRINTERR();
        return -1;
    }

    // Connect SSL over the socket
    c->ssl = SSL_new(c->ssl_context);
    SSL_set_fd(c->ssl, c->sockfd);

    int ret = SSL_connect(c->ssl);
    if (ret != 1) {
        PRINTERR();
        return -1;
    } else {
        long ret = SSL_get_verify_result(c->ssl);
        if (ret != X509_V_OK) {
            PRINTERR();
            return -1;
        }
    }
}

int handshake(struct client *c) {
    char request[1024];
    int request_len;
    char response[1024];
    int response_len;

    // Prepare the WebSocket handshake request
    request_len = sprintf(request, "GET %s HTTP/1.1\r\n"
                                   "Host: %s\r\n"
                                   "Upgrade: websocket\r\n"
                                   "Connection: Upgrade\r\n"
                                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                   "Sec-WebSocket-Version: 13\r\n\r\n",
                                   c->path, c->host);
    // Send the WebSocket handshake request
    if (SSL_write(c->ssl, request, request_len) < 0) {
        PRINTERR();
        return -1;
    }
    // Receive the WebSocket handshake response
    response_len = SSL_read(c->ssl, response, sizeof(response));
    if (response_len < 0) {
        PRINTERR();
        return -1;
    }

    // Check if the connection has been upgraded to a WebSocket connection
    if (strstr(response, "HTTP/1.1 101 Switching Protocols") &&
        strstr(response, "upgrade: websocket") &&
        strstr(response, "Connection: upgrade")) {
            printf("WebSocket handshake successful\n");
    } else {
        printf("WebSocket handshake failed\n");
        return -1;
    }

    return 1;
}

#if __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

void send_message(struct client *c, const char req[]) {
    int message_length = strlen(req);
    unsigned char frame[8192];
    int frame_len = 0;

    // Set the first byte of the frame header to indicate a text frame
    frame[frame_len++] = 0x81;
    // Generate a random 4-byte masking key
    unsigned char masking_key[4];
    create_masking_key(masking_key);
    printf("masking with: 0x%02x 0x%02x 0x%02x 0x%02x\n",
        masking_key[0],
        masking_key[1],
        masking_key[2],
        masking_key[3]
    );

	if(message_length <= 125) {
		frame[1] = (message_length | 0x80);
		frame[2] = masking_key[0];
		frame[3] = masking_key[1];
		frame[4] = masking_key[2];
		frame[5] = masking_key[3];
	}
	else if(message_length > 125 && message_length <= 0xffff) { // 125 && 65535
		uint16_t len16 = htons(message_length);
		frame[1] = (126 | 0x80);
		memcpy(frame + 2, &len16, 2);
		frame[4] = masking_key[0];
		frame[5] = masking_key[1];
		frame[6] = masking_key[2];
		frame[7] = masking_key[3];
	}
	else if(message_length > 0xffff && message_length <= 0xffffffffffffffffLL) {  // 65535 && 18446744073709551615
		char len64[8];
		//char len64[8] = htonll(message_length);
		frame[1] = (127 | 0x80);
		memcpy(frame + 2, len64, 8);
		frame[10] = masking_key[0];
		frame[11] = masking_key[1];
		frame[12] = masking_key[2];
		frame[13] = masking_key[3];
        frame_len += 4;
	}
	else {
        printf("frame too large\n");
		exit(-1);
	}

    // Mask the payload with the masking key
    for (int i = 0; i < message_length; i++) {
        frame[frame_len + i] = req[i] ^ masking_key[i % 4];
    }
    frame_len += message_length;

    // Use SSL_write to send the websocket frame
    hex_dump("ok", frame, frame_len);
    int sent_bytes = 0;
    sent_bytes = SSL_write(c->ssl, frame, frame_len);
    printf("sent %i bytes\n", sent_bytes);
}

int receive_message(struct client *c, char res[]) {
    unsigned char buf[4096];
    unsigned char mask[4];
    int bytes_received;
    int payload_length;
    unsigned char frame_header[2];

    printf("receiving\n");
    bytes_received = SSL_read(c->ssl, frame_header, 2);

    if (bytes_received < 0) {
        PRINTERR();
        return -1;
    }

    payload_length = (frame_header[1] & 0x7F);
    printf("payload_length: %i\n", payload_length);
    if (payload_length == 126) {
        printf("126\n");
        bytes_received = SSL_read(c->ssl, &payload_length, 2);
        if (bytes_received < 0) {
            PRINTERR();
            return -1;
        }
    } else if (payload_length == 127) {
        printf("127\n");
        bytes_received = SSL_read(c->ssl, &payload_length, 8);
        if (bytes_received < 0) {
            PRINTERR();
            return -1;
        } else {
            printf("toooo long\n");
        }
    }

   if (frame_header[1] & 0x80) {
        printf("mask?: %i -> yes\n", frame_header[1] & 0x80);
        bytes_received = SSL_read(c->ssl, mask, 4);
        if (bytes_received < 0) {
            PRINTERR();
            return -1;
        }
    }
    printf("ok\n");

    bytes_received = SSL_read(c->ssl, buf, payload_length);
    if (bytes_received < 0) {
        PRINTERR();
        return -1;
    }

    if (frame_header[0] == 0x88) {
        printf("connection closed by deribit\n");
        unsigned short close_code;
        memcpy(&close_code, buf, sizeof(close_code));
        close_code = ntohs(close_code);
        printf("close code: %hu\n", close_code);
    }

    hex_dump("received frame header", frame_header, 2);
    printf("payload length: %i\n", payload_length);
    hex_dump("received frame payload", buf, payload_length);
    if (frame_header[1] & 0x80) {
        // Unmask the message
#if 0
        printf("buf before: %s\n", buf);
        for (int i = 0; i < bytes_received; i++) {
            buf[i] = buf[i] ^ mask[i % 4];
        }
        printf("buf after: %s\n", buf);
        //unmask_message(buf, mask, bytes_received);
#endif
    }
    return 1;
}

int main()
{
    struct client c;
    init_ws(&c, "www.deribit.com", "/ws/api/v2", 443);

    /* connection*/
    connect_to_server(&c);
    printf("connected to deribit (sockfd: %i)\n", c.sockfd);

    /* handshake */
    int handshake_ret = handshake(&c);
    if(handshake_ret < 0) {
        return handshake_ret;
    }
    printf("handshake: %i\n", handshake_ret);

    /* send message */
    send_message(
        &c,
        "{\"jsonrpc\":\"2.0\",\"id\":55,\"method\":\"public/status\",\"params\":{}}"
    );
    printf("\n");

    /* receive message */
    char res[4096];
    receive_message(&c, res);
    printf("res:\n%s\n", res);

    return 0;
}

#endif